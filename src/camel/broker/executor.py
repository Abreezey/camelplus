"""Execution broker: OS-level execution of approved effects (arch.md §6.9).

The broker is the only component that touches the filesystem or network on
behalf of the agent. Every execution requires a valid, unexpired, unconsumed
capability ticket (I5) — verification failure always raises (fail closed,
see ``camel/policy/ticket.py``).

v0.6 effect support (fail closed for everything else):

- ``READ``   — read one file inside the sandbox read roots;
- ``WRITE``  — write caller-provided bytes inside the sandbox write dirs;
- ``EGRESS`` — one pinned-IP HTTP request through a configured
  :class:`~camel.normalization.NetworkPolicy` (see ``egress.py``); the
  vault-derived credential is injected as ``Authorization: Bearer``;
- ``EXEC`` / ``REPO_MUTATE`` / … — unsupported until the kernel sandbox
  exists; attempting them raises :class:`UnsupportedEffectError` and is
  audited as ``rejected``.

Check order: static sandbox validation happens *before* ticket verification
(pure path math, no side effects, does not burn a ticket use); authorization
happens *before* any filesystem IO.

Audit: every attempt (``executed`` / ``rejected`` / ``failed``) appends one
``execution`` event to the :class:`~camel.audit.AuditStore`.
"""

import os
from collections.abc import Callable
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, ConfigDict

from camel.audit.store import AuditContext, AuditStore, execution_event, execution_payload
from camel.broker.credentials import InjectedCredential, KeyVault
from camel.broker.egress import ALLOWED_METHODS, EgressClient, EgressError
from camel.broker.profile import SandboxProfile, SandboxViolationError
from camel.core.effect import CanonicalEffect, EffectType
from camel.normalization.net import NetworkPolicy, NormalizationError, Resolver, resolve_dns
from camel.policy.ticket import CapabilityTicket, TicketStore, TicketVerificationError, verify_ticket


class UnsupportedEffectError(Exception):
    """Raised for effect types the broker cannot execute safely (fail closed)."""


class ExecutionAuditError(OSError):
    """I/O may have happened; inspect the durable intent, never blindly retry."""

    def __init__(self, intent_event_id: str):
        self.intent_event_id = intent_event_id
        super().__init__(f"execution completion audit failed; inspect intent {intent_event_id}; do not retry")


def _write_flags() -> int:
    """Require the POSIX no-follow primitive rather than silently dropping it."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(nofollow, int) or nofollow <= 0:
        raise UnsupportedEffectError("secure WRITE requires POSIX O_NOFOLLOW support")
    return os.O_WRONLY | os.O_CREAT | nofollow


class ExecutionResult(BaseModel):
    """Outcome of one successful broker execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    effect_id: str
    ticket_id: str
    output: bytes | None = None
    credential_handle: str | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ExecutionBroker:
    """Executes approved effects inside a :class:`SandboxProfile`, guarded by tickets."""

    def __init__(
        self,
        *,
        signing_key: bytes,
        profile: SandboxProfile,
        ticket_store: TicketStore,
        audit: AuditStore,
        now_fn: Callable[[], datetime] | None = None,
        vault: KeyVault | None = None,
        network: NetworkPolicy | None = None,
        resolver: Resolver = resolve_dns,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
        max_response_bytes: int = 1_048_576,
    ) -> None:
        self._key = signing_key
        self._profile = profile
        self._tickets = ticket_store
        self._audit = audit
        self._now = now_fn or _utcnow
        self._vault = vault
        self._egress: EgressClient | None = None
        if network is not None:
            self._egress = EgressClient(
                network,
                resolver=resolver,
                transport=transport,
                timeout=timeout,
                max_response_bytes=max_response_bytes,
            )

    def execute(
        self,
        effect: CanonicalEffect,
        ticket: CapabilityTicket,
        *,
        subject: str,
        trace_id: str,
        session_id: str,
        content: bytes | None = None,
        parent_ids: tuple[str, ...] = (),
        audit_context: AuditContext | None = None,
    ) -> ExecutionResult:
        """Validate → consume ticket → persist intent → IO → persist result.

        Intent failure prevents IO. Completion failure leaves an unresolved
        intent and raises without delivering output; IO cannot be rolled back.
        """
        now = self._now()
        try:
            self._validate(effect, content)
        except (SandboxViolationError, UnsupportedEffectError) as err:
            self._audit_attempt(
                effect,
                ticket.ticket_id,
                "rejected",
                str(err),
                subject=subject,
                trace_id=trace_id,
                session_id=session_id,
                parent_ids=parent_ids,
                now=now,
                audit_context=audit_context,
            )
            raise
        try:
            verify_ticket(self._key, ticket, effect, subject=subject, store=self._tickets, now=now)
        except TicketVerificationError as err:
            self._audit_attempt(
                effect,
                ticket.ticket_id,
                "rejected",
                str(err),
                subject=subject,
                trace_id=trace_id,
                session_id=session_id,
                parent_ids=parent_ids,
                now=now,
                audit_context=audit_context,
            )
            raise
        credential: InjectedCredential | None = None
        if self._vault is not None:
            try:
                credential = self._vault.derive(
                    subject=subject, ticket_id=ticket.ticket_id, expires_at=ticket.expires_at
                )
            except Exception as err:  # vault failure must fail closed and be audited
                self._audit_attempt(
                    effect,
                    ticket.ticket_id,
                    "failed",
                    f"credential_derivation_error: {err}",
                    subject=subject,
                    trace_id=trace_id,
                    session_id=session_id,
                    parent_ids=parent_ids,
                    now=now,
                    audit_context=audit_context,
                )
                raise
        handle = credential.handle if credential is not None else None
        intent = execution_event(
            effect,
            ticket_id=ticket.ticket_id,
            trace_id=trace_id,
            session_id=session_id,
            principal=subject,
            now=now,
            parent_ids=parent_ids,
        ).model_copy(update={"source": "execution_intent"})
        self._audit.append(
            intent,
            payload=execution_payload(
                effect, ticket.ticket_id, "prepared", context=audit_context, credential_handle=handle
            ),
        )
        parent_ids = (intent.event_id,)
        try:
            output = self._do_execute(effect, content, credential)
        except (OSError, EgressError) as err:
            try:
                self._audit_attempt(
                    effect,
                    ticket.ticket_id,
                    "failed",
                    str(err),
                    subject=subject,
                    trace_id=trace_id,
                    session_id=session_id,
                    parent_ids=parent_ids,
                    now=now,
                    audit_context=audit_context,
                    credential_handle=handle,
                )
            except Exception as audit_error:
                raise ExecutionAuditError(intent.event_id) from audit_error
            raise
        try:
            self._audit_attempt(
                effect,
                ticket.ticket_id,
                "executed",
                None,
                subject=subject,
                trace_id=trace_id,
                session_id=session_id,
                parent_ids=parent_ids,
                now=now,
                audit_context=audit_context,
                credential_handle=handle,
            )
        except Exception as error:
            raise ExecutionAuditError(intent.event_id) from error
        return ExecutionResult(
            effect_id=effect.effect_id,
            ticket_id=ticket.ticket_id,
            output=output,
            credential_handle=handle,
        )

    def _validate(self, effect: CanonicalEffect, content: bytes | None) -> None:
        """Static validation: supported type, resource present, sandbox containment."""
        if effect.type is EffectType.READ:
            if not effect.resources:
                raise SandboxViolationError("READ effect without a resource")
            self._profile.resolve_read(effect.resources[0])
        elif effect.type is EffectType.WRITE:
            if not effect.resources:
                raise SandboxViolationError("WRITE effect without a resource")
            if content is None:
                raise ValueError("WRITE effect requires content")
            self._profile.resolve_write(effect.resources[0])
            _write_flags()
        elif effect.type is EffectType.EGRESS:
            self._validate_egress(effect)
        else:
            raise UnsupportedEffectError(
                f"effect type {effect.type.value} is not executable in broker v0 (fail closed)"
            )

    def _validate_egress(self, effect: CanonicalEffect) -> None:
        """Allowlist/DNS validation before the ticket is burned; rechecked at send time."""
        if not effect.destination:
            raise SandboxViolationError("EGRESS effect without a destination")
        if self._egress is None:
            raise UnsupportedEffectError("EGRESS execution requires a configured NetworkPolicy (fail closed)")
        method = effect.operation.removeprefix("http_")
        if not effect.operation.startswith("http_") or method.upper() not in ALLOWED_METHODS:
            raise UnsupportedEffectError(f"unsupported EGRESS operation {effect.operation!r}")
        try:
            self._egress.validate(effect.destination)
        except NormalizationError as err:
            raise SandboxViolationError(str(err)) from err

    def _do_execute(
        self, effect: CanonicalEffect, content: bytes | None, credential: InjectedCredential | None
    ) -> bytes | None:
        if effect.type is EffectType.READ:
            return self._profile.resolve_read(effect.resources[0]).read_bytes()
        if effect.type is EffectType.EGRESS:
            if self._egress is None:
                raise UnsupportedEffectError("EGRESS execution requires a configured NetworkPolicy (fail closed)")
            if effect.destination is None:  # _validate_egress enforces this; defense in depth
                raise SandboxViolationError("EGRESS effect without a destination")
            return self._egress.send(
                url=effect.destination,
                method=effect.operation.removeprefix("http_").upper(),
                content=content,
                credential=credential,
            )
        if content is None:
            raise ValueError("WRITE effect requires content")
        target = self._profile.resolve_write(effect.resources[0])
        fd = os.open(target, _write_flags(), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        return None

    def _audit_attempt(
        self,
        effect: CanonicalEffect,
        ticket_id: str,
        outcome: str,
        detail: str | None,
        *,
        subject: str,
        trace_id: str,
        session_id: str,
        parent_ids: tuple[str, ...],
        now: datetime,
        audit_context: AuditContext | None = None,
        credential_handle: str | None = None,
    ) -> None:
        event = execution_event(
            effect,
            ticket_id=ticket_id,
            trace_id=trace_id,
            session_id=session_id,
            principal=subject,
            now=now,
            parent_ids=parent_ids,
        )
        self._audit.append(
            event,
            payload=execution_payload(
                effect, ticket_id, outcome, detail, context=audit_context, credential_handle=credential_handle
            ),
        )
