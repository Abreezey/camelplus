"""Execution broker: OS-level execution of approved effects (arch.md §6.9).

The broker is the only component that touches the filesystem on behalf of
the agent. Every execution requires a valid, unexpired, unconsumed
capability ticket (I5) — verification failure always raises (fail closed,
see ``camel/policy/ticket.py``).

v0 effect support (fail closed for everything else):

- ``READ``  — read one file inside the sandbox read roots;
- ``WRITE`` — write caller-provided bytes inside the sandbox write dirs;
- ``EXEC`` / ``EGRESS`` / ``REPO_MUTATE`` / … — unsupported until the kernel
  sandbox and egress proxy exist; attempting them raises
  :class:`UnsupportedEffectError` and is audited as ``rejected``.

Check order: static sandbox validation happens *before* ticket verification
(pure path math, no side effects, does not burn a ticket use); authorization
happens *before* any filesystem IO.

Audit: every attempt (``executed`` / ``rejected`` / ``failed``) appends one
``execution`` event to the :class:`~camel.audit.AuditStore`.
"""

import os
from collections.abc import Callable
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

from camel.audit.store import AuditContext, AuditStore, execution_event, execution_payload
from camel.broker.profile import SandboxProfile, SandboxViolationError
from camel.core.effect import CanonicalEffect, EffectType
from camel.policy.ticket import CapabilityTicket, TicketStore, TicketVerificationError, verify_ticket


class UnsupportedEffectError(Exception):
    """Raised for effect types the broker cannot execute safely (fail closed)."""


class ExecutionResult(BaseModel):
    """Outcome of one successful broker execution."""

    model_config = ConfigDict(frozen=True)

    effect_id: str
    ticket_id: str
    output: bytes | None = None


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
    ) -> None:
        self._key = signing_key
        self._profile = profile
        self._tickets = ticket_store
        self._audit = audit
        self._now = now_fn or _utcnow

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
        """Execute one effect: sandbox-check → verify ticket → do IO → audit.

        Raises without executing on any failure; every attempt is audited.
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
        try:
            output = self._do_execute(effect, content)
        except OSError as err:
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
            )
            raise
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
        )
        return ExecutionResult(effect_id=effect.effect_id, ticket_id=ticket.ticket_id, output=output)

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
        else:
            raise UnsupportedEffectError(
                f"effect type {effect.type.value} is not executable in broker v0 (fail closed)"
            )

    def _do_execute(self, effect: CanonicalEffect, content: bytes | None) -> bytes | None:
        if effect.type is EffectType.READ:
            return self._profile.resolve_read(effect.resources[0]).read_bytes()
        if content is None:
            raise ValueError("WRITE effect requires content")
        target = self._profile.resolve_write(effect.resources[0])
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
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
        self._audit.append(event, payload=execution_payload(effect, ticket_id, outcome, detail, context=audit_context))
