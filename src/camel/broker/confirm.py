"""Scoped confirmation flow (arch.md §6.9): CONFIRM → user decision → ticket.

The authority shows the user exactly what they are approving — the specific
resources, destination and consequences of one effect — and only on explicit
approval issues the one-time capability ticket (format and signing defined
by module A; the signing key is TCB-held, injected via environment, never
committed).

Every request/approval/denial is audited as a ``confirmation`` event.
"""

import hashlib
import hmac
import json
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict, field_validator

from camel.audit.store import AuditContext, AuditStore, ConfirmationStateError
from camel.core.decision import Decision, DecisionOutcome
from camel.core.effect import CanonicalEffect
from camel.core.events import CanonicalEvent
from camel.policy.ticket import CapabilityTicket, issue_ticket


class ConfirmationExpiredError(Exception):
    """Raised when a confirmation request is approved after its expiry."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ConfirmationRequest(BaseModel):
    """What the user sees and approves: one effect plus the decision context."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    effect: CanonicalEffect
    decision: Decision
    expires_at: datetime
    audit_context: AuditContext | None = None

    def event_id(self, outcome: str) -> str:
        return f"confirmation:{self.request_id}:{outcome}"

    @field_validator("expires_at")
    @classmethod
    def _expires_at_must_be_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return v

    def render(self) -> str:
        """Human-readable summary of what is being approved (CLI/log friendly)."""
        lines = [
            f"Confirm effect `{self.effect.effect_id}`?",
            f"  type: {self.effect.type.value}   operation: {self.effect.operation}",
            f"  resources: {list(self.effect.resources)}",
        ]
        if self.effect.destination is not None:
            lines.append(f"  destination: {self.effect.destination}")
        lines.append(f"  reversibility: {self.effect.reversibility.value}")
        if self.decision.confirm_reasons:
            lines.append(f"  reasons: {list(self.decision.confirm_reasons)}")
        if self.decision.safe_alternative is not None:
            lines.append(f"  safe alternative: {self.decision.safe_alternative}")
        lines.append(f"  policy: {self.decision.policy_version}")
        return "\n".join(lines)


class ConfirmationAuthority:
    """Issues scoped confirmation requests and (on approval) one-time tickets."""

    def __init__(
        self,
        *,
        signing_key: bytes,
        audit: AuditStore,
        ticket_ttl: timedelta = timedelta(minutes=5),
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._key = signing_key
        self._audit = audit
        self._ttl = ticket_ttl
        self._now = now_fn or _utcnow

    def request(
        self,
        decision: Decision,
        effect: CanonicalEffect,
        *,
        trace_id: str,
        session_id: str,
        subject: str,
        audit_context: AuditContext | None = None,
        parent_ids: tuple[str, ...] = (),
        expires_at: datetime | None = None,
    ) -> ConfirmationRequest:
        """Build (and audit) the confirmation request for a CONFIRM decision."""
        if decision.decision is not DecisionOutcome.CONFIRM:
            raise ValueError("request() expects a CONFIRM decision")
        now = self._now()
        expiry = min(now + self._ttl, expires_at) if expires_at is not None else now + self._ttl
        if expiry <= now:
            raise ConfirmationExpiredError("confirmation_expired_before_request")
        request = ConfirmationRequest(
            request_id=f"cfm_{uuid.uuid4().hex}",
            effect=effect,
            decision=decision,
            expires_at=expiry,
            audit_context=audit_context,
        )
        record = dict(
            request=request.model_dump(mode="json"),
            subject=subject,
            trace_id=trace_id,
            session_id=session_id,
            context=audit_context.model_dump() if audit_context is not None else None,
        )
        record["signature"] = self._sign(record)
        event, payload = self._confirmation_event(request, "requested", record, parent_ids=parent_ids)
        self._audit.create_confirmation(request.request_id, record, event, payload=payload)
        return request

    def approve(
        self,
        request: ConfirmationRequest,
        *,
        subject: str,
        trace_id: str,
        session_id: str,
        audit_context: AuditContext | None = None,
    ) -> CapabilityTicket:
        """Issue the one-time ticket after explicit user approval."""
        record = self._validate(
            request, subject=subject, trace_id=trace_id, session_id=session_id, audit_context=audit_context
        )
        now = self._now()
        if now >= request.expires_at:
            self._resolve(request, record, "expired")
            raise ConfirmationExpiredError(f"confirmation request {request.request_id} expired")
        ticket = issue_ticket(
            self._key, subject=subject, effect=request.effect, expires_at=min(now + self._ttl, request.expires_at)
        )
        self._resolve(request, record, "approved", ticket_id=ticket.ticket_id)
        return ticket

    def deny(
        self,
        request: ConfirmationRequest,
        *,
        subject: str,
        trace_id: str,
        session_id: str,
        audit_context: AuditContext | None = None,
    ) -> None:
        """Record the user's refusal; no ticket is issued."""
        record = self._validate(
            request, subject=subject, trace_id=trace_id, session_id=session_id, audit_context=audit_context
        )
        self._resolve(request, record, "denied")

    def _sign(self, record: dict) -> str:
        body = {key: value for key, value in record.items() if key != "signature"}
        encoded = json.dumps(body, sort_keys=True).encode()
        return hmac.new(self._key, b"camel-confirmation-v1:" + encoded, hashlib.sha256).hexdigest()

    def _validate(
        self,
        request: ConfirmationRequest,
        *,
        subject: str,
        trace_id: str,
        session_id: str,
        audit_context: AuditContext | None,
    ) -> dict:
        record = self._audit.confirmation_record(request.request_id)
        signature = record.get("signature")
        if not isinstance(signature, str) or not hmac.compare_digest(signature, self._sign(record)):
            raise ConfirmationStateError("confirmation_signature_invalid")
        # Public models contain frozensets: compare validated values rather
        # than JSON list order, which may differ after a process restart.
        if ConfirmationRequest.model_validate(record["request"]) != request:
            raise ConfirmationStateError("confirmation_request_changed")
        if any(
            record[key] != value
            for key, value in dict(subject=subject, trace_id=trace_id, session_id=session_id).items()
        ):
            raise ConfirmationStateError("confirmation_scope_mismatch")
        if audit_context is not None and record["context"] != audit_context.model_dump():
            raise ConfirmationStateError("confirmation_context_changed")
        return record

    def _resolve(self, request: ConfirmationRequest, record: dict, outcome: str, *, ticket_id: str | None = None):
        event, payload = self._confirmation_event(
            request, outcome, record, parent_ids=(request.event_id("requested"),), ticket_id=ticket_id
        )
        self._audit.resolve_confirmation(request.request_id, record, outcome, event, payload=payload)

    def _confirmation_event(
        self,
        request: ConfirmationRequest,
        outcome: str,
        record: dict,
        *,
        parent_ids: tuple[str, ...],
        ticket_id: str | None = None,
    ) -> tuple[CanonicalEvent, dict]:
        event = CanonicalEvent(
            event_id=request.event_id(outcome),
            trace_id=record["trace_id"],
            session_id=record["session_id"],
            principal=record["subject"],
            parent_ids=parent_ids,
            source="confirmation",
            payload_ref=f"confirmation:{request.request_id}",
            timestamp=self._now(),
        )
        payload: dict = {
            "request_id": request.request_id,
            "outcome": outcome,
            "effect": request.effect.model_dump(mode="json"),
            "confirm_reasons": list(request.decision.confirm_reasons),
            "context": record["context"],
        }
        if ticket_id is not None:
            payload["ticket_id"] = ticket_id
        return event, payload
