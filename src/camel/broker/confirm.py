"""Scoped confirmation flow (arch.md §6.9): CONFIRM → user decision → ticket.

The authority shows the user exactly what they are approving — the specific
resources, destination and consequences of one effect — and only on explicit
approval issues the one-time capability ticket (format and signing defined
by module A; the signing key is TCB-held, injected via environment, never
committed).

Every request/approval/denial is audited as a ``confirmation`` event.
"""

import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict

from camel.audit.store import AuditContext, AuditStore
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

    model_config = ConfigDict(frozen=True)

    request_id: str
    effect: CanonicalEffect
    decision: Decision
    expires_at: datetime

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
    ) -> ConfirmationRequest:
        """Build (and audit) the confirmation request for a CONFIRM decision."""
        if decision.decision is not DecisionOutcome.CONFIRM:
            raise ValueError("request() expects a CONFIRM decision")
        request = ConfirmationRequest(
            request_id=f"cfm_{uuid.uuid4().hex}",
            effect=effect,
            decision=decision,
            expires_at=self._now() + self._ttl,
        )
        self._audit_confirmation(
            request,
            "requested",
            trace_id=trace_id,
            session_id=session_id,
            subject=subject,
            audit_context=audit_context,
        )
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
        now = self._now()
        if now >= request.expires_at:
            self._audit_confirmation(
                request,
                "expired",
                trace_id=trace_id,
                session_id=session_id,
                subject=subject,
                audit_context=audit_context,
            )
            raise ConfirmationExpiredError(f"confirmation request {request.request_id} expired")
        ticket = issue_ticket(self._key, subject=subject, effect=request.effect, expires_at=now + self._ttl)
        self._audit_confirmation(
            request,
            "approved",
            trace_id=trace_id,
            session_id=session_id,
            subject=subject,
            ticket_id=ticket.ticket_id,
            audit_context=audit_context,
        )
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
        self._audit_confirmation(
            request,
            "denied",
            trace_id=trace_id,
            session_id=session_id,
            subject=subject,
            audit_context=audit_context,
        )

    def _audit_confirmation(
        self,
        request: ConfirmationRequest,
        outcome: str,
        *,
        trace_id: str,
        session_id: str,
        subject: str,
        ticket_id: str | None = None,
        audit_context: AuditContext | None = None,
    ) -> None:
        event = CanonicalEvent(
            event_id=f"evt_{uuid.uuid4().hex}",
            trace_id=trace_id,
            session_id=session_id,
            principal=subject,
            source="confirmation",
            payload_ref=f"confirmation:{request.request_id}",
            timestamp=self._now(),
        )
        payload: dict = {
            "request_id": request.request_id,
            "outcome": outcome,
            "effect": request.effect.model_dump(mode="json"),
            "confirm_reasons": list(request.decision.confirm_reasons),
            "context": audit_context.model_dump() if audit_context is not None else None,
        }
        if ticket_id is not None:
            payload["ticket_id"] = ticket_id
        self._audit.append(event, payload=payload)
