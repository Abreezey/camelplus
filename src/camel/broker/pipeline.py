"""End-to-end secure execution pipeline: decide → audit → (confirm) → execute.

This is module C's reference integration of the arch.md §7 decision flow for
the layers that exist today (A's policy engine + C's confirmation, broker
and audit). Module B's gateway will later own the entry point; the branch
semantics implemented here must not change:

- ``DENY``    — blocked before any execution; the safe alternative (if any)
  is carried on the decision;
- ``CONFIRM`` — never auto-executes: the caller obtains explicit user
  approval through :meth:`SecureExecutionPipeline.resolve`;
- ``ALLOW``   — a single-use execution ticket is issued and the effect runs
  inside the sandbox (I5: every executed effect carries a verifiable
  authorization, and both the decision and the execution are audited).
"""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict

from camel.audit.store import AuditContext, AuditStore, decision_event, decision_payload
from camel.broker.confirm import ConfirmationAuthority, ConfirmationRequest
from camel.broker.executor import ExecutionBroker, ExecutionResult
from camel.core.contract import IntentContract
from camel.core.decision import Decision, DecisionOutcome
from camel.core.effect import CanonicalEffect
from camel.policy.engine import PolicyEngine
from camel.policy.ticket import issue_ticket


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PipelineResult(BaseModel):
    """Outcome of one pipeline run or confirmation resolution."""

    model_config = ConfigDict(frozen=True)

    decision: Decision
    execution: ExecutionResult | None = None
    confirmation: ConfirmationRequest | None = None


class SecureExecutionPipeline:
    """Glues the frozen pieces together without changing any hard semantics."""

    def __init__(
        self,
        *,
        engine: PolicyEngine,
        broker: ExecutionBroker,
        confirmations: ConfirmationAuthority,
        audit: AuditStore,
        signing_key: bytes,
        ticket_ttl: timedelta = timedelta(minutes=5),
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._engine = engine
        self._broker = broker
        self._confirmations = confirmations
        self._audit = audit
        self._key = signing_key
        self._ttl = ticket_ttl
        self._now = now_fn or _utcnow

    def run(
        self,
        effect: CanonicalEffect,
        *,
        subject: str,
        trace_id: str,
        session_id: str,
        contract: IntentContract | None = None,
        content: bytes | None = None,
        audit_context: AuditContext | None = None,
    ) -> PipelineResult:
        """Evaluate one effect and follow its branch; every decision is audited."""
        now = self._now()
        decision = self._engine.evaluate(effect, now=now, contract=contract)
        event = decision_event(decision, effect, trace_id=trace_id, session_id=session_id, principal=subject, now=now)
        self._audit.append(event, payload=decision_payload(decision, effect, context=audit_context))

        if decision.decision is DecisionOutcome.DENY:
            return PipelineResult(decision=decision)
        if decision.decision is DecisionOutcome.CONFIRM:
            request = self._confirmations.request(
                decision,
                effect,
                trace_id=trace_id,
                session_id=session_id,
                subject=subject,
                audit_context=audit_context,
            )
            return PipelineResult(decision=decision, confirmation=request)

        ticket = issue_ticket(self._key, subject=subject, effect=effect, expires_at=now + self._ttl)
        execution = self._broker.execute(
            effect,
            ticket,
            subject=subject,
            trace_id=trace_id,
            session_id=session_id,
            content=content,
            parent_ids=(event.event_id,),
            audit_context=audit_context,
        )
        return PipelineResult(decision=decision, execution=execution)

    def resolve(
        self,
        request: ConfirmationRequest,
        *,
        approved: bool,
        subject: str,
        trace_id: str,
        session_id: str,
        content: bytes | None = None,
        audit_context: AuditContext | None = None,
    ) -> PipelineResult:
        """Resolve a CONFIRM request with the user's decision; execute on approval."""
        if not approved:
            self._confirmations.deny(
                request, subject=subject, trace_id=trace_id, session_id=session_id, audit_context=audit_context
            )
            return PipelineResult(decision=request.decision)
        ticket = self._confirmations.approve(
            request, subject=subject, trace_id=trace_id, session_id=session_id, audit_context=audit_context
        )
        execution = self._broker.execute(
            request.effect,
            ticket,
            subject=subject,
            trace_id=trace_id,
            session_id=session_id,
            content=content,
            audit_context=audit_context,
        )
        return PipelineResult(decision=request.decision, execution=execution)
