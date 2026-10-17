"""D connected flow on the real chain: B production normalization + C execution.

The offline fixture path (``connected.run_flow`` defaults) stays untouched;
this module injects the real EffectNormalizer adapter and routes the final
tool effect through ``SecureExecutionPipeline`` (ticket, sandbox, audit).
"""

from collections.abc import Callable
from datetime import datetime
from functools import partial
from pathlib import Path

from camel.audit import AuditContext, AuditStore
from camel.audit.tickets import SQLiteTicketStore
from camel.broker import (
    ConfirmationAuthority,
    ExecutionBroker,
    SandboxProfile,
    SecureExecutionPipeline,
)
from camel.core.effect import CanonicalEffect
from camel.evaluation.connected import OWNER, FlowCase, run_flow
from camel.normalization.models import digest
from camel.planner.production_adapter import PRODUCTION_TOOLS, normalize_production
from camel.policy import PolicyEngine, load_rules


class PipelineToolExecutor:
    """Execute one effect through C's pipeline; fail closed on any decision drift."""

    def __init__(
        self,
        pipeline: SecureExecutionPipeline,
        *,
        subject: str,
        trace_id: str,
        session_id: str,
        audit_context: AuditContext | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._subject = subject
        self._trace_id = trace_id
        self._session_id = session_id
        self._audit_context = audit_context

    def __call__(self, effect: CanonicalEffect, payload: str) -> dict:
        result = self._pipeline.run(
            effect,
            subject=self._subject,
            trace_id=self._trace_id,
            session_id=self._session_id,
            audit_context=self._audit_context,
        )
        if result.decision.decision.value != "ALLOW" or result.execution is None:
            raise RuntimeError(f"real_execution_not_allowed:{effect.effect_id}:{result.decision.decision.value}")
        output = result.execution.output or b""
        return {
            "effect_id": effect.effect_id,
            "type": effect.type.value,
            "operation": effect.operation,
            "resources": list(effect.resources),
            "destination": effect.destination,
            "payload": payload,
            "response": output.decode("utf-8", errors="replace"),
        }


def run_real_flow(
    case: FlowCase,
    directory: Path,
    *,
    workspace: Path,
    scratch: Path,
    audit: AuditStore,
    signing_key: bytes,
    model_version: str | None = None,
    code_commit: str | None = None,
    now_fn: Callable[[], datetime] | None = None,
) -> dict:
    """Connected flow over the real workspace, with real normalization and execution."""
    documents = {"document": str(workspace / "README.md"), "other": str(workspace / "NOTES.md")}
    engine = PolicyEngine(
        load_rules(f"""id: allow-real-workspace-read
when:
  effect.type: READ
  effect.operation: read_file
  effect.resource_matches: {workspace}/**
then: ALLOW
""")
    )
    audit_context = AuditContext(
        model_version=model_version,
        tool_manifest_digest=digest([tool.model_dump(mode="json") for tool in PRODUCTION_TOOLS]),
        code_commit=code_commit,
    )
    broker = ExecutionBroker(
        signing_key=signing_key,
        profile=SandboxProfile.workspace(workspace, scratch),
        # run_flow requires a fresh directory, so the ticket store lives beside it.
        ticket_store=SQLiteTicketStore(f"{directory}.tickets.sqlite"),
        audit=audit,
        now_fn=now_fn,
    )
    confirmations = ConfirmationAuthority(signing_key=signing_key, audit=audit, now_fn=now_fn)
    pipeline = SecureExecutionPipeline(
        engine=engine,
        broker=broker,
        confirmations=confirmations,
        audit=audit,
        signing_key=signing_key,
        now_fn=now_fn,
    )
    executor = PipelineToolExecutor(
        pipeline,
        subject=OWNER,
        trace_id=case.case_id,
        session_id=f"{case.case_id}-real",
        audit_context=audit_context,
    )
    return run_flow(
        case,
        directory,
        executor=executor,
        normalize=partial(normalize_production, workspace=workspace),
        tools=PRODUCTION_TOOLS,
        engine=engine,
        documents=documents,
    )


__all__ = ["PipelineToolExecutor", "run_real_flow"]
