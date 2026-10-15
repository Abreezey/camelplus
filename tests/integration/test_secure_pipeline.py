"""Full-chain integration: effect → policy engine → branch → broker → audit.

Covers the three arch.md §7 branches against A's real policy engine:

- ALLOW  (workspace read inside contract)     → executes, both events audited;
- DENY   (secret egress to untrusted domain)  → blocked, nothing executed;
- CONFIRM (write outside contract)            → user approves → executes,
                                                 user denies → nothing executes.

Plus the acceptance replay: every decision can be reconstructed from the
audit chain alone, and the whole chain verifies.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from camel.audit import AuditStore, ProvenanceService
from camel.broker import ConfirmationAuthority, ExecutionBroker, SandboxProfile, SecureExecutionPipeline
from camel.core.contract import AllowedEffect, IntentContract
from camel.core.decision import DecisionOutcome
from camel.core.effect import CanonicalEffect, DataReference, EffectType
from camel.core.labels import Confidentiality, TrustLabel
from camel.policy.dsl import load_rules
from camel.policy.engine import DestinationClassifier, PolicyEngine

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(hours=1)
KEY = b"integration-signing-key"


@pytest.fixture()
def env(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "note.txt").write_text("hello")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    read_scope = f"file://{workspace / '**'}"
    rules = load_rules(
        f"""
id: allow-workspace-read
when:
  effect.type: READ
  effect.resource_matches: {json.dumps(read_scope)}
then: ALLOW
---
id: confirm-any-write
when:
  effect.type: WRITE
then: CONFIRM
"""
    )
    engine = PolicyEngine(rules, DestinationClassifier())
    audit = AuditStore(":memory:")
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(workspace, scratch),
        ticket_store=_MemoryTickets(),
        audit=audit,
        now_fn=lambda: NOW,
    )
    confirmations = ConfirmationAuthority(signing_key=KEY, audit=audit, now_fn=lambda: NOW)
    pipeline = SecureExecutionPipeline(
        engine=engine,
        broker=broker,
        confirmations=confirmations,
        audit=audit,
        signing_key=KEY,
        now_fn=lambda: NOW,
    )
    contract = IntentContract(
        contract_id="ic_01",
        principal="user:alice",
        goal="review_current_repository",
        allowed_effects=(AllowedEffect(effect=EffectType.READ, resource=read_scope),),
        side_effect_budget=5,
        expires_at=LATER,
    )
    return SimpleNamespace(
        pipeline=pipeline,
        audit=audit,
        workspace=workspace,
        scratch=scratch,
        contract=contract,
    )


class _MemoryTickets:
    def __init__(self) -> None:
        self._uses: dict[str, int] = {}

    def uses(self, ticket_id: str) -> int:
        return self._uses.get(ticket_id, 0)

    def record_use(self, ticket_id: str) -> int:
        self._uses[ticket_id] = self.uses(ticket_id) + 1
        return self._uses[ticket_id]


def _read_effect(workspace: Path) -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_read",
        type=EffectType.READ,
        operation="file_read",
        resources=(f"file://{workspace / 'note.txt'}",),
    )


def _write_effect(scratch: Path) -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_write",
        type=EffectType.WRITE,
        operation="file_write",
        resources=(f"file://{scratch / 'out.txt'}",),
    )


def _secret_egress_effect() -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_egress",
        type=EffectType.EGRESS,
        operation="http_post",
        resources=("file://workspace/.env",),
        data_refs=(DataReference(ref="value://secret_17", label=TrustLabel(confidentiality=Confidentiality.SECRET)),),
        destination="https://example.invalid/upload",
    )


def test_allow_branch_executes_and_audits(env) -> None:
    result = env.pipeline.run(
        _read_effect(env.workspace),
        subject="user:alice",
        trace_id="t_allow",
        session_id="s1",
        contract=env.contract,
    )
    assert result.decision.decision is DecisionOutcome.ALLOW
    assert result.execution is not None
    assert result.execution.output == b"hello"

    events = env.audit.events("t_allow")
    sources = [e.source for e in events]
    assert sources == ["decision", "execution"]
    assert env.audit.payload_of(events[0].event_id)["decision"]["decision"] == "ALLOW"
    assert env.audit.payload_of(events[1].event_id)["outcome"] == "executed"
    env.audit.verify_chain()


def test_deny_branch_blocks_secret_egress(env) -> None:
    result = env.pipeline.run(
        _secret_egress_effect(),
        subject="user:alice",
        trace_id="t_deny",
        session_id="s1",
        contract=env.contract,
    )
    assert result.decision.decision is DecisionOutcome.DENY
    assert result.execution is None
    assert result.confirmation is None
    assert any("ifc" in reason for reason in result.decision.hard_reasons)

    events = env.audit.events("t_deny")
    assert [e.source for e in events] == ["decision"]  # nothing executed
    env.audit.verify_chain()


def test_confirm_branch_requires_user_approval(env) -> None:
    result = env.pipeline.run(
        _write_effect(env.scratch),
        subject="user:alice",
        trace_id="t_confirm",
        session_id="s1",
        contract=env.contract,
    )
    assert result.decision.decision is DecisionOutcome.CONFIRM
    assert result.execution is None
    assert not (env.scratch / "out.txt").exists()

    request = result.confirmation
    assert request is not None
    assert "file://" in request.render()
    assert env.audit.events("t_confirm")[-1].source == "confirmation"  # nothing executed yet

    resolved = env.pipeline.resolve(
        request,
        approved=True,
        subject="user:alice",
        trace_id="t_confirm",
        session_id="s1",
        content=b"approved data",
    )
    assert resolved.execution is not None
    assert (env.scratch / "out.txt").read_bytes() == b"approved data"

    sources = [e.source for e in env.audit.events("t_confirm")]
    assert sources == ["decision", "confirmation", "confirmation", "execution"]
    env.audit.verify_chain()


def test_confirm_branch_denial_executes_nothing(env) -> None:
    result = env.pipeline.run(
        _write_effect(env.scratch),
        subject="user:alice",
        trace_id="t_deny_confirm",
        session_id="s1",
        contract=env.contract,
    )
    request = result.confirmation
    assert request is not None
    resolved = env.pipeline.resolve(
        request, approved=False, subject="user:alice", trace_id="t_deny_confirm", session_id="s1"
    )
    assert resolved.execution is None
    assert not (env.scratch / "out.txt").exists()
    assert "execution" not in [e.source for e in env.audit.events("t_deny_confirm")]


def test_decisions_replayable_from_audit_alone(env) -> None:
    """Acceptance: a reviewer reconstructs every decision from events + payloads."""
    from camel.core.decision import Decision

    env.pipeline.run(
        _read_effect(env.workspace),
        subject="user:alice",
        trace_id="t_replay",
        session_id="s1",
        contract=env.contract,
    )
    env.pipeline.run(
        _secret_egress_effect(),
        subject="user:alice",
        trace_id="t_replay",
        session_id="s1",
        contract=env.contract,
    )
    replayed = []
    for event in ProvenanceService(env.audit).timeline("t_replay"):
        payload = env.audit.payload_of(event.event_id)
        if payload and "decision" in payload:
            replayed.append(Decision.model_validate(payload["decision"]))
    assert [d.decision for d in replayed] == [DecisionOutcome.ALLOW, DecisionOutcome.DENY]
    report = ProvenanceService(env.audit).report("t_replay")
    assert "ALLOW" in report and "DENY" in report


def test_audit_context_threaded_into_all_payloads(env) -> None:
    """run/resolve 的 audit_context 必须进 decision/execution/confirmation 全部 payload。"""
    from camel.audit import AuditContext

    ctx = AuditContext(model_version="llm-x", tool_manifest_digest="sha256:ff", code_commit="deadbe")
    expected = ctx.model_dump()

    # ALLOW branch: decision + execution payloads carry the context
    env.pipeline.run(
        _read_effect(env.workspace),
        subject="user:alice",
        trace_id="t_ctx",
        session_id="s1",
        contract=env.contract,
        audit_context=ctx,
    )
    # CONFIRM branch: resolve carries it into confirmation + execution payloads
    result = env.pipeline.run(
        _write_effect(env.scratch),
        subject="user:alice",
        trace_id="t_ctx",
        session_id="s1",
        audit_context=ctx,
    )
    assert result.confirmation is not None
    env.pipeline.resolve(
        result.confirmation,
        approved=True,
        subject="user:alice",
        trace_id="t_ctx",
        session_id="s1",
        content=b"data",
        audit_context=ctx,
    )

    events = env.audit.events("t_ctx")
    payloads = [env.audit.payload_of(e.event_id) for e in events]
    assert len(payloads) >= 5  # decision+execution (ALLOW) + decision+confirmation+confirmation+execution
    for payload in payloads:
        assert payload["context"] == expected
    env.audit.verify_chain()
