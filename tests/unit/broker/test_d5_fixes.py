"""D5 regressions for authority, atomic confirmation state and durable intent."""

import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from camel.audit.provenance import ProvenanceService
from camel.audit.store import AuditContext, AuditStore, ConfirmationStateError
from camel.broker.confirm import ConfirmationAuthority, ConfirmationExpiredError
from camel.broker.executor import ExecutionAuditError
from camel.core import DataReference, DecisionOutcome, EffectType, RiskSignal, TrustLabel
from camel.evaluation.integration import KEY, NOW, OWNER, Probe
from camel.policy import PolicyEngine, load_rules


@pytest.fixture
def probe(tmp_path):
    value = Probe(tmp_path / "probe", "d5-fixes")
    yield value
    value.audit.close()
    value.tickets.close()


def signal():
    return RiskSignal(name="synthetic-risk", confidence=0.9, detector_version="d5-test")


def test_risk_reaches_decision_audit_and_confirmation_without_io(probe):
    result = probe.pipeline.run(probe.effect(), risk_signals=(signal(),), **probe.scope)
    assert result.decision.decision == DecisionOutcome.CONFIRM
    assert result.decision.risk_signals == (signal(),)
    assert result.confirmation is not None and not probe.broker.io_effects
    payload = probe.audit.payload_of(probe.audit.events()[0].event_id)
    assert payload["decision"]["risk_signals"][0]["name"] == "synthetic-risk"


@pytest.mark.parametrize("kind", ["hard-deny", "default-deny"])
def test_risk_cannot_remove_a_deny(probe, kind):
    effect = probe.effect(type=EffectType.WRITE) if kind == "hard-deny" else probe.effect(type=EffectType.EXEC)
    result = probe.pipeline.run(effect, risk_signals=(signal(),), **probe.scope)
    assert result.decision.decision == DecisionOutcome.DENY
    assert result.confirmation is None and not probe.broker.io_effects


@pytest.mark.parametrize("used", [True, -1, 1.5, "1"])
def test_invalid_side_effect_count_refused_before_decision_or_io(probe, used):
    with pytest.raises(ValueError, match="nonnegative integer"):
        probe.pipeline.run(probe.effect(), side_effects_used=used, **probe.scope)
    assert not probe.audit.events() and not probe.broker.io_effects


@pytest.mark.parametrize("approved", [1, "true", None])
def test_confirmation_requires_boolean_approval(probe, approved):
    request = probe.pending()
    with pytest.raises(ValueError, match="explicit boolean"):
        probe.pipeline.resolve(request, approved=approved, **probe.scope)
    assert not probe.broker.io_effects


@pytest.mark.parametrize("field", ["subject", "trace_id", "session_id"])
def test_confirmation_cannot_move_to_another_scope(probe, field):
    request = probe.pending()
    with pytest.raises(ConfirmationStateError, match="scope_mismatch"):
        probe.pipeline.resolve(request, approved=True, **(probe.scope | {field: "different"}))
    assert not probe.broker.io_effects
    result = probe.pipeline.resolve(request, approved=True, **probe.scope)
    assert result.execution is not None


@pytest.mark.parametrize("field", ["effect", "expires_at", "decision"])
def test_changed_confirmation_record_cannot_issue_a_ticket(probe, field):
    request = probe.pending()
    changes = dict(
        effect=probe.effect(resources=(str(probe.other),)),
        expires_at=request.expires_at + timedelta(days=1),
        decision=request.decision.model_copy(update={"confirm_reasons": ("altered",)}),
    )
    changed = request.model_copy(update={field: changes[field]})
    with pytest.raises(ConfirmationStateError, match="request_changed"):
        probe.confirmations.approve(changed, **probe.scope)
    assert not probe.broker.io_effects


def test_unknown_confirmation_is_refused(probe):
    request = probe.pending().model_copy(update={"request_id": "unknown"})
    with pytest.raises(ConfirmationStateError, match="unknown"):
        probe.confirmations.approve(request, **probe.scope)


@pytest.mark.parametrize("first", ["approved", "denied"])
def test_terminal_confirmation_survives_restart(probe, first):
    request = probe.pending()
    probe.pipeline.resolve(request, approved=first == "approved", **probe.scope)
    probe.audit.close()
    audit = AuditStore(probe.root / "audit.sqlite")
    try:
        authority = ConfirmationAuthority(signing_key=KEY, audit=audit, now_fn=lambda: NOW)
        with pytest.raises(ConfirmationStateError, match="resolved"):
            authority.approve(request, **probe.scope)
        with pytest.raises(ConfirmationStateError, match="resolved"):
            authority.deny(request, **probe.scope)
        audit.verify_chain()
    finally:
        audit.close()


def test_pending_confirmation_survives_restart(probe):
    request = probe.pending()
    probe.audit.close()
    audit = AuditStore(probe.root / "audit.sqlite")
    try:
        authority = ConfirmationAuthority(signing_key=KEY, audit=audit, now_fn=lambda: NOW)
        ticket = authority.approve(request, **probe.scope)
        assert ticket.subject == OWNER
        audit.verify_chain()
    finally:
        audit.close()


def test_confirmation_state_and_set_labels_survive_distinct_processes(probe):
    label = TrustLabel(
        provenance=frozenset({"alpha", "beta", "gamma", "delta"}),
        data_classes=frozenset({"synthetic-a", "synthetic-b"}),
    )
    result = probe.pipeline.run(
        probe.effect(data_refs=(DataReference(ref="s", label=label),)), risk_signals=(signal(),), **probe.scope
    )
    assert result.confirmation is not None
    code = """
import sys
from datetime import datetime
from camel.audit.store import AuditStore, ConfirmationStateError
from camel.broker.confirm import ConfirmationAuthority, ConfirmationRequest
audit = AuditStore(sys.argv[1])
request = ConfirmationRequest.model_validate_json(sys.argv[2])
authority = ConfirmationAuthority(signing_key=b'D5-PUBLIC-SYNTHETIC-TEST-KEY-ONLY-32', audit=audit,
                                  now_fn=lambda: datetime.fromisoformat(sys.argv[3]))
try:
    authority.approve(request, subject='user:d5-synthetic', trace_id='d5-fixes', session_id='d5-session')
    assert sys.argv[4] == 'first'
except ConfirmationStateError:
    assert sys.argv[4] == 'second'
audit.verify_chain()
audit.close()
print('verified')
"""
    for seed, phase in [("17", "first"), ("991", "second")]:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                code,
                str(probe.root / "audit.sqlite"),
                result.confirmation.model_dump_json(),
                NOW.isoformat(),
                phase,
            ],
            env=dict(os.environ, PYTHONHASHSEED=seed),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "verified"


def test_pending_record_is_bound_to_issuer_key(probe):
    request = probe.pending()
    authority = ConfirmationAuthority(signing_key=b"different-key", audit=probe.audit, now_fn=lambda: NOW)
    with pytest.raises(ConfirmationStateError, match="signature_invalid"):
        authority.approve(request, **probe.scope)


def test_two_connections_can_only_approve_once(probe):
    request = probe.pending()
    audits = [AuditStore(probe.root / "audit.sqlite") for _ in range(2)]

    def approve(audit):
        authority = ConfirmationAuthority(signing_key=KEY, audit=audit, now_fn=lambda: NOW)
        try:
            return authority.approve(request, **probe.scope).ticket_id
        except ConfirmationStateError:
            return None

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(approve, audits))
        assert sum(value is not None for value in results) == 1
        approved = [e for e in probe.audit.events() if e.event_id == request.event_id("approved")]
        assert len(approved) == 1
        probe.audit.verify_chain()
    finally:
        for audit in audits:
            audit.close()


def test_resolution_state_and_audit_rollback_together(probe):
    request = probe.pending()
    probe.audit._conn.execute(
        "CREATE TRIGGER fail_confirmation BEFORE INSERT ON audit_events "
        "WHEN NEW.source = 'confirmation' BEGIN SELECT RAISE(ABORT, 'injected'); END"
    )
    probe.audit._conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        probe.confirmations.approve(request, **probe.scope)
    assert probe.audit._conn.execute("SELECT state FROM confirmations").fetchone()[0] == "pending"
    assert len(probe.audit.events()) == 2
    probe.audit._conn.execute("DROP TRIGGER fail_confirmation")
    probe.audit._conn.commit()
    ticket = probe.confirmations.approve(request, **probe.scope)
    assert ticket.subject == OWNER


def test_request_creation_and_audit_rollback_together(probe):
    probe.audit._conn.execute(
        "CREATE TRIGGER fail_confirmation BEFORE INSERT ON audit_events "
        "WHEN NEW.source = 'confirmation' BEGIN SELECT RAISE(ABORT, 'injected'); END"
    )
    probe.audit._conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        probe.pending()
    assert probe.audit._conn.execute("SELECT COUNT(*) FROM confirmations").fetchone()[0] == 0
    assert not probe.broker.io_effects


def test_approval_expires_at_original_contract_deadline(probe):
    deadline = NOW + timedelta(seconds=5)
    request = probe.confirmations.request(
        probe.engine.evaluate(probe.effect(normalization_confidence="failed"), now=NOW),
        probe.effect(),
        expires_at=deadline,
        **probe.scope,
    )
    assert request.expires_at == deadline
    late = ConfirmationAuthority(signing_key=KEY, audit=probe.audit, now_fn=lambda: deadline)
    with pytest.raises(ConfirmationExpiredError):
        late.approve(request, **probe.scope)


def test_policy_change_invalidates_confirmation(probe):
    request = probe.pending()
    probe.pipeline._engine = PolicyEngine(load_rules("id: deny-all\nwhen: {}\nthen: DENY"))
    with pytest.raises(ValueError, match="policy_changed"):
        probe.pipeline.resolve(request, approved=True, **probe.scope)
    assert not probe.broker.io_effects


def test_approval_keeps_original_audit_context_and_causal_chain(probe):
    context = AuditContext(model_version="synthetic", tool_manifest_digest="fixture", code_commit="local")
    result = probe.pipeline.run(probe.effect(), risk_signals=(signal(),), audit_context=context, **probe.scope)
    assert result.confirmation is not None
    probe.pipeline.resolve(result.confirmation, approved=True, **probe.scope)
    assert all(probe.audit.payload_of(e.event_id)["context"] == context.model_dump() for e in probe.audit.events())
    dag = ProvenanceService(probe.audit).dag(probe.scenario)
    assert len(dag.nodes) == 5 and len(dag.edges) == 4
    assert not probe.audit.pending_executions()


def test_intent_failure_prevents_io_even_with_valid_ticket(probe):
    probe.audit.fail_source = "execution_intent"
    with pytest.raises(OSError):
        probe.pipeline.run(probe.effect(), **probe.scope)
    assert not probe.broker.io_effects
    assert not probe.audit.pending_executions()


def test_completion_failure_is_durable_and_not_automatically_retried(probe):
    probe.audit.fail_source = "execution"
    with pytest.raises(ExecutionAuditError) as failure:
        probe.pipeline.run(probe.effect(), **probe.scope)
    assert len(probe.broker.io_effects) == 1
    assert probe.audit.pending_executions()[0].event_id == failure.value.intent_event_id
    probe.audit.close()
    audit = AuditStore(probe.root / "audit.sqlite")
    try:
        assert len(audit.pending_executions()) == 1
        assert len(audit.pending_executions("different-trace")) == 0
        audit.verify_chain()
    finally:
        audit.close()


def test_io_failure_followed_by_audit_failure_keeps_unresolved_intent(probe):
    probe.audit.fail_source = "execution"
    effect = probe.effect(resources=(str(probe.workspace / "missing.txt"),))
    with pytest.raises(ExecutionAuditError) as failure:
        probe.pipeline.run(effect, **probe.scope)
    assert probe.audit.pending_executions()[0].event_id == failure.value.intent_event_id
    assert len(probe.broker.io_effects) == 1
