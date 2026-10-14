"""Provenance: DAG edges from parent_ids and derived_from, timeline report."""

from datetime import datetime, timezone

import pytest

from camel.audit import (
    AuditStore,
    ProvenanceService,
    decision_event,
    decision_payload,
    execution_event,
    execution_payload,
)
from camel.core.decision import Decision, DecisionOutcome
from camel.core.effect import CanonicalEffect, EffectType
from camel.core.events import CanonicalEvent

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def service():
    store = AuditStore(":memory:")
    yield ProvenanceService(store), store
    store.close()


def _event(event_id: str, parents: tuple[str, ...] = ()) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id,
        trace_id="t1",
        session_id="s1",
        parent_ids=parents,
        principal="user:alice",
        source="ingress",
        payload_ref=f"ref:{event_id}",
        timestamp=NOW,
    )


def test_dag_edges_from_parent_ids(service) -> None:
    svc, store = service
    store.append(_event("evt_a"))
    store.append(_event("evt_b", parents=("evt_a",)))
    store.append(_event("evt_c", parents=("evt_a", "evt_b")))
    dag = svc.dag("t1")
    assert set(dag.edges) == {("evt_a", "evt_b"), ("evt_a", "evt_c"), ("evt_b", "evt_c")}
    assert len(dag.nodes) == 3


def test_dag_includes_derived_from_edges(service) -> None:
    svc, store = service
    store.append(_event("evt_web_17"))
    effect = CanonicalEffect(
        effect_id="fx_01",
        type=EffectType.EGRESS,
        operation="http_post",
        resources=("file://workspace/.env",),
        destination="https://example.invalid/upload",
        derived_from=("evt_web_17",),
    )
    decision = Decision(decision=DecisionOutcome.DENY, hard_reasons=("x",), policy_version="sha256:1")
    event = decision_event(decision, effect, trace_id="t1", session_id="s1", principal="user:alice", now=NOW)
    store.append(event, payload=decision_payload(decision, effect))
    dag = svc.dag("t1")
    assert ("evt_web_17", event.event_id) in set(dag.edges)


def test_cross_trace_parents_kept_out_of_edges(service) -> None:
    svc, store = service
    store.append(_event("evt_a"))
    cross = _event("evt_x").model_copy(update={"trace_id": "t2"})
    store.append(cross)
    store.append(_event("evt_b", parents=("evt_a", "evt_x")))
    dag = svc.dag("t1")
    assert set(dag.edges) == {("evt_a", "evt_b")}
    # the cross-trace reference is still visible on the event itself
    assert store.events("t1")[-1].parent_ids == ("evt_a", "evt_x")


def test_report_lists_decisions_and_executions(service) -> None:
    svc, store = service
    store.append(_event("evt_a"))
    effect = CanonicalEffect(
        effect_id="fx_01",
        type=EffectType.WRITE,
        operation="file_write",
        resources=("file://workspace/out.txt",),
    )
    decision = Decision(decision=DecisionOutcome.ALLOW, policy_version="sha256:beef")
    d_event = decision_event(decision, effect, trace_id="t1", session_id="s1", principal="user:alice", now=NOW)
    store.append(d_event, payload=decision_payload(decision, effect))
    x_event = execution_event(
        effect,
        ticket_id="tkt_1",
        trace_id="t1",
        session_id="s1",
        principal="user:alice",
        now=NOW,
        parent_ids=(d_event.event_id,),
    )
    store.append(x_event, payload=execution_payload(effect, "tkt_1", "executed"))

    report = svc.report("t1")
    assert "ALLOW" in report
    assert "sha256:beef" in report
    assert "tkt_1" in report
    assert "executed" in report
