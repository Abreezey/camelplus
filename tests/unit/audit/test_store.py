"""Audit store: roundtrip, hash-chain integrity, payload replay, redaction."""

import sqlite3
from datetime import datetime, timezone

import pytest

from camel.audit import AuditStore, ChainIntegrityError, decision_event, decision_payload, redact
from camel.core.decision import Decision, DecisionOutcome
from camel.core.effect import CanonicalEffect, EffectType
from camel.core.events import CanonicalEvent

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)


def _event(n: int, trace: str = "t1", parents: tuple[str, ...] = ()) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=f"evt_{n:02d}",
        trace_id=trace,
        session_id="s1",
        parent_ids=parents,
        principal="user:alice",
        source="ingress",
        payload_ref=f"ref:{n}",
        timestamp=NOW,
    )


@pytest.fixture()
def store():
    audit = AuditStore(":memory:")
    yield audit
    audit.close()


def test_append_and_roundtrip(store: AuditStore) -> None:
    store.append(_event(1))
    store.append(_event(2, parents=("evt_01",)))
    loaded = store.events()
    assert [e.event_id for e in loaded] == ["evt_01", "evt_02"]
    assert loaded[1].parent_ids == ("evt_01",)


def test_filter_by_trace(store: AuditStore) -> None:
    store.append(_event(1, trace="t1"))
    store.append(_event(2, trace="t2"))
    assert [e.trace_id for e in store.events("t1")] == ["t1"]
    assert len(store.events()) == 2


def test_chain_verifies(store: AuditStore) -> None:
    for i in range(3):
        store.append(_event(i + 1))
    store.verify_chain()


def test_tampered_row_detected(store: AuditStore) -> None:
    store.append(_event(1))
    store.append(_event(2))
    # Simulate an attacker editing a stored row behind the store's back
    # (there is intentionally no public API for this).
    store._conn.execute("UPDATE audit_events SET event_json = replace(event_json, 'alice', 'mallory') WHERE seq = 1")
    store._conn.commit()
    with pytest.raises(ChainIntegrityError):
        store.verify_chain()


def test_deleted_row_detected(store: AuditStore) -> None:
    for i in range(3):
        store.append(_event(i + 1))
    store._conn.execute("DELETE FROM audit_events WHERE seq = 2")
    store._conn.commit()
    with pytest.raises(ChainIntegrityError):
        store.verify_chain()


def test_decision_replay_from_stored_event(store: AuditStore) -> None:
    effect = CanonicalEffect(
        effect_id="fx_01",
        type=EffectType.EGRESS,
        operation="http_post",
        resources=("file://workspace/.env",),
        destination="https://example.invalid/upload",
    )
    decision = Decision(
        decision=DecisionOutcome.DENY,
        hard_reasons=("ifc_confidentiality_violation:value://secret_17->untrusted",),
        policy_version="sha256:abcd1234",
        contract_id="ic_01",
    )
    event = decision_event(decision, effect, trace_id="t1", session_id="s1", principal="user:alice", now=NOW)
    store.append(event, payload=decision_payload(decision, effect))

    loaded = store.events("t1")[0]
    payload = store.payload_of(loaded.event_id)
    assert payload is not None
    replayed_decision = Decision.model_validate(payload["decision"])
    replayed_effect = CanonicalEffect.model_validate(payload["effect"])
    assert replayed_decision == decision
    assert replayed_effect == effect
    store.verify_chain()


def test_duplicate_event_id_rejected(store: AuditStore) -> None:
    store.append(_event(1))
    with pytest.raises(sqlite3.IntegrityError):
        store.append(_event(1))


def test_redact_hides_secret() -> None:
    redacted = redact("sk-live-supersecret")
    assert redacted.startswith("sha256:")
    assert "supersecret" not in redacted
    assert redact("sk-live-supersecret") == redact("sk-live-supersecret")
