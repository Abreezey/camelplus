"""Canonical event model: versioning, serialization, defaults."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from camel.core.events import CanonicalEvent
from camel.core.labels import Integrity, TrustLabel

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)


def _event(**overrides) -> CanonicalEvent:
    base = {
        "event_id": "evt_web_17",
        "trace_id": "tr_01",
        "session_id": "sess_01",
        "principal": "user:alice",
        "source": "web",
        "payload_ref": "payloads/evt_web_17",
        "timestamp": NOW,
    }
    return CanonicalEvent(**(base | overrides))


def test_minimal_event_and_defaults() -> None:
    event = _event()
    assert event.schema_version == 1
    assert event.parent_ids == ()
    assert event.span_map == {}
    # Default label is the safe one: untrusted, public, data-only.
    assert event.labels.integrity == Integrity.UNTRUSTED


def test_provenance_fields_roundtrip() -> None:
    event = _event(
        parent_ids=("evt_tool_04",),
        span_map={"body": (0, 128)},
        labels=TrustLabel(provenance=frozenset({"evt_tool_04"}), integrity=Integrity.UNTRUSTED),
    )
    restored = CanonicalEvent.model_validate_json(event.model_dump_json())
    assert restored == event
    assert restored.span_map == {"body": (0, 128)}


def test_wrong_schema_version_rejected() -> None:
    with pytest.raises(ValidationError):
        _event(schema_version=2)
