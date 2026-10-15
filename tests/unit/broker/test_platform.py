"""Unsupported write platforms reject before authorization consumption or IO."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from camel.audit import AuditStore
from camel.broker import ExecutionBroker, SandboxProfile, UnsupportedEffectError
from camel.broker import executor as executor_module
from camel.core import CanonicalEffect, EffectType
from camel.policy.ticket import InMemoryTicketStore, issue_ticket


def test_missing_nofollow_is_rejected_and_audited_before_ticket_use(tmp_path: Path, monkeypatch) -> None:
    # A missing platform primitive is a failure-injection case on every OS.
    monkeypatch.delattr(executor_module.os, "O_NOFOLLOW", raising=False)
    workspace = tmp_path / "workspace"
    scratch = tmp_path / "scratch"
    workspace.mkdir()
    scratch.mkdir()
    target = scratch / "out.txt"
    audit = AuditStore(":memory:")
    tickets = InMemoryTicketStore()
    key = b"synthetic-platform-test-key"
    now = datetime(2026, 10, 15, tzinfo=timezone.utc)
    effect = CanonicalEffect(
        effect_id="platform-test", type=EffectType.WRITE, operation="file_write", resources=(str(target),)
    )
    ticket = issue_ticket(key, subject="user:synthetic", effect=effect, expires_at=now + timedelta(minutes=1))
    broker = ExecutionBroker(
        signing_key=key,
        profile=SandboxProfile.workspace(workspace, scratch),
        ticket_store=tickets,
        audit=audit,
        now_fn=lambda: now,
    )
    with pytest.raises(UnsupportedEffectError, match="POSIX O_NOFOLLOW"):
        broker.execute(
            effect, ticket, subject="user:synthetic", trace_id="platform-test", session_id="s1", content=b"synthetic"
        )
    assert not target.exists()
    assert tickets.uses(ticket.ticket_id) == 0
    events = audit.events("platform-test")
    assert len(events) == 1
    payload = audit.payload_of(events[0].event_id)
    assert payload is not None
    assert payload["outcome"] == "rejected"
    audit.verify_chain()
