"""Execution broker: ticket enforcement (I5), sandbox rejection, audit trail."""

import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from camel.audit import AuditStore
from camel.broker import (
    ExecutionBroker,
    KeyVault,
    SandboxProfile,
    SandboxViolationError,
    UnsupportedEffectError,
)
from camel.core.effect import CanonicalEffect, EffectType
from camel.policy.ticket import InMemoryTicketStore, TicketVerificationError, issue_ticket

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(minutes=5)
KEY = b"test-signing-key"


def _read_effect(path: Path) -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_read",
        type=EffectType.READ,
        operation="file_read",
        resources=(f"file://{path}",),
    )


def _write_effect(path: Path) -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_write",
        type=EffectType.WRITE,
        operation="file_write",
        resources=(f"file://{path}",),
    )


@pytest.fixture()
def env(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "note.txt").write_text("hello")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    audit = AuditStore(":memory:")
    tickets = InMemoryTicketStore()
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(workspace, scratch),
        ticket_store=tickets,
        audit=audit,
        now_fn=lambda: NOW,
    )
    return SimpleNamespace(broker=broker, audit=audit, tickets=tickets, workspace=workspace, scratch=scratch)


def _issue(effect: CanonicalEffect, subject: str = "user:alice", **overrides):
    base = {"subject": subject, "effect": effect, "expires_at": LATER}
    return issue_ticket(KEY, **(base | overrides))


def _executions(env, trace: str = "t1"):
    return [e for e in env.audit.events(trace) if e.source == "execution"]


def test_read_with_valid_ticket_executes_and_audits(env) -> None:
    effect = _read_effect(env.workspace / "note.txt")
    result = env.broker.execute(effect, _issue(effect), subject="user:alice", trace_id="t1", session_id="s1")
    assert result.output == b"hello"
    executions = _executions(env)
    assert len(executions) == 1
    assert env.audit.payload_of(executions[0].event_id)["outcome"] == "executed"
    env.audit.verify_chain()


def test_forged_ticket_rejected_and_audited(env) -> None:
    effect = _read_effect(env.workspace / "note.txt")
    forged = _issue(effect).model_copy(update={"max_uses": 100})
    with pytest.raises(TicketVerificationError, match="invalid_signature"):
        env.broker.execute(effect, forged, subject="user:alice", trace_id="t1", session_id="s1")
    assert env.audit.payload_of(_executions(env)[0].event_id)["outcome"] == "rejected"
    assert env.audit.payload_of(_executions(env)[0].event_id)["detail"] == "invalid_signature"


def test_wrong_subject_rejected(env) -> None:
    effect = _read_effect(env.workspace / "note.txt")
    with pytest.raises(TicketVerificationError, match="subject_mismatch"):
        env.broker.execute(effect, _issue(effect), subject="user:mallory", trace_id="t1", session_id="s1")


def test_expired_ticket_rejected(env) -> None:
    effect = _read_effect(env.workspace / "note.txt")
    ticket = _issue(effect, expires_at=NOW)
    with pytest.raises(TicketVerificationError, match="ticket_expired"):
        env.broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")


def test_ticket_single_use(env) -> None:
    effect = _read_effect(env.workspace / "note.txt")
    ticket = _issue(effect)
    env.broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")
    with pytest.raises(TicketVerificationError, match="max_uses_exceeded"):
        env.broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")
    outcomes = [env.audit.payload_of(e.event_id)["outcome"] for e in _executions(env)]
    assert outcomes == ["executed", "rejected"]


def test_wrong_signing_key_rejected(env) -> None:
    effect = _read_effect(env.workspace / "note.txt")
    ticket = issue_ticket(b"attacker-key", subject="user:alice", effect=effect, expires_at=LATER)
    with pytest.raises(TicketVerificationError, match="invalid_signature"):
        env.broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")


def test_sandbox_rejection_does_not_burn_ticket(env) -> None:
    effect = _read_effect(Path("/etc/passwd"))
    ticket = _issue(effect)
    with pytest.raises(SandboxViolationError):
        env.broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")
    assert env.tickets.uses(ticket.ticket_id) == 0
    assert env.audit.payload_of(_executions(env)[0].event_id)["outcome"] == "rejected"


def test_write_executes_with_private_permissions(env) -> None:
    effect = _write_effect(env.scratch / "out.txt")
    env.broker.execute(
        effect,
        _issue(effect),
        subject="user:alice",
        trace_id="t1",
        session_id="s1",
        content=b"data",
    )
    target = env.scratch / "out.txt"
    assert target.read_bytes() == b"data"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert env.audit.payload_of(_executions(env)[0].event_id)["outcome"] == "executed"


def test_unsupported_effect_type_fails_closed(env) -> None:
    effect = CanonicalEffect(
        effect_id="fx_egress",
        type=EffectType.EGRESS,
        operation="http_post",
        destination="https://example.invalid/upload",
    )
    with pytest.raises(UnsupportedEffectError):
        env.broker.execute(effect, _issue(effect), subject="user:alice", trace_id="t1", session_id="s1")
    assert env.audit.payload_of(_executions(env)[0].event_id)["outcome"] == "rejected"


def test_write_requires_content(env) -> None:
    effect = _write_effect(env.scratch / "out.txt")
    with pytest.raises(ValueError, match="requires content"):
        env.broker.execute(effect, _issue(effect), subject="user:alice", trace_id="t1", session_id="s1")


def test_read_missing_file_fails_audited(env) -> None:
    effect = _read_effect(env.workspace / "missing.txt")
    with pytest.raises(OSError):
        env.broker.execute(effect, _issue(effect), subject="user:alice", trace_id="t1", session_id="s1")
    assert env.audit.payload_of(_executions(env)[0].event_id)["outcome"] == "failed"


def test_every_attempt_audited_once(env) -> None:
    effect = _read_effect(env.workspace / "note.txt")
    env.broker.execute(effect, _issue(effect), subject="user:alice", trace_id="t1", session_id="s1")
    events = env.audit.events("t1")
    assert [event.source for event in events] == ["execution_intent", "execution"]
    assert env.audit.payload_of(events[0].event_id)["outcome"] == "prepared"
    assert env.audit.payload_of(events[1].event_id)["outcome"] == "executed"
    assert events[1].parent_ids == (events[0].event_id,)
    env.audit.verify_chain()


def test_execute_with_vault_returns_handle_audits_handle_only(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "note.txt").write_text("hello")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    audit = AuditStore(":memory:")
    vault = KeyVault(b"vault-master")
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(workspace, scratch),
        ticket_store=InMemoryTicketStore(),
        audit=audit,
        vault=vault,
        now_fn=lambda: NOW,
    )
    effect = _read_effect(workspace / "note.txt")
    ticket = _issue(effect)
    result = broker.execute(effect, ticket, subject="user:alice", trace_id="t_vault", session_id="s1")
    assert result.credential_handle is not None
    assert result.credential_handle.startswith("cred_")
    # the handle matches what the vault derives for this exact ticket
    expected = vault.derive(subject="user:alice", ticket_id=ticket.ticket_id, expires_at=ticket.expires_at)
    assert result.credential_handle == expected.handle

    execution_events = [e for e in audit.events("t_vault") if e.source == "execution"]
    payload = audit.payload_of(execution_events[0].event_id)
    assert payload is not None
    assert payload["credential_handle"] == result.credential_handle
    assert "secret" not in payload
    audit.verify_chain()


def test_no_vault_behavior_unchanged(env) -> None:
    effect = _read_effect(env.workspace / "note.txt")
    result = env.broker.execute(effect, _issue(effect), subject="user:alice", trace_id="t1", session_id="s1")
    assert result.credential_handle is None
    payload = env.audit.payload_of(_executions(env)[0].event_id)
    assert "credential_handle" not in payload


def test_vault_write_also_gets_handle(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    audit = AuditStore(":memory:")
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(workspace, scratch),
        ticket_store=InMemoryTicketStore(),
        audit=audit,
        vault=KeyVault(b"vault-master"),
        now_fn=lambda: NOW,
    )
    effect = _write_effect(scratch / "out.txt")
    result = broker.execute(
        effect, _issue(effect), subject="user:alice", trace_id="t_vw", session_id="s1", content=b"data"
    )
    assert result.credential_handle is not None and result.credential_handle.startswith("cred_")
    assert (scratch / "out.txt").read_bytes() == b"data"
    audit.verify_chain()
