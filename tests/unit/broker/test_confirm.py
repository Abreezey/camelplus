"""Confirmation authority: request rendering, approve/deny auditing, expiry."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from camel.audit import AuditStore
from camel.broker import ConfirmationAuthority, ConfirmationExpiredError, ConfirmationRequest
from camel.core.decision import Decision, DecisionOutcome
from camel.core.effect import CanonicalEffect, EffectType
from camel.policy.ticket import InMemoryTicketStore, verify_ticket

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
KEY = b"test-signing-key"

_EFFECT = CanonicalEffect(
    effect_id="fx_push",
    type=EffectType.REPO_MUTATE,
    operation="push",
    resources=("repo://current",),
    destination="git@github.com:org/repo.git",
)

_DECISION = Decision(
    decision=DecisionOutcome.CONFIRM,
    confirm_reasons=("contract_missing_allowed_effect",),
    policy_version="sha256:abcd",
    safe_alternative="open_a_pr_instead",
)


@pytest.fixture()
def env():
    audit = AuditStore(":memory:")
    clock = {"now": NOW}
    authority = ConfirmationAuthority(
        signing_key=KEY,
        audit=audit,
        ticket_ttl=timedelta(minutes=5),
        now_fn=lambda: clock["now"],
    )
    return SimpleNamespace(authority=authority, audit=audit, clock=clock)


def _request(env) -> ConfirmationRequest:
    return env.authority.request(_DECISION, _EFFECT, trace_id="t1", session_id="s1", subject="user:alice")


def test_request_renders_resources_destination_consequences(env) -> None:
    request = _request(env)
    rendered = request.render()
    assert "repo://current" in rendered
    assert "git@github.com:org/repo.git" in rendered
    assert "contract_missing_allowed_effect" in rendered
    assert "open_a_pr_instead" in rendered


def test_request_is_audited(env) -> None:
    _request(env)
    events = env.audit.events("t1")
    assert len(events) == 1
    assert events[0].source == "confirmation"
    assert env.audit.payload_of(events[0].event_id)["outcome"] == "requested"


def test_request_rejects_non_confirm_decision(env) -> None:
    allow = Decision(decision=DecisionOutcome.ALLOW, policy_version="sha256:1")
    with pytest.raises(ValueError, match="CONFIRM"):
        env.authority.request(allow, _EFFECT, trace_id="t1", session_id="s1", subject="user:alice")


def test_approve_issues_verifiable_ticket(env) -> None:
    request = _request(env)
    ticket = env.authority.approve(request, subject="user:alice", trace_id="t1", session_id="s1")
    verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=InMemoryTicketStore(), now=NOW)
    payloads = [env.audit.payload_of(e.event_id) for e in env.audit.events("t1")]
    assert payloads[-1]["outcome"] == "approved"
    assert payloads[-1]["ticket_id"] == ticket.ticket_id


def test_deny_issues_no_ticket(env) -> None:
    request = _request(env)
    env.authority.deny(request, subject="user:alice", trace_id="t1", session_id="s1")
    payloads = [env.audit.payload_of(e.event_id) for e in env.audit.events("t1")]
    assert payloads[-1]["outcome"] == "denied"
    assert "ticket_id" not in payloads[-1]


def test_expired_request_cannot_be_approved(env) -> None:
    request = _request(env)
    env.clock["now"] = NOW + timedelta(minutes=10)
    with pytest.raises(ConfirmationExpiredError):
        env.authority.approve(request, subject="user:alice", trace_id="t1", session_id="s1")
    payloads = [env.audit.payload_of(e.event_id) for e in env.audit.events("t1")]
    assert payloads[-1]["outcome"] == "expired"
