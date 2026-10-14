"""Capability tickets: binding, single-use, expiry, non-transferability (supports I5)."""

from datetime import datetime, timedelta, timezone

import pytest

from camel.core.effect import CanonicalEffect, EffectType
from camel.policy.ticket import (
    InMemoryTicketStore,
    TicketVerificationError,
    hash_effect,
    issue_ticket,
    verify_ticket,
)

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(minutes=5)
KEY = b"test-signing-key"

_EFFECT = CanonicalEffect(
    effect_id="fx_01",
    type=EffectType.REPO_MUTATE,
    operation="push",
    resources=("repo://current",),
    destination="git@github.com:org/repo.git",
)


def _issue(**overrides):
    base = {"subject": "user:alice", "effect": _EFFECT, "expires_at": LATER}
    return issue_ticket(KEY, **(base | overrides))


def test_issue_and_verify_single_use() -> None:
    ticket = _issue()
    store = InMemoryTicketStore()
    verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=store, now=NOW)
    assert store.uses(ticket.ticket_id) == 1
    with pytest.raises(TicketVerificationError, match="max_uses_exceeded"):
        verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=store, now=NOW)


def test_tampered_ticket_rejected() -> None:
    ticket = _issue()
    forged = ticket.model_copy(update={"subject": "user:mallory", "max_uses": 100})
    with pytest.raises(TicketVerificationError, match="invalid_signature"):
        verify_ticket(KEY, forged, _EFFECT, subject="user:mallory", store=InMemoryTicketStore(), now=NOW)


def test_wrong_key_rejected() -> None:
    with pytest.raises(TicketVerificationError, match="invalid_signature"):
        verify_ticket(b"other-key", _issue(), _EFFECT, subject="user:alice", store=InMemoryTicketStore(), now=NOW)


def test_ticket_not_transferable_to_other_subject() -> None:
    with pytest.raises(TicketVerificationError, match="subject_mismatch"):
        verify_ticket(KEY, _issue(), _EFFECT, subject="user:bob", store=InMemoryTicketStore(), now=NOW)


def test_ticket_bound_to_exact_effect() -> None:
    different_branch = _EFFECT.model_copy(update={"resources": ("repo://other",)})
    with pytest.raises(TicketVerificationError, match="effect_mismatch"):
        verify_ticket(KEY, _issue(), different_branch, subject="user:alice", store=InMemoryTicketStore(), now=NOW)


def test_expired_ticket_rejected() -> None:
    ticket = _issue()
    with pytest.raises(TicketVerificationError, match="ticket_expired"):
        verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=InMemoryTicketStore(), now=LATER)


def test_max_uses_respected() -> None:
    ticket = _issue(max_uses=2)
    store = InMemoryTicketStore()
    verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=store, now=NOW)
    verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=store, now=NOW)
    with pytest.raises(TicketVerificationError, match="max_uses_exceeded"):
        verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=store, now=NOW)


def test_hash_effect_is_stable_and_sensitive() -> None:
    same = _EFFECT.model_copy(update={"effect_id": "fx_99", "derived_from": ("evt_1",)})
    assert hash_effect(_EFFECT) == hash_effect(same)
    changed = _EFFECT.model_copy(update={"operation": "force-push"})
    assert hash_effect(_EFFECT) != hash_effect(changed)
