"""Capability tickets: binding, single-use, expiry, non-transferability (supports I5)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from camel.core.effect import CanonicalEffect, DataReference, EffectType
from camel.core.labels import Confidentiality, TrustLabel
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


def test_concurrent_consume_single_use_ticket() -> None:
    """N racing verifiers on a max_uses=1 ticket: exactly one may succeed (I5)."""
    ticket = _issue()
    store = InMemoryTicketStore()

    def spend() -> bool:
        try:
            verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=store, now=NOW)
        except TicketVerificationError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: spend(), range(16)))
    assert results.count(True) == 1
    assert store.uses(ticket.ticket_id) == 1


def test_hash_effect_is_stable_and_sensitive() -> None:
    assert hash_effect(_EFFECT) == hash_effect(_EFFECT.model_copy())
    changed = _EFFECT.model_copy(update={"operation": "force-push"})
    assert hash_effect(_EFFECT) != hash_effect(changed)


def test_hash_binds_data_labels() -> None:
    """Swapping confirmed public data for secret data must invalidate the ticket."""
    public = _EFFECT.model_copy(
        update={
            "data_refs": (DataReference(ref="value://x", label=TrustLabel(confidentiality=Confidentiality.PUBLIC)),)
        }
    )
    secret = public.model_copy(
        update={
            "data_refs": (DataReference(ref="value://x", label=TrustLabel(confidentiality=Confidentiality.SECRET)),)
        }
    )
    assert hash_effect(public) != hash_effect(secret)
    ticket = issue_ticket(KEY, subject="user:alice", effect=public, expires_at=LATER)
    with pytest.raises(TicketVerificationError, match="effect_mismatch"):
        verify_ticket(KEY, ticket, secret, subject="user:alice", store=InMemoryTicketStore(), now=NOW)


def test_hash_stable_across_unordered_collections() -> None:
    """frozenset fields must not make the digest depend on iteration order."""
    a = _EFFECT.model_copy(update={"required_capabilities": frozenset({"net", "fs", "git"})})
    b = _EFFECT.model_copy(update={"required_capabilities": frozenset({"git", "fs", "net"})})
    assert hash_effect(a) == hash_effect(b)


def test_naive_expires_at_rejected_at_construction() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        issue_ticket(KEY, subject="user:alice", effect=_EFFECT, expires_at=datetime(2030, 1, 1))
