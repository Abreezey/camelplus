"""SQLiteTicketStore: durability and interop with module A's verify_ticket."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from camel.audit import SQLiteTicketStore
from camel.core.effect import CanonicalEffect, EffectType
from camel.policy.ticket import TicketVerificationError, issue_ticket, verify_ticket

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(minutes=5)
KEY = b"test-signing-key"

_EFFECT = CanonicalEffect(
    effect_id="fx_01",
    type=EffectType.WRITE,
    operation="file_write",
    resources=("file://workspace/out.txt",),
)


def test_counts_uses() -> None:
    store = SQLiteTicketStore(":memory:")
    assert store.uses("tkt_1") == 0
    assert store.try_consume("tkt_1", max_uses=2)
    assert store.try_consume("tkt_1", max_uses=2)
    assert store.uses("tkt_1") == 2
    assert not store.try_consume("tkt_1", max_uses=2)
    assert store.uses("tkt_1") == 2
    store.close()


def test_counts_survive_restart(tmp_path) -> None:
    path = tmp_path / "tickets.db"
    first = SQLiteTicketStore(path)
    assert first.try_consume("tkt_1", max_uses=3)
    assert first.try_consume("tkt_1", max_uses=3)
    first.close()

    second = SQLiteTicketStore(path)
    assert second.uses("tkt_1") == 2
    second.close()


def test_concurrent_consume_single_use_ticket(tmp_path) -> None:
    """N racing verifiers on a max_uses=1 ticket: exactly one may succeed."""
    ticket = issue_ticket(KEY, subject="user:alice", effect=_EFFECT, expires_at=LATER)
    store = SQLiteTicketStore(tmp_path / "tickets.db")

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
    store.close()


def test_interops_with_verify_ticket_single_use(tmp_path) -> None:
    """The durable store must enforce the same single-use semantics as A's in-memory one."""
    ticket = issue_ticket(KEY, subject="user:alice", effect=_EFFECT, expires_at=LATER)
    store = SQLiteTicketStore(tmp_path / "tickets.db")
    verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=store, now=NOW)
    with pytest.raises(TicketVerificationError, match="max_uses_exceeded"):
        verify_ticket(KEY, ticket, _EFFECT, subject="user:alice", store=store, now=NOW)
    store.close()
