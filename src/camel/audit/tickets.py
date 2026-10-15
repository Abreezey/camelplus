"""Persistent ticket-use counting backed by SQLite.

Implements the ``TicketStore`` protocol defined by module A in
``camel/policy/ticket.py`` (which explicitly delegates production storage to
the execution/audit layer). Use counting must survive process restarts,
otherwise a relayed/replayed ticket could be spent twice.
"""

import sqlite3
import threading
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ticket_uses (
    ticket_id TEXT PRIMARY KEY,
    uses INTEGER NOT NULL DEFAULT 0
);
"""


class SQLiteTicketStore:
    """Durable ``TicketStore``: counts ticket uses in SQLite (protocol of module A)."""

    def __init__(self, path: str | Path) -> None:
        """Open (or create) the store at ``path``; ``:memory:`` is supported."""
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def uses(self, ticket_id: str) -> int:
        """Return how many times ``ticket_id`` has been used."""
        row = self._conn.execute("SELECT uses FROM ticket_uses WHERE ticket_id = ?", (ticket_id,)).fetchone()
        return row[0] if row else 0

    def try_consume(self, ticket_id: str, max_uses: int) -> bool:
        """Atomically consume one use iff under the limit (single conditional upsert).

        The limit check lives in the ``WHERE`` clause of the upsert, so the
        check and the increment are one indivisible statement — concurrent
        verifiers cannot both spend the last use of a ticket (I5).
        """
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO ticket_uses (ticket_id, uses) VALUES (?, 1)"
                " ON CONFLICT(ticket_id) DO UPDATE SET uses = uses + 1"
                " WHERE ticket_uses.uses < ?",
                (ticket_id, max_uses),
            )
        return cursor.rowcount == 1

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()
