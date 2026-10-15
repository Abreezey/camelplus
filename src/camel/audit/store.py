"""Append-only audit event store (arch.md §6.10, §12.4).

Design:

- SQLite; one table for event metadata (queryable columns) plus the full
  versioned event JSON, and a separate table for payloads keyed by
  ``event_id`` (payload/metadata separation).
- A hash chain ``record_hash = sha256(prev_hash | seq | event_json)`` makes
  silent modification detectable: :meth:`AuditStore.verify_chain` recomputes
  the whole chain and raises :class:`ChainIntegrityError` on any mismatch.
- Secrets never enter the store as plaintext: payload fields that could carry
  secrets must be passed through :func:`redact` by the caller. Decision and
  execution payloads contain no secrets by construction (reasons, ids,
  policy version only).
- There is no update or delete API: the store is append-only by design.

Event constructors (:func:`decision_event`, :func:`execution_event`) build the
``CanonicalEvent`` wrappers that module C records for every policy decision
and every broker execution, so the acceptance criterion "another reviewer can
replay a decision from stored events + policy version" is a plain roundtrip
through :meth:`AuditStore.payload_of`.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from camel.core.decision import Decision
from camel.core.effect import CanonicalEffect
from camel.core.events import CanonicalEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    trace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source TEXT NOT NULL,
    ts TEXT NOT NULL,
    event_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_payloads (
    event_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS confirmations (
    request_id TEXT PRIMARY KEY,
    record_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'expired'))
);
"""

GENESIS_HASH = "sha256:" + "0" * 64


class ChainIntegrityError(Exception):
    """Raised when the audit hash chain does not verify."""


class ConfirmationStateError(ValueError):
    """Unknown, altered, or already resolved confirmation; no ticket may escape."""


def redact(value: str) -> str:
    """Replace a secret with a short, non-reversible controlled reference."""
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


class AuditContext(BaseModel):
    """Deployment/origin metadata that plan.md §2.C requires in audit events.

    ``model_version`` (which LLM produced the plan), ``tool_manifest_digest``
    (which tool set was offered) and ``code_commit`` (which code ran) must be
    recorded alongside every decision. Their producers are modules B/D and the
    deployment; until those exist the fields stay ``None`` — the payload
    honestly records "not provided" instead of omitting the key.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_version: str | None = None
    tool_manifest_digest: str | None = None
    code_commit: str | None = None

    @classmethod
    def from_env(cls) -> "AuditContext":
        """Load the deployment-provided fields from ``CAMEL_*`` env vars.

        Empty strings are treated as missing so ``VAR=`` does not pollute the
        audit trail with meaningless values.
        """

        def _get(name: str) -> str | None:
            value = os.environ.get(name)
            return value if value else None

        return cls(
            model_version=_get("CAMEL_MODEL_VERSION"),
            tool_manifest_digest=_get("CAMEL_TOOL_MANIFEST_DIGEST"),
            code_commit=_get("CAMEL_CODE_COMMIT"),
        )


def _record_hash(prev_hash: str, seq: int, event_json: str) -> str:
    return "sha256:" + hashlib.sha256(f"{prev_hash}|{seq}|{event_json}".encode()).hexdigest()


def decision_event(
    decision: Decision,
    effect: CanonicalEffect,
    *,
    trace_id: str,
    session_id: str,
    principal: str,
    now: datetime,
    parent_ids: tuple[str, ...] = (),
) -> CanonicalEvent:
    """Build the audit event recording one policy decision for ``effect``."""
    return CanonicalEvent(
        event_id=f"evt_{uuid.uuid4().hex}",
        trace_id=trace_id,
        session_id=session_id,
        parent_ids=parent_ids,
        principal=principal,
        source="decision",
        payload_ref=f"decision:{effect.effect_id}",
        timestamp=now,
    )


def decision_payload(decision: Decision, effect: CanonicalEffect, context: AuditContext | None = None) -> dict:
    """Non-secret payload for a decision event; sufficient to replay it."""
    return {
        "decision": decision.model_dump(mode="json"),
        "effect": effect.model_dump(mode="json"),
        "context": context.model_dump() if context is not None else None,
    }


def execution_event(
    effect: CanonicalEffect,
    *,
    ticket_id: str,
    trace_id: str,
    session_id: str,
    principal: str,
    now: datetime,
    parent_ids: tuple[str, ...] = (),
) -> CanonicalEvent:
    """Build the audit event recording one broker execution attempt."""
    return CanonicalEvent(
        event_id=f"evt_{uuid.uuid4().hex}",
        trace_id=trace_id,
        session_id=session_id,
        parent_ids=parent_ids,
        principal=principal,
        source="execution",
        payload_ref=f"execution:{effect.effect_id}:{ticket_id}",
        timestamp=now,
    )


def execution_payload(
    effect: CanonicalEffect,
    ticket_id: str,
    outcome: str,
    detail: str | None = None,
    context: AuditContext | None = None,
    credential_handle: str | None = None,
) -> dict:
    """Non-secret payload for an execution event.

    ``outcome`` is one of ``executed`` / ``rejected`` / ``failed``.
    ``credential_handle`` is the opaque reference to the injected short-lived
    credential (the secret itself never appears in any payload).
    """
    payload: dict = {
        "effect": effect.model_dump(mode="json"),
        "ticket_id": ticket_id,
        "outcome": outcome,
        "context": context.model_dump() if context is not None else None,
    }
    if detail is not None:
        payload["detail"] = detail
    if credential_handle is not None:
        payload["credential_handle"] = credential_handle
    return payload


class AuditStore:
    """Append-only, hash-chained store for ``CanonicalEvent``s and payloads."""

    def __init__(self, path: str | Path) -> None:
        """Open (or create) the store at ``path``; ``:memory:`` is supported."""
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def append(self, event: CanonicalEvent, *, payload: dict | None = None) -> str:
        """Append one event (plus optional non-secret payload); return the record hash.

        Raises ``sqlite3.IntegrityError`` if ``event_id`` was already stored —
        every event is stored at most once.
        """
        with self._lock, self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            return self._append_uncommitted(event, payload=payload)

    def _append_uncommitted(self, event: CanonicalEvent, *, payload: dict | None = None) -> str:
        """Caller must hold the lock and an IMMEDIATE transaction."""
        prev = self._conn.execute("SELECT record_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = prev[0] if prev else GENESIS_HASH
        seq = self._conn.execute("SELECT COALESCE(MAX(seq), 0) FROM audit_events").fetchone()[0] + 1
        event_json = event.model_dump_json()
        record_hash = _record_hash(prev_hash, seq, event_json)
        self._conn.execute(
            "INSERT INTO audit_events"
            " (event_id, trace_id, session_id, source, ts, event_json, prev_hash, record_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.trace_id,
                event.session_id,
                event.source,
                event.timestamp.isoformat(),
                event_json,
                prev_hash,
                record_hash,
            ),
        )
        if payload is not None:
            self._conn.execute(
                "INSERT INTO audit_payloads (event_id, payload_json) VALUES (?, ?)",
                (event.event_id, json.dumps(payload, sort_keys=True)),
            )
        return record_hash

    def create_confirmation(self, request_id: str, record: dict, event: CanonicalEvent, *, payload: dict) -> None:
        """Persist the bound request and its audit event in one transaction."""
        with self._lock, self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT INTO confirmations (request_id, record_json, state) VALUES (?, ?, 'pending')",
                (request_id, json.dumps(record, sort_keys=True)),
            )
            self._append_uncommitted(event, payload=payload)

    def confirmation_record(self, request_id: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT record_json FROM confirmations WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            raise ConfirmationStateError("confirmation_unknown")
        return json.loads(row[0])

    def resolve_confirmation(
        self, request_id: str, record: dict, outcome: str, event: CanonicalEvent, *, payload: dict
    ) -> None:
        """CAS pending → terminal plus audit; serializes independent connections."""
        if outcome not in {"approved", "denied", "expired"}:
            raise ValueError("invalid_confirmation_outcome")
        with self._lock, self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            changed = self._conn.execute(
                "UPDATE confirmations SET state = ? WHERE request_id = ? AND record_json = ? AND state = 'pending'",
                (outcome, request_id, json.dumps(record, sort_keys=True)),
            ).rowcount
            if changed != 1:
                raise ConfirmationStateError("confirmation_altered_or_resolved")
            self._append_uncommitted(event, payload=payload)

    def pending_executions(self, trace_id: str | None = None) -> list[CanonicalEvent]:
        """Prepared operations lacking a terminal event. Never automatically replay."""
        events = self.events(trace_id)
        finished = {parent for event in events if event.source == "execution" for parent in event.parent_ids}
        return [event for event in events if event.source == "execution_intent" and event.event_id not in finished]

    def events(self, trace_id: str | None = None) -> list[CanonicalEvent]:
        """Return events in append order, optionally filtered by trace."""
        query = "SELECT event_json FROM audit_events"
        params: tuple = ()
        if trace_id is not None:
            query += " WHERE trace_id = ?"
            params = (trace_id,)
        query += " ORDER BY seq"
        rows = self._conn.execute(query, params).fetchall()
        return [CanonicalEvent.model_validate_json(row[0]) for row in rows]

    def payload_of(self, event_id: str) -> dict | None:
        """Return the payload dict stored with ``event_id``, or ``None``."""
        row = self._conn.execute("SELECT payload_json FROM audit_payloads WHERE event_id = ?", (event_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def verify_chain(self) -> None:
        """Recompute the full hash chain; raise on any mismatch.

        Detects row edits, row deletions (prev-hash linkage breaks) and row
        reordering. Insertion-only tampering between two valid events is
        impossible without knowing how to extend the chain, which requires
        rewriting every subsequent hash.
        """
        prev_hash = GENESIS_HASH
        for seq, event_json, stored_prev, stored_hash in self._conn.execute(
            "SELECT seq, event_json, prev_hash, record_hash FROM audit_events ORDER BY seq"
        ):
            expected = _record_hash(prev_hash, seq, event_json)
            if stored_prev != prev_hash or not hmac.compare_digest(stored_hash, expected):
                raise ChainIntegrityError(f"chain broken at seq={seq}")
            prev_hash = stored_hash

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()
