"""Authenticated SQLite records and transactional metadata-only event outbox."""

import hashlib
import hmac
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ValidationError

from camel.audit.store import AuditStore
from camel.core import Authority, CanonicalEvent, TrustLabel
from camel.detection.models import identity_view
from camel.detection.rules import detect, predicted_attack
from camel.memory.models import (
    Context,
    Entry,
    MemoryDeniedError,
    MemoryIntegrityError,
    MemoryPolicy,
    Result,
    Source,
    Write,
    WriteBinding,
    aware,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL, seal TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_sources (id TEXT PRIMARY KEY, value TEXT NOT NULL, seal TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_entries (
 id TEXT PRIMARY KEY, value TEXT NOT NULL, content TEXT NOT NULL, seal TEXT NOT NULL, dedupe TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_events (
 seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, value TEXT NOT NULL, seal TEXT NOT NULL
);
"""


def canonical(value):
    if isinstance(value, BaseModel):
        return canonical(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, set | frozenset):
        return sorted(canonical(item) for item in value)
    if isinstance(value, list | tuple):
        return [canonical(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def encoded(value):
    return json.dumps(canonical(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


class MemoryGate:
    def __init__(self, path: str | Path, *, key: bytes, policy: MemoryPolicy, store_id: str):
        if not isinstance(key, bytes) or len(key) < 32 or not store_id or len(store_id) > 128:
            raise ValueError("explicit_key_and_store_identity_required")
        self._key = key
        self.policy = policy
        self.store_id = store_id
        self.policy_digest = digest(encoded(policy))
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=5)
        self._conn.execute("PRAGMA foreign_keys=ON")
        try:
            tables = {row[0] for row in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and tables != {"memory_meta", "memory_sources", "memory_entries", "memory_events"}:
                raise MemoryIntegrityError("unknown_or_partial_store_schema")
            self._conn.executescript(SCHEMA)
            with self._transaction():
                row = self._conn.execute("SELECT value,seal FROM memory_meta WHERE name='identity'").fetchone()
                identity = encoded({"schema_version": 1, "store_id": store_id})
                if row is None:
                    if tables:
                        raise MemoryIntegrityError("store_identity_missing")
                    self._conn.execute(
                        "INSERT INTO memory_meta VALUES ('identity',?,?)", (identity, self._seal("identity", identity))
                    )
                elif row[0] != identity or not hmac.compare_digest(row[1], self._seal("identity", row[0])):
                    raise MemoryIntegrityError("wrong_store_key_or_identity")
        except Exception:
            self._conn.close()
            raise

    def _seal(self, domain, text):
        return hmac.new(self._key, (self.store_id + "\0" + domain + "\0" + text).encode(), hashlib.sha256).hexdigest()

    def _matches(self, seal, domain, text):
        return isinstance(seal, str) and isinstance(text, str) and hmac.compare_digest(seal, self._seal(domain, text))

    @contextmanager
    def _transaction(self):
        with self._lock, self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            yield

    def close(self):
        self._conn.close()

    def _event(self, operation, context, now, *, entry_id=None, label=None, parents=(), reason=None, content_ref=None):
        seq = self._conn.execute("SELECT COALESCE(MAX(seq),0)+1 FROM memory_events").fetchone()[0]
        event_id = f"memory:{self.store_id}:{seq}"
        event = CanonicalEvent(
            event_id=event_id,
            trace_id=context.trace_id,
            session_id=context.session_id,
            parent_ids=tuple(dict.fromkeys(parents)),
            principal=context.principal,
            source="memory_" + operation,
            payload_ref="memory-event:" + event_id,
            labels=label if label is not None else TrustLabel(provenance=frozenset({event_id})),
            timestamp=now,
        )
        payload = {
            "operation": operation,
            "entry_id": entry_id,
            "reason": reason,
            "content_ref": content_ref,
            "policy_version": self.policy.version,
            "policy_digest": self.policy_digest,
        }
        value = encoded({"sequence": seq, "event": event, "payload": payload})
        self._conn.execute(
            "INSERT INTO memory_events VALUES (?,?,?,?)", (seq, event_id, value, self._seal("event:" + event_id, value))
        )
        return event_id

    def _deny(self, operation, context, now, reason, *, entry_id=None, parents=()):
        self._event(operation + "_denied", context, now, entry_id=entry_id, parents=parents, reason=reason)
        return Result(status="DENIED", reasons=(reason,))

    def register_source(self, source: Source, *, context: Context, now: datetime):
        aware(now)
        with self._transaction():
            if context.principal not in self.policy.writers:
                raise MemoryDeniedError("unrecognized_source_registrar")
            if source.source_id not in source.label.provenance:
                raise MemoryDeniedError("source_missing_own_provenance")
            if self._conn.execute("SELECT 1 FROM memory_sources WHERE id=?", (source.source_id,)).fetchone():
                raise MemoryDeniedError("duplicate_source")
            event_id = self._event("source", context, now, label=source.label, parents=(source.event_id,))
            value = encoded({"source": source, "registered_event_id": event_id})
            self._conn.execute(
                "INSERT INTO memory_sources VALUES (?,?,?)",
                (source.source_id, value, self._seal("source:" + source.source_id, value)),
            )

    def _source(self, source_id):
        row = self._conn.execute("SELECT value,seal FROM memory_sources WHERE id=?", (source_id,)).fetchone()
        if row is None:
            raise MemoryDeniedError("source_not_registered")
        if not self._matches(row[1], "source:" + source_id, row[0]):
            raise MemoryIntegrityError("source_seal_mismatch")
        try:
            value = json.loads(row[0])
            if set(value) != {"source", "registered_event_id"}:
                raise ValueError("source_shape")
            source = Source.model_validate_json(encoded(value["source"]))
            if source.source_id != source_id or source_id not in source.label.provenance:
                raise ValueError("source_identity")
            registered, _ = self._checked_event(value["registered_event_id"])
            if registered.source != "memory_source" or registered.labels != source.label:
                raise ValueError("source_registration_event")
            return source, value["registered_event_id"]
        except (ValueError, TypeError, KeyError, ValidationError):
            raise MemoryIntegrityError("source_record_invalid") from None

    def _load(self, entry_id, *, seen=frozenset(), depth=0, memo=None):
        memo = memo if memo is not None else {}
        if entry_id in seen or depth > self.policy.max_depth:
            raise MemoryIntegrityError("lineage_cycle_or_depth_limit")
        if entry_id in memo:
            if depth + memo[entry_id][3] > self.policy.max_depth:
                raise MemoryIntegrityError("lineage_depth_limit")
            return memo[entry_id][:3]
        row = self._conn.execute("SELECT value,content,seal FROM memory_entries WHERE id=?", (entry_id,)).fetchone()
        if row is None:
            raise MemoryDeniedError("entry_or_parent_missing")
        if not self._matches(row[2], "entry:" + entry_id, row[0]):
            raise MemoryIntegrityError("entry_seal_mismatch")
        try:
            entry = Entry.model_validate_json(row[0])
            if entry.entry_id != entry_id or not isinstance(row[1], str) or digest(row[1]) != entry.content_ref:
                raise ValueError("entry_content_or_identity")
            if entry.policy_version != self.policy.version or entry.policy_digest != self.policy_digest:
                raise MemoryDeniedError("policy_changed")
            sources = [self._source(source_id) for source_id in entry.source_ids]
            if (
                not sources
                or len(set(entry.source_ids)) != len(entry.source_ids)
                or len(set(entry.parent_ids)) != len(entry.parent_ids)
            ):
                raise ValueError("empty_or_duplicate_lineage")
            label = sources[0][0].label
            for source, _ in sources[1:]:
                label = label.join(source.label)
            ancestors = {}
            height = 0
            for parent_id in entry.parent_ids:
                parent, _, parents = self._load(parent_id, seen=seen | {entry_id}, depth=depth + 1, memo=memo)
                if parent.created_at > entry.created_at or entry.expires_at > parent.expires_at:
                    raise ValueError("parent_ttl_or_time_inconsistent")
                label = label.join(parent.labels)
                ancestors.update({item.entry_id: item for item in [parent, *parents]})
                height = max(height, 1 + memo[parent_id][3])
            label = label.model_copy(update={"authority": Authority.DATA_ONLY, "execute_scopes": frozenset()})
            if entry.labels != label or entry.expires_at <= entry.created_at:
                raise ValueError("derived_label_or_expiry_inconsistent")
            event, payload = self._checked_event(entry.write_event_id)
            if (
                event.source != "memory_write"
                or event.principal != entry.writer
                or event.labels != entry.labels
                or event.session_id != entry.session_id
                or event.trace_id != entry.trace_id
                or event.timestamp != entry.created_at
                or payload["entry_id"] != entry_id
                or payload["content_ref"] != entry.content_ref
            ):
                raise ValueError("write_event_inconsistent")
            event, payload = self._checked_event(entry.state_event_id)
            if event.labels != entry.labels or payload["entry_id"] != entry_id:
                raise ValueError("state_event_inconsistent")
            result = (entry, row[1], list(ancestors.values()))
            memo[entry_id] = (*result, height)
            return result
        except (ValueError, TypeError, KeyError, ValidationError):
            raise MemoryIntegrityError("entry_record_invalid") from None

    def put(self, request: Write, *, binding: WriteBinding, context: Context, now: datetime) -> Result:
        aware(now)
        with self._transaction():
            try:
                if context.principal not in self.policy.writers:
                    raise MemoryDeniedError("writer_not_allowed")
                if (
                    not isinstance(binding, WriteBinding)
                    or binding.principal != context.principal
                    or binding.entry_id != request.entry_id
                    or binding.source_ids != request.source_ids
                    or binding.parent_ids != request.parent_ids
                    or binding.content_ref != digest(request.content)
                ):
                    raise MemoryDeniedError("host_data_flow_binding_mismatch")
                if request.expires_at <= now:
                    raise MemoryDeniedError("new_entry_already_expired")
                if len(set(request.source_ids)) != len(request.source_ids) or len(set(request.parent_ids)) != len(
                    request.parent_ids
                ):
                    raise MemoryDeniedError("duplicate_lineage_ids")
                if request.entry_id in request.parent_ids:
                    raise MemoryDeniedError("self_parent")
                sources = [self._source(source_id) for source_id in request.source_ids]
                if self._conn.execute("SELECT 1 FROM memory_entries WHERE id=?", (request.entry_id,)).fetchone():
                    raise MemoryDeniedError("duplicate_entry_id")
                dedupe = digest(
                    encoded(
                        {
                            "content": digest(request.content),
                            "sources": sorted(request.source_ids),
                            "parents": sorted(request.parent_ids),
                        }
                    )
                )
                if self._conn.execute("SELECT 1 FROM memory_entries WHERE dedupe=?", (dedupe,)).fetchone():
                    raise MemoryDeniedError("duplicate_content_lineage")
                if self._conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0] >= self.policy.max_entries:
                    raise MemoryDeniedError("entry_count_limit")
                expiry = min(request.expires_at, now + timedelta(seconds=self.policy.max_ttl_seconds))
                label = sources[0][0].label
                parents = [event_id for _, event_id in sources]
                quarantined = False
                for source, _ in sources[1:]:
                    label = label.join(source.label)
                for parent_id in request.parent_ids:
                    parent, _, ancestors = self._load(parent_id)
                    if any(item.expires_at <= now for item in [parent, *ancestors]):
                        raise MemoryDeniedError("expired_parent")
                    quarantined |= any(item.state == "quarantined" for item in [parent, *ancestors])
                    label = label.join(parent.labels)
                    expiry = min(expiry, parent.expires_at)
                    parents.append(parent.state_event_id)
                label = label.model_copy(update={"authority": Authority.DATA_ONLY, "execute_scopes": frozenset()})
                detection = detect(
                    (
                        identity_view(
                            "memory-candidate",
                            "memory",
                            request.content,
                            label.model_copy(update={"provenance": label.provenance | {"memory-candidate"}}),
                        ),
                    )
                )
                if detection.status != "OK":
                    quarantined = True
                else:
                    quarantined |= predicted_attack(detection) is True
                state = "quarantined" if quarantined else "active"
                ref = digest(request.content)
                event_id = self._event(
                    "write",
                    context,
                    now,
                    entry_id=request.entry_id,
                    label=label,
                    parents=parents,
                    reason=state,
                    content_ref=ref,
                )
                entry = Entry(
                    entry_id=request.entry_id,
                    content_ref=ref,
                    source_ids=request.source_ids,
                    parent_ids=request.parent_ids,
                    writer=context.principal,
                    session_id=context.session_id,
                    trace_id=context.trace_id,
                    labels=label,
                    created_at=now,
                    expires_at=expiry,
                    policy_version=self.policy.version,
                    policy_digest=self.policy_digest,
                    state=state,
                    write_event_id=event_id,
                    state_event_id=event_id,
                )
                value = encoded(entry)
                self._conn.execute(
                    "INSERT INTO memory_entries VALUES (?,?,?,?,?)",
                    (entry.entry_id, value, request.content, self._seal("entry:" + entry.entry_id, value), dedupe),
                )
                # Validate the new lineage within the same transaction before making it durable.
                self._load(entry.entry_id)
                return Result(status="QUARANTINED" if quarantined else "STORED", entry=entry)
            except (MemoryDeniedError, MemoryIntegrityError) as error:
                # Validation happens before inserts, except the final consistency assertion: that assertion must rollback.
                if isinstance(error, MemoryIntegrityError):
                    raise
                return self._deny("write", context, now, str(error), entry_id=request.entry_id)

    def get(self, entry_id: str, *, context: Context, now: datetime) -> Result:
        aware(now)
        with self._transaction():
            parents = ()
            try:
                access = next((reader for reader in self.policy.readers if reader.principal == context.principal), None)
                if access is None:
                    raise MemoryDeniedError("reader_not_allowed")
                entry, content, ancestors = self._load(entry_id)
                parents = (entry.state_event_id,)
                if any(item.expires_at <= now for item in [entry, *ancestors]):
                    raise MemoryDeniedError("expired")
                if any(item.state == "quarantined" for item in [entry, *ancestors]):
                    raise MemoryDeniedError("quarantined")
                if not entry.labels.readable_by(context.principal) or not entry.labels.flows_to(access.clearance):
                    raise MemoryDeniedError("reader_or_clearance_denied")
                self._event(
                    "read",
                    context,
                    now,
                    entry_id=entry_id,
                    label=entry.labels,
                    parents=(entry.state_event_id,),
                    content_ref=entry.content_ref,
                )
                return Result(status="RETURNED", entry=entry, content=content)
            except (MemoryDeniedError, MemoryIntegrityError) as error:
                reason = "corrupt_record" if isinstance(error, MemoryIntegrityError) else str(error)
                return self._deny("read", context, now, reason, entry_id=entry_id, parents=parents)

    def describe(self, entry_id: str, *, context: Context, now: datetime) -> Result:
        """Host operator metadata only, including quarantined/expired entries; never content."""
        aware(now)
        with self._transaction():
            try:
                if context.principal not in self.policy.operators:
                    raise MemoryDeniedError("operator_not_allowed")
                entry, _, _ = self._load(entry_id)
                self._event(
                    "describe", context, now, entry_id=entry_id, label=entry.labels, parents=(entry.state_event_id,)
                )
                return Result(status="DESCRIBED", entry=entry)
            except (MemoryDeniedError, MemoryIntegrityError) as error:
                return self._deny(
                    "describe",
                    context,
                    now,
                    "corrupt_record" if isinstance(error, MemoryIntegrityError) else str(error),
                    entry_id=entry_id,
                )

    def quarantine(self, entry_id: str, *, context: Context, now: datetime) -> Result:
        aware(now)
        with self._transaction():
            try:
                if context.principal not in self.policy.operators:
                    raise MemoryDeniedError("operator_not_allowed")
                entry, _, _ = self._load(entry_id)
                if entry.state == "quarantined":
                    raise MemoryDeniedError("already_quarantined")
                event_id = self._event(
                    "quarantine", context, now, entry_id=entry_id, label=entry.labels, parents=(entry.state_event_id,)
                )
                entry = entry.model_copy(update={"state": "quarantined", "state_event_id": event_id})
                value = encoded(entry)
                self._conn.execute(
                    "UPDATE memory_entries SET value=?,seal=? WHERE id=?",
                    (value, self._seal("entry:" + entry_id, value), entry_id),
                )
                return Result(status="QUARANTINED", entry=entry)
            except (MemoryDeniedError, MemoryIntegrityError) as error:
                return self._deny(
                    "quarantine",
                    context,
                    now,
                    "corrupt_record" if isinstance(error, MemoryIntegrityError) else str(error),
                    entry_id=entry_id,
                )

    def search(self, *, context: Context, now: datetime, limit: int = 20) -> tuple[Result, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("search_limit")
        ids = [row[0] for row in self._conn.execute("SELECT id FROM memory_entries ORDER BY id")]
        returned = []
        for entry_id in ids:
            result = self.get(entry_id, context=context, now=now)
            if result.status == "RETURNED":
                returned.append(result)
                if len(returned) == limit:
                    break
        return tuple(returned)

    def _checked_event(self, event_id):
        row = self._conn.execute("SELECT seq,value,seal FROM memory_events WHERE id=?", (event_id,)).fetchone()
        if row is None or not self._matches(row[2], "event:" + event_id, row[1]):
            raise MemoryIntegrityError("outbox_missing_or_seal_mismatch")
        seq, value, _ = row
        try:
            item = json.loads(value)
            event = CanonicalEvent.model_validate_json(encoded(item["event"]))
            if (
                set(item) != {"sequence", "event", "payload"}
                or type(item["sequence"]) is not int
                or item["sequence"] != seq
                or event.event_id != event_id
            ):
                raise MemoryIntegrityError("outbox_sequence_or_identity_changed")
            return event, item["payload"]
        except (ValueError, KeyError, TypeError, ValidationError):
            raise MemoryIntegrityError("outbox_record_invalid") from None

    def events(self):
        ids = [row[0] for row in self._conn.execute("SELECT id FROM memory_events ORDER BY seq")]
        return tuple(self._checked_event(event_id) for event_id in ids)

    def export_events(self, audit: AuditStore) -> int:
        """Idempotent outbox copy; not an atomic transaction across the two databases."""
        existing = {event.event_id: event for event in audit.events()}
        appended = 0
        for event, payload in self.events():
            if event.event_id in existing:
                if existing[event.event_id] != event or audit.payload_of(event.event_id) != payload:
                    raise MemoryIntegrityError("audit_event_collision")
                continue
            audit.append(event, payload=payload)
            appended += 1
        return appended
