"""Provenance queries: causal DAGs and timeline reports from the audit store.

Edges come from two sources (arch.md §6.10):

- ``parent_ids``: explicit event causality recorded by the producer;
- ``derived_from`` on the effect stored in decision/execution payloads:
  which earlier events the executed effect was derived from.

The report contains only metadata and non-secret payload fields (decisions,
reasons, policy versions, ticket ids, outcomes) — never raw payloads.
"""

from pydantic import BaseModel, ConfigDict

from camel.audit.store import AuditStore
from camel.core.events import CanonicalEvent


class ProvenanceDag(BaseModel):
    """A causal DAG over the events of one trace."""

    model_config = ConfigDict(frozen=True)

    nodes: tuple[CanonicalEvent, ...] = ()
    edges: tuple[tuple[str, str], ...] = ()


class ProvenanceService:
    """Read-only provenance views over an :class:`AuditStore`."""

    def __init__(self, store: AuditStore) -> None:
        self._store = store

    def timeline(self, trace_id: str) -> list[CanonicalEvent]:
        """Return all events of ``trace_id`` in append order."""
        return self._store.events(trace_id)

    def dag(self, trace_id: str) -> ProvenanceDag:
        """Rebuild the causal DAG of ``trace_id``.

        Only edges whose both endpoints are in the trace are kept; cross-trace
        references remain visible through each event's ``parent_ids``.
        """
        events = self._store.events(trace_id)
        ids = {event.event_id for event in events}
        edges: set[tuple[str, str]] = set()
        for event in events:
            edges.update((parent, event.event_id) for parent in event.parent_ids if parent in ids)
            payload = self._store.payload_of(event.event_id)
            if payload and "effect" in payload:
                edges.update(
                    (parent, event.event_id) for parent in payload["effect"].get("derived_from", ()) if parent in ids
                )
        return ProvenanceDag(nodes=tuple(events), edges=tuple(sorted(edges)))

    def report(self, trace_id: str) -> str:
        """Render a markdown timeline report for ``trace_id`` (secret-free)."""
        lines = [f"# Provenance report — trace {trace_id}", ""]
        for event in self.timeline(trace_id):
            lines.append(
                f"- {event.timestamp.isoformat()} **{event.source}** by `{event.principal}` (event `{event.event_id}`)"
            )
            payload = self._store.payload_of(event.event_id)
            if payload is None:
                continue
            if "decision" in payload:
                decision = payload["decision"]
                lines.append(
                    f"  - decision `{decision['decision']}` — policy `{decision['policy_version']}`,"
                    f" hard_reasons={list(decision['hard_reasons'])},"
                    f" confirm_reasons={list(decision['confirm_reasons'])}"
                )
            if "ticket_id" in payload:
                lines.append(f"  - ticket `{payload['ticket_id']}` → {payload['outcome']}")
        return "\n".join(lines)
