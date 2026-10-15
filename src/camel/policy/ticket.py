"""One-time, non-transferable capability tickets (arch.md §6.5, R17/R22).

A ticket is issued after a user CONFIRMs a decision and authorizes the
Execution Broker (module C) to run exactly one effect:

- bound to ``subject + exact effect hash + resource + destination``;
- expires at ``expires_at``;
- usable at most ``max_uses`` times (default 1), counted by a TicketStore;
- HMAC-signed; any tampering invalidates it.

Verification failure always raises — there is no "soft" failure mode (I5).
"""

import hashlib
import hmac
import json
import threading
import uuid
from datetime import datetime
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from camel.core.effect import CanonicalEffect


class TicketVerificationError(Exception):
    """Raised when a ticket fails any verification check."""


class CapabilityTicket(BaseModel):
    """A signed, scoped, single-use authorization to execute one effect."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    ticket_id: str
    subject: str
    effect_hash: str
    resource: str
    destination: str | None
    expires_at: datetime
    max_uses: int = Field(default=1, ge=1)
    signature: str

    @field_validator("expires_at")
    @classmethod
    def _expires_at_must_be_tz_aware(cls, v: datetime) -> datetime:
        """Naive datetimes would crash expiry comparison with a TypeError
        instead of producing a structured rejection; fail at construction."""
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return v

    def signed_payload(self) -> bytes:
        """Canonical JSON of every field covered by the signature."""
        return json.dumps(
            self.model_dump(mode="json", exclude={"signature"}),
            sort_keys=True,
        ).encode()


def _canonicalize(value: object) -> object:
    """Recursively sort lists so unordered collections (frozensets) hash stably.

    ``model_dump(mode="json")`` serializes frozensets to lists in iteration
    order, which varies with hash randomization across processes; sorting by
    JSON rendering makes the digest reproducible. Both sides of a comparison
    are canonicalized identically, so list order becomes insignificant.
    """
    if isinstance(value, dict):
        return {k: _canonicalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((_canonicalize(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def hash_effect(effect: CanonicalEffect) -> str:
    """Stable hash binding a ticket to the exact effect it authorizes.

    Covers every field of the effect — including data references with their
    trust labels, required capabilities, reversibility and normalization
    confidence — so swapping any security-relevant attribute after the user
    confirmed (e.g. public data replaced with secret data) invalidates the
    ticket (I5).
    """
    payload = json.dumps(_canonicalize(effect.model_dump(mode="json")), sort_keys=True)
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def _sign(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def issue_ticket(
    key: bytes,
    *,
    subject: str,
    effect: CanonicalEffect,
    expires_at: datetime,
    max_uses: int = 1,
    ticket_id: str | None = None,
) -> CapabilityTicket:
    """Issue a signed ticket for ``effect``. ``key`` must be a TCB-held secret."""
    unsigned = CapabilityTicket(
        ticket_id=ticket_id or f"tkt_{uuid.uuid4().hex}",
        subject=subject,
        effect_hash=hash_effect(effect),
        resource=";".join(effect.resources),
        destination=effect.destination,
        expires_at=expires_at,
        max_uses=max_uses,
        signature="",
    )
    signature = _sign(key, unsigned.signed_payload())
    return unsigned.model_copy(update={"signature": signature})


class TicketStore(Protocol):
    """Counts ticket uses. The in-memory implementation below is for v0/tests;

    production storage belongs to the audit/execution layer (module C).

    Consumption MUST be atomic: ``try_consume`` checks the limit and records
    the use as one indivisible operation, otherwise two concurrent verifiers
    could both observe ``uses < max_uses`` and both spend the same ticket.
    """

    def uses(self, ticket_id: str) -> int: ...
    def try_consume(self, ticket_id: str, max_uses: int) -> bool:
        """Atomically record one use iff ``uses(ticket_id) < max_uses``.

        Returns True when the use was recorded, False when the ticket is
        already exhausted. Implementations must guarantee atomicity across
        threads and processes.
        """
        ...


class InMemoryTicketStore:
    def __init__(self) -> None:
        self._uses: dict[str, int] = {}
        self._lock = threading.Lock()

    def uses(self, ticket_id: str) -> int:
        return self._uses.get(ticket_id, 0)

    def try_consume(self, ticket_id: str, max_uses: int) -> bool:
        with self._lock:
            current = self._uses.get(ticket_id, 0)
            if current >= max_uses:
                return False
            self._uses[ticket_id] = current + 1
            return True


def verify_ticket(
    key: bytes,
    ticket: CapabilityTicket,
    effect: CanonicalEffect,
    *,
    subject: str,
    store: TicketStore,
    now: datetime,
) -> None:
    """Verify a ticket against the effect being executed, then consume one use.

    Raises ``TicketVerificationError`` on any mismatch: bad signature, wrong
    subject, different effect, different destination, expiry, or exhausted
    uses. On success exactly one use is recorded.
    """
    expected_signature = _sign(key, ticket.signed_payload())
    if not hmac.compare_digest(expected_signature, ticket.signature):
        raise TicketVerificationError("invalid_signature")
    if ticket.subject != subject:
        raise TicketVerificationError("subject_mismatch")
    if ticket.effect_hash != hash_effect(effect):
        raise TicketVerificationError("effect_mismatch")
    if ticket.destination != effect.destination:
        raise TicketVerificationError("destination_mismatch")
    if now >= ticket.expires_at:
        raise TicketVerificationError("ticket_expired")
    # Atomic check-and-consume: a separate uses() check would race with a
    # concurrent verifier spending the same ticket (I5).
    if not store.try_consume(ticket.ticket_id, ticket.max_uses):
        raise TicketVerificationError("max_uses_exceeded")
