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
import uuid
from datetime import datetime
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from camel.core.effect import CanonicalEffect


class TicketVerificationError(Exception):
    """Raised when a ticket fails any verification check."""


class CapabilityTicket(BaseModel):
    """A signed, scoped, single-use authorization to execute one effect."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal[1] = 1
    ticket_id: str
    subject: str
    effect_hash: str
    resource: str
    destination: str | None
    expires_at: datetime
    max_uses: int = Field(default=1, ge=1)
    signature: str

    def signed_payload(self) -> bytes:
        """Canonical JSON of every field covered by the signature."""
        return json.dumps(
            self.model_dump(mode="json", exclude={"signature"}),
            sort_keys=True,
        ).encode()


def hash_effect(effect: CanonicalEffect) -> str:
    """Stable hash binding a ticket to the exact effect it authorizes."""
    payload = json.dumps(
        {
            "type": effect.type.value,
            "operation": effect.operation,
            "resources": sorted(effect.resources),
            "destination": effect.destination,
        },
        sort_keys=True,
    )
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
    unsigned = CapabilityTicket.model_construct(
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

    production storage belongs to the audit/execution layer (module C)."""

    def uses(self, ticket_id: str) -> int: ...
    def record_use(self, ticket_id: str) -> int: ...


class InMemoryTicketStore:
    def __init__(self) -> None:
        self._uses: dict[str, int] = {}

    def uses(self, ticket_id: str) -> int:
        return self._uses.get(ticket_id, 0)

    def record_use(self, ticket_id: str) -> int:
        self._uses[ticket_id] = self.uses(ticket_id) + 1
        return self._uses[ticket_id]


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
    if store.uses(ticket.ticket_id) >= ticket.max_uses:
        raise TicketVerificationError("max_uses_exceeded")
    store.record_use(ticket.ticket_id)
