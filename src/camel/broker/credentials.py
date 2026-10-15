"""Ticket-bound short-lived credential injection (arch.md §6.9).

The agent process never holds long-term keys. The ``KeyVault`` lives in the
TCB (broker process) and holds the master key; it *derives* a short-lived
credential per verified ticket. The derivation is HMAC-based and stateless:

- ``handle = "cred_" + sha256(master_key | ticket_id)[:16]`` — the opaque
  reference that may appear in results and audit events;
- ``secret = HMAC-SHA256(master_key, subject | ticket_id | expires_at)`` —
  the actual credential, only ever handed to the execution layer, bound to
  one subject, one ticket and one expiry.

Because derivation is deterministic, no credential store is needed; because
the secret folds in ``expires_at`` and the ticket is single-use (I5), the
credential dies with its ticket. The master key never leaves the vault:
only derived secrets are injected, and :class:`InjectedCredential` keeps the
secret as a pydantic ``SecretBytes`` so repr/serialization cannot leak it.
"""

import hashlib
import hmac
from datetime import datetime

from pydantic import BaseModel, ConfigDict, SecretBytes, field_validator


class InjectedCredential(BaseModel):
    """One short-lived credential derived for a verified ticket."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    handle: str
    secret: SecretBytes
    subject: str
    ticket_id: str
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def _expires_at_must_be_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return v

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


class KeyVault:
    """Derives ticket-bound short-lived credentials from a TCB-held master key."""

    def __init__(self, master_key: bytes) -> None:
        self._master_key = master_key

    def derive(self, *, subject: str, ticket_id: str, expires_at: datetime) -> InjectedCredential:
        handle = "cred_" + hashlib.sha256(self._master_key + b"|" + ticket_id.encode()).hexdigest()[:16]
        secret = hmac.new(
            self._master_key, f"{subject}|{ticket_id}|{expires_at.isoformat()}".encode(), hashlib.sha256
        ).digest()
        return InjectedCredential(
            handle=handle, secret=SecretBytes(secret), subject=subject, ticket_id=ticket_id, expires_at=expires_at
        )
