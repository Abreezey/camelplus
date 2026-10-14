"""KeyVault: ticket-bound short-lived credential derivation (arch.md §6.9)."""

from datetime import datetime, timedelta, timezone

from camel.broker.credentials import InjectedCredential, KeyVault

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(minutes=5)


def test_derive_deterministic_and_bound() -> None:
    vault = KeyVault(b"master")
    a = vault.derive(subject="user:alice", ticket_id="tk_1", expires_at=LATER)
    b = vault.derive(subject="user:alice", ticket_id="tk_1", expires_at=LATER)
    assert a == b  # idempotent derivation, no storage needed
    assert a.handle.startswith("cred_")

    # bound to subject, ticket, master key and expiry — change any, change the secret
    assert vault.derive(subject="user:bob", ticket_id="tk_1", expires_at=LATER).secret != a.secret
    assert vault.derive(subject="user:alice", ticket_id="tk_2", expires_at=LATER).secret != a.secret
    assert vault.derive(subject="user:alice", ticket_id="tk_1", expires_at=NOW).secret != a.secret
    assert KeyVault(b"other").derive(subject="user:alice", ticket_id="tk_1", expires_at=LATER).secret != a.secret


def test_secret_never_serialized() -> None:
    cred = KeyVault(b"master").derive(subject="user:alice", ticket_id="tk_1", expires_at=LATER)
    assert "**********" in str(cred.secret)
    assert cred.secret.get_secret_value().hex() not in repr(cred)
    assert cred.secret.get_secret_value().hex() not in cred.model_dump_json()


def test_expiry() -> None:
    cred = KeyVault(b"master").derive(subject="user:alice", ticket_id="tk_1", expires_at=LATER)
    assert not cred.is_expired(NOW)
    assert cred.is_expired(LATER)
    assert isinstance(cred, InjectedCredential)
