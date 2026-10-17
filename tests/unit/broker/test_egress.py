"""Broker EGRESS execution: pinned IP, credential injection, fail-closed boundary."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretBytes

from camel.audit import AuditStore
from camel.broker import EgressError, ExecutionBroker, KeyVault, SandboxProfile, SandboxViolationError
from camel.broker.credentials import InjectedCredential
from camel.core.effect import CanonicalEffect, EffectType
from camel.normalization import NetworkPolicy
from camel.policy.ticket import InMemoryTicketStore, issue_ticket

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(minutes=5)
KEY = b"test-signing-key"
MASTER = b"test-master-key"
PUBLIC_IP = "93.184.216.34"
STUB_RESOLVER = lambda host, port: (PUBLIC_IP,)


class FakeTransport(httpx.BaseTransport):
    """Records forwarded requests; replies with a canned status/body."""

    def __init__(self, handler):
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self._handler(request)
        return httpx.Response(status, content=body, request=request)


def _egress_effect(operation: str = "http_get", destination: str = "https://example.com/data") -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_egress",
        type=EffectType.EGRESS,
        operation=operation,
        destination=destination,
    )


@pytest.fixture()
def env(tmp_path: Path):
    transport = FakeTransport(lambda request: (200, b"payload"))
    audit = AuditStore(":memory:")
    tickets = InMemoryTicketStore()
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(tmp_path / "ws", tmp_path / "scratch"),
        ticket_store=tickets,
        audit=audit,
        now_fn=lambda: NOW,
        vault=KeyVault(MASTER),
        network=NetworkPolicy(allowed_hosts=frozenset({"example.com"}), allowed_networks=("127.0.0.0/8",)),
        resolver=STUB_RESOLVER,
        transport=transport,
        timeout=5.0,
    )
    return SimpleNamespace(broker=broker, audit=audit, tickets=tickets, transport=transport)


def _issue(effect: CanonicalEffect, subject: str = "user:alice"):
    return issue_ticket(KEY, subject=subject, effect=effect, expires_at=LATER)


def _run(env, effect, **overrides):
    ticket = _issue(effect)
    return env.broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1", **overrides)


def _executions(env, trace: str = "t1"):
    return [e for e in env.audit.events(trace) if e.source == "execution"]


def _outcomes(env):
    return [(env.audit.payload_of(e.event_id) or {})["outcome"] for e in _executions(env)]


def test_allowlisted_get_executes_pinned_with_bearer_credential(env) -> None:
    effect = _egress_effect()
    ticket = _issue(effect)
    result = env.broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")
    assert result.output == b"payload"
    request = env.transport.requests[0]
    assert request.url.host == PUBLIC_IP  # connect to the approved IP literal
    assert request.headers["host"] == "example.com"  # original authority preserved
    assert request.extensions["sni_hostname"] == "example.com"
    expected = (
        KeyVault(MASTER)
        .derive(subject="user:alice", ticket_id=ticket.ticket_id, expires_at=LATER)
        .secret.get_secret_value()
        .hex()
    )
    assert request.headers["authorization"] == f"Bearer {expected}"
    assert _outcomes(env) == ["executed"]
    payload = env.audit.payload_of(_executions(env)[0].event_id)
    assert payload is not None
    assert payload["credential_handle"].startswith("cred_")
    assert expected not in str(payload)  # the secret never reaches the audit trail
    env.audit.verify_chain()


def test_post_body_passthrough(env) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request):
        request.read()
        seen["body"] = request.content
        return 200, b"ok"

    env.transport._handler = handler
    effect = _egress_effect(operation="http_post", destination="https://example.com/submit")
    result = _run(env, effect, content=b'{"answer": 42}')
    assert result.output == b"ok"
    assert seen["body"] == b'{"answer": 42}'


def test_non_allowlisted_host_rejected_before_ticket_burn(env) -> None:
    effect = _egress_effect(destination="https://evil.example.org/data")
    ticket = _issue(effect)
    with pytest.raises(SandboxViolationError, match="egress_not_allowlisted"):
        env.broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")
    assert env.tickets.uses(ticket.ticket_id) == 0  # static rejection burns no ticket use
    assert _outcomes(env) == ["rejected"]
    assert not env.transport.requests


def test_private_address_rejected_before_ticket_burn(env) -> None:
    effect = _egress_effect(destination="https://example.com/data")
    ticket = _issue(effect)
    broker = env.broker
    broker._egress._resolver = lambda host, port: ("10.0.0.5",)
    with pytest.raises(SandboxViolationError, match="private_network_address"):
        broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")
    assert env.tickets.uses(ticket.ticket_id) == 0
    assert _outcomes(env) == ["rejected"]


def test_dns_rebinding_rejected_as_failed(tmp_path: Path) -> None:
    class FlipResolver:
        def __init__(self) -> None:
            self.answers: tuple[str, ...] = (PUBLIC_IP,)

        def __call__(self, host, port):
            return self.answers

    resolver = FlipResolver()
    audit = AuditStore(":memory:")
    transport = FakeTransport(lambda request: (200, b"payload"))
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(tmp_path / "ws", tmp_path / "scratch"),
        ticket_store=InMemoryTicketStore(),
        audit=audit,
        now_fn=lambda: NOW,
        network=NetworkPolicy(allowed_hosts=frozenset({"example.com"})),
        resolver=resolver,
        transport=transport,
    )
    first = _egress_effect()
    broker.execute(first, _issue(first), subject="user:alice", trace_id="t1", session_id="s1")
    resolver.answers = ("93.184.216.35",)  # the answer changes between requests
    second = _egress_effect().model_copy(update={"effect_id": "fx_egress2"})
    with pytest.raises(EgressError, match="dns_rebinding"):
        broker.execute(second, _issue(second), subject="user:alice", trace_id="t1", session_id="s1")
    outcomes = [(audit.payload_of(e.event_id) or {})["outcome"] for e in audit.events("t1") if e.source == "execution"]
    assert outcomes == ["executed", "failed"]


def test_redirect_rejected_as_failed(env) -> None:
    env.transport._handler = lambda request: (302, b"")
    with pytest.raises(EgressError, match="redirect"):
        _run(env, _egress_effect())
    assert _outcomes(env) == ["failed"]


def test_oversized_response_rejected_as_failed(env) -> None:
    env.transport._handler = lambda request: (200, b"x" * 64)
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(Path("/tmp"), Path("/tmp")),
        ticket_store=env.tickets,
        audit=env.audit,
        now_fn=lambda: NOW,
        network=NetworkPolicy(allowed_hosts=frozenset({"example.com"})),
        resolver=STUB_RESOLVER,
        transport=env.transport,
        max_response_bytes=16,
    )
    effect = _egress_effect()
    ticket = _issue(effect)
    with pytest.raises(EgressError, match="response_size_limit"):
        broker.execute(effect, ticket, subject="user:alice", trace_id="t1", session_id="s1")
    assert _outcomes(env) == ["failed"]


def test_egress_without_network_policy_fails_closed(tmp_path: Path) -> None:
    audit = AuditStore(":memory:")
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(tmp_path / "ws", tmp_path / "scratch"),
        ticket_store=InMemoryTicketStore(),
        audit=audit,
        now_fn=lambda: NOW,
    )
    effect = _egress_effect()
    from camel.broker import UnsupportedEffectError

    with pytest.raises(UnsupportedEffectError, match="NetworkPolicy"):
        broker.execute(effect, _issue(effect), subject="user:alice", trace_id="t1", session_id="s1")
    assert [(audit.payload_of(e.event_id) or {})["outcome"] for e in audit.events("t1") if e.source == "execution"] == [
        "rejected"
    ]


def test_non_http_operation_rejected(env) -> None:
    with pytest.raises(Exception, match="unsupported EGRESS operation"):
        _run(env, _egress_effect(operation="send"))


def test_missing_destination_rejected(env) -> None:
    effect = CanonicalEffect(effect_id="fx_egress", type=EffectType.EGRESS, operation="http_get")
    with pytest.raises(SandboxViolationError, match="without a destination"):
        _run(env, effect)


def test_credential_never_serialized() -> None:
    secret = KeyVault(MASTER).derive(subject="user:alice", ticket_id="t1", expires_at=LATER).secret.get_secret_value()
    credential = InjectedCredential(
        handle="cred_x", secret=SecretBytes(secret), subject="user:alice", ticket_id="t1", expires_at=LATER
    )
    assert secret.hex() not in repr(credential)
