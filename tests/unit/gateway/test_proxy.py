"""Real MCP JSON-RPC over ASGI HTTP with authenticated per-request contexts."""

import json

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Message

from camel.gateway import streamable_http_app
from tests.unit.gateway.conftest import register

pytestmark = pytest.mark.anyio


def app_for(env):
    async def authenticate(request: Request):
        if request.headers.get("authorization") == "Bearer alice":
            return env.context
        if request.headers.get("authorization") == "Bearer bob":
            return env.context.model_copy(update={"subject": "user:bob", "session_id": "bob"})
        return None

    return streamable_http_app(env.gateway, authenticate=authenticate, allowed_hosts=frozenset({"testserver"}))


async def rpc(client, method: str, params=None, **kw):
    return await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, **kw)


async def test_http_auth_host_origin_and_frame_limits(env) -> None:
    app = app_for(env)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            assert (await rpc(client, "tools/list")).status_code == 401
            assert (await rpc(client, "tools/list", headers={"host": "evil.invalid"})).status_code == 421
            assert (await rpc(client, "tools/list", headers={"origin": "https://evil.invalid"})).status_code == 403
            response = await client.post("/mcp", content="x" * 524289, headers={"authorization": "Bearer alice"})
            assert response.status_code == 413
    assert not env.transport.calls


async def test_http_list_call_denial_and_identity_isolation(env) -> None:
    await register(env)
    app = app_for(env)
    headers = {"authorization": "Bearer alice", "accept": "application/json, text/event-stream"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver", headers=headers
        ) as client:
            initialized = await rpc(
                client,
                "initialize",
                {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
            )
            assert initialized.status_code == 200
            response = await rpc(client, "tools/list")
            assert response.json()["result"]["tools"][0]["name"] == "files__read"
            response = await rpc(client, "tools/call", {"name": "files__read", "arguments": {"path": "note"}})
            envelope = json.loads(response.json()["result"]["content"][0]["text"])
            assert envelope["server_id"] == "files" and envelope["payload"]["content"][0]["text"] == "hello"
            response = await rpc(client, "tools/call", {"name": "read", "arguments": {"path": "note"}})
            assert response.json()["result"]["isError"]
            response = await rpc(client, "tools/call", {"name": "files__read", "arguments": {"path": "../escape"}})
            assert response.json()["result"]["isError"]
            response = await rpc(
                client,
                "tools/call",
                {"name": "files__read", "arguments": {"path": "note"}},
                headers={"authorization": "Bearer bob"},
            )
            assert not response.json()["result"]["isError"]
            assert env.audit.events()[-1].principal == "user:bob"
            # The Agent has no MCP method for registration, approval or raw upstream calls.
            response = await rpc(client, "tools/call", {"name": "gateway__approve", "arguments": {}})
            assert response.json()["result"]["isError"]
            assert (await client.get("/mcp")).status_code in {400, 405}
    assert len(env.transport.calls) == 2


async def test_http_confirmation_reports_pending_without_executing(env) -> None:
    from camel.policy import PolicyEngine, load_rules

    env.gateway._engine = PolicyEngine(load_rules("id: confirm\nthen: CONFIRM"))
    await register(env)
    app = app_for(env)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            headers={"authorization": "Bearer alice", "accept": "application/json, text/event-stream"},
        ) as client:
            response = await rpc(client, "tools/call", {"name": "files__read", "arguments": {"path": "note"}})
            result = response.json()["result"]
            assert result["isError"]
            assert json.loads(result["content"][0]["text"])["status"] == "confirmation_required"
    assert not env.transport.calls


async def test_http_requires_explicit_host_allowlist(env) -> None:
    async def authenticate(request):
        return env.context

    with pytest.raises(ValueError):
        streamable_http_app(env.gateway, authenticate=authenticate, allowed_hosts=frozenset())


async def test_buffered_http_frame_is_delivered_once_and_disconnect_preserved(env, monkeypatch) -> None:
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    seen = []

    async def handle(self, scope, receive, send):
        seen.append(await receive())
        seen.append(await receive())
        await Response(status_code=204)(scope, receive, send)

    monkeypatch.setattr(StreamableHTTPSessionManager, "handle_request", handle)
    messages: list[Message] = [
        {"type": "http.request", "body": b'{"part":', "more_body": True},
        {"type": "http.request", "body": b"1}", "more_body": False},
        {"type": "http.disconnect"},
    ]

    async def receive():
        return messages.pop(0)

    sent = []

    async def send(message):
        sent.append(message)

    app = app_for(env)
    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "scheme": "http",
            "method": "POST",
            "path": "/mcp",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"testserver"), (b"authorization", b"Bearer alice")],
        },
        receive,
        send,
    )
    assert seen == [{"type": "http.request", "body": b'{"part":1}', "more_body": False}, {"type": "http.disconnect"}]
    assert sent[0]["status"] == 204 and not env.transport.calls
