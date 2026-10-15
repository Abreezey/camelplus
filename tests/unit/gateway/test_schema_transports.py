"""Schema resource limits and actual-address pinning at the HTTP boundary."""

import sys
from pathlib import Path

import httpx
import pytest
from mcp import types

from camel.gateway import GatewayError, PinnedHTTPTransport, SessionTransport, connect_http
from camel.gateway.schema import bounded_json, validate_arguments, validate_schema
from camel.gateway.transports import stdio_identity
from camel.normalization import NetworkPolicy, NormalizationError

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "string"},
        {"type": "object", "properties": {"x": {"type": "invalid"}}},
        {"type": "object", "$ref": "https://example.com/a"},
        {"type": "object", "$dynamicRef": "file:///tmp/a"},
        {"type": "object", "$id": "https://example.com/"},
    ],
)
async def test_bad_or_external_schemas(schema: dict) -> None:
    with pytest.raises(GatewayError):
        validate_schema(schema)


async def test_local_refs_work_without_io() -> None:
    schema = {"type": "object", "$defs": {"text": {"type": "string"}}, "properties": {"x": {"$ref": "#/$defs/text"}}}
    validate_schema(schema)
    validate_arguments({"x": "okay"}, schema)
    with pytest.raises(GatewayError):
        validate_arguments({"x": 1}, schema)
    with pytest.raises(GatewayError):
        validate_arguments({"x": 1}, {"type": "object", "properties": {"x": {"$ref": "#/$defs/missing"}}})


@pytest.mark.parametrize("value", [{1: "value"}, {"x": object()}, {"x": float("nan")}, {"x": float("inf")}])
async def test_non_json_arguments_fail(value) -> None:
    with pytest.raises(GatewayError):
        bounded_json(value)


async def test_json_size_depth_and_cycles() -> None:
    with pytest.raises(GatewayError):
        bounded_json("long", max_bytes=1)
    with pytest.raises(GatewayError):
        bounded_json({"a": {"b": 1}}, max_depth=1)
    cycle = []
    cycle.append(cycle)
    with pytest.raises(GatewayError):
        bounded_json(cycle)
    assert bounded_json((None, True, 1, 1.5)) == b"[null,true,1,1.5]"


async def test_http_connects_to_validated_ip_with_original_host_and_sni() -> None:
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    policy = NetworkPolicy(allowed_hosts=frozenset({"example.com"}))
    transport = PinnedHTTPTransport(
        policy, resolver=lambda *_: ("93.184.216.34",), transport=httpx.MockTransport(handler)
    )
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("https://example.com/path", content=b"body", headers={"host": "attacker.invalid"})
        assert response.status_code == 200
    assert seen[0].url.host == "93.184.216.34"
    assert seen[0].headers["host"] == "example.com"
    assert seen[0].extensions["sni_hostname"] == "example.com"
    assert seen[0].content == b"body"


async def test_http_private_dns_and_rebinding_never_connect() -> None:
    answers = ["93.184.216.34"]
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200)

    transport = PinnedHTTPTransport(
        NetworkPolicy(allowed_hosts=frozenset({"example.com"})),
        resolver=lambda *_: tuple(answers),
        transport=httpx.MockTransport(handler),
    )
    async with httpx.AsyncClient(transport=transport) as client:
        await client.get("https://example.com/")
        answers[:] = ["8.8.8.8"]
        with pytest.raises(GatewayError, match="dns_rebinding"):
            await client.get("https://example.com/")
        answers[:] = ["127.0.0.1"]
        with pytest.raises(NormalizationError):
            await client.get("https://example.com/")
    assert len(calls) == 1


async def test_http_redirect_not_followed_even_if_client_requests_it() -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    transport = PinnedHTTPTransport(
        NetworkPolicy(allowed_hosts=frozenset({"example.com"})),
        resolver=lambda *_: ("93.184.216.34",),
        transport=httpx.MockTransport(handler),
    )
    async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
        with pytest.raises(GatewayError, match="redirect"):
            await client.get("https://example.com/")
    assert len(calls) == 1


async def test_stdio_identity_binds_executable_arguments_scripts_and_env(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    script.write_text("print(1)")
    original = stdio_identity(sys.executable, (str(script),), {})
    assert original != stdio_identity(sys.executable, (str(script), "changed"), {})
    assert original != stdio_identity(sys.executable, (str(script),), {"ENV": "changed"})
    script.write_text("print(2)")
    assert original != stdio_identity(sys.executable, (str(script),), {})
    with pytest.raises(GatewayError):
        stdio_identity("python", (), {})


async def test_http_endpoint_requires_the_exact_canonical_pin() -> None:
    with pytest.raises(GatewayError, match="canonical"):
        async with connect_http(
            "https://EXAMPLE.com",
            NetworkPolicy(allowed_hosts=frozenset({"example.com"})),
            resolver=lambda *_: ("8.8.8.8",),
        ):
            pytest.fail("noncanonical endpoint connected")


async def test_session_pagination_and_result_serialization() -> None:
    class Session:
        async def list_tools(self, cursor=None):
            return types.ListToolsResult(
                tools=[types.Tool(name="b" if cursor else "a", inputSchema={"type": "object"})],
                nextCursor=None if cursor else "page2",
            )

        async def call_tool(self, name, arguments):
            return types.CallToolResult(content=[types.TextContent(type="text", text="hello")])

    transport = SessionTransport(Session(), "endpoint", {"name": "test"})  # type: ignore[arg-type]
    manifest = await transport.snapshot()
    assert [t.name for t in manifest.tools] == ["a", "b"]
    assert manifest.identity == transport.identity
    assert (await transport.call_tool("a", {}))["content"][0]["text"] == "hello"


@pytest.mark.parametrize("mode", ["loop", "pages", "tools"])
async def test_session_manifest_budgets(mode: str) -> None:
    class Session:
        count = 0

        async def list_tools(self, cursor=None):
            self.count += 1
            tools = [types.Tool(name="tool", inputSchema={"type": "object"})] * (513 if mode == "tools" else 1)
            return types.ListToolsResult(tools=tools, nextCursor="loop" if mode == "loop" else str(self.count))

    transport = SessionTransport(Session(), "endpoint", {})  # type: ignore[arg-type]
    with pytest.raises(GatewayError):
        await transport.snapshot()
