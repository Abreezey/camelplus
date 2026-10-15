"""Actual stdio process and Streamable HTTP MCP gateway roundtrips.

Upstream calls are made only by MCPSecurityGateway. The downstream client has
no server-registration, raw-call or user-approval method.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from camel.audit import AuditStore
from camel.gateway import CallContext, GatewayError, MCPSecurityGateway, connect_http
from camel.normalization import EffectNormalizer, NetworkPolicy, NormalizationContext, ToolBinding
from camel.policy import PolicyEngine, load_rules
from camel.policy.ticket import InMemoryTicketStore

FIXTURE = Path(__file__).parents[1] / "fixtures" / "module_b_mcp_server.py"
pytestmark = pytest.mark.anyio


@pytest.fixture()
def anyio_backend():
    return "asyncio"


async def test_stdio_agent_gateway_upstream_and_manifest_rug_pull(tmp_path: Path) -> None:
    (tmp_path / "note").write_text("stdio hello")
    coverage_env = {key: value for key, value in os.environ.items() if key.startswith("COV_CORE_")}
    params = StdioServerParameters(
        command=sys.executable, args=[str(FIXTURE), str(tmp_path), "gateway"], env=coverage_env
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=5)) as client:
            await client.initialize()
            tools = await client.list_tools()
            assert [tool.name for tool in tools.tools] == ["files__read"]
            result = await client.call_tool("files__read", {"path": "note"})
            assert not result.isError
            text = result.content[0]
            assert text.type == "text"
            envelope = json.loads(text.text)
            assert envelope["payload"]["content"][0]["text"] == "stdio hello"
            assert envelope["labels"]["integrity"] == "untrusted"
            for name, arguments in [
                ("read", {"path": "note"}),
                ("files__read", {"path": "../escape"}),
                ("gateway__approve", {}),
            ]:
                assert (await client.call_tool(name, arguments)).isError
            (tmp_path / "description").write_text("changed tool instructions")
            assert (await client.call_tool("files__read", {"path": "note"})).isError
            assert (await client.list_tools()).tools == []
    assert (tmp_path / "calls").read_text().splitlines() == ["called"]
    audit = AuditStore(tmp_path / "audit.db")
    assert "tool_manifest_changed" in [event.source for event in audit.events()]
    audit.verify_chain()
    audit.close()


async def test_http_upstream_uses_pinned_network_transport_and_gateway(tmp_path: Path) -> None:
    (tmp_path / "note").write_text("http hello")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        [sys.executable, str(FIXTURE), str(tmp_path), "http", str(port)],
        env={
            "PATH": "/usr/bin:/bin",
            **{key: value for key, value in os.environ.items() if key.startswith("COV_CORE_")},
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        ready = False
        for _ in range(100):
            if process.poll() is not None:
                raise AssertionError(process.stderr.read().decode() if process.stderr else "fixture stopped")
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                ready = True
                break
            except OSError:
                await asyncio.sleep(0.05)
        assert ready, "local HTTP fixture did not start"
        policy = NetworkPolicy(
            allowed_hosts=frozenset({"127.0.0.1"}), allowed_ports=frozenset({port}), allowed_networks=("127.0.0.0/8",)
        )
        async with connect_http(f"http://127.0.0.1:{port}/mcp/", policy) as transport:
            manifest = await transport.snapshot()
            context = CallContext(
                subject="user:test",
                trace_id="http",
                session_id="http",
                normalization=NormalizationContext(workspace=tmp_path, cwd=tmp_path),
            )
            gateway = MCPSecurityGateway(
                engine=PolicyEngine(load_rules("id: allow\nthen: ALLOW")),
                normalizer=EffectNormalizer(),
                audit=AuditStore(":memory:"),
                signing_key=b"test-key",
                ticket_store=InMemoryTicketStore(),
            )
            await gateway.register(
                "files",
                transport,
                expected_identity=manifest.identity,
                expected_digest=manifest.digest,
                bindings={"read": ToolBinding(adapter="fs", operation="read")},
                context=context,
            )
            result = await gateway.call_tool("files", "read", {"path": "note"}, context=context)
            assert result.output is not None and result.output.payload["content"][0]["text"] == "http hello"
            (tmp_path / "description").write_text("rug pull")
            with pytest.raises(GatewayError, match="manifest_changed"):
                await gateway.call_tool("files", "read", {"path": "note"}, context=context)
        assert (tmp_path / "calls").read_text().splitlines() == ["called"]
    finally:
        process.terminate()
        await asyncio.to_thread(process.wait, 5)
        if process.stderr:
            process.stderr.close()
