"""Local MCP fixture: an upstream file tool or an isolated downstream gateway.

Used only by module B's real protocol tests. Every file is inside the pytest
temporary directory and no inherited API credentials are needed.
"""

import asyncio
import os
import sys
from pathlib import Path

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount

from camel.audit import AuditStore, SQLiteTicketStore
from camel.gateway import CallContext, MCPSecurityGateway, connect_stdio, serve_stdio, stdio_identity
from camel.normalization import EffectNormalizer, NormalizationContext, ToolBinding
from camel.policy import PolicyEngine, load_rules


def upstream(root: Path) -> Server:
    server = Server("module-b-test-upstream", version="1")

    @server.list_tools()
    async def tools():
        return [
            types.Tool(
                name="read",
                description=(root / "description").read_text() if (root / "description").exists() else "Read a file",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            )
        ]

    @server.call_tool()
    async def call(name, arguments):
        if name != "read":
            raise ValueError("unknown fixture tool")
        path = Path(arguments["path"]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("fixture boundary")
        with (root / "calls").open("a") as log:
            log.write("called\n")
        return [types.TextContent(type="text", text=path.read_text())]

    return server


async def run_stdio(root: Path, mode: str) -> None:
    if mode == "upstream":
        server = upstream(root)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
        return
    context = CallContext(
        subject="user:test",
        trace_id="stdio",
        session_id="stdio",
        normalization=NormalizationContext(workspace=root, cwd=root),
    )
    coverage_env = {key: value for key, value in os.environ.items() if key.startswith("COV_CORE_")}
    args = (str(Path(__file__).resolve()), str(root), "upstream")
    approved = stdio_identity(sys.executable, args, coverage_env)
    async with connect_stdio(sys.executable, args, expected_identity=approved, env=coverage_env) as transport:
        manifest = await transport.snapshot()
        gateway = MCPSecurityGateway(
            engine=PolicyEngine(load_rules("id: allow\nwhen: {}\nthen: ALLOW")),
            normalizer=EffectNormalizer(),
            audit=AuditStore(root / "audit.db"),
            signing_key=b"fixture-signing-key",
            ticket_store=SQLiteTicketStore(root / "tickets.db"),
        )
        await gateway.register(
            "files",
            transport,
            expected_identity=manifest.identity,
            expected_digest=manifest.digest,
            bindings={"read": ToolBinding(adapter="fs", operation="read")},
            context=context,
        )
        await serve_stdio(gateway, context)


def http_app(root: Path) -> Starlette:
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    manager = StreamableHTTPSessionManager(upstream(root), json_response=True, stateless=True)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    return Starlette(routes=[Mount("/mcp", app=manager.handle_request)], lifespan=lifespan)


if __name__ == "__main__":
    if "COV_CORE_SOURCE" in os.environ:
        from pytest_cov.embed import cleanup_on_sigterm

        cleanup_on_sigterm()
    root, mode = Path(sys.argv[1]).resolve(), sys.argv[2]
    if mode == "http":
        import uvicorn

        uvicorn.run(http_app(root), host="127.0.0.1", port=int(sys.argv[3]), log_level="error")
    else:
        asyncio.run(run_stdio(root, mode))
