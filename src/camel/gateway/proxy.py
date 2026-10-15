"""Downstream MCP stdio and authenticated Streamable HTTP proxies.

Only discovery and calls are exposed. Server registration, raw upstream sessions
and user approval are absent from the MCP surface. HTTP is stateless so each
request's authenticated context cannot leak into another user's session.
"""

import contextvars
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from camel.gateway.gateway import MCPSecurityGateway
from camel.gateway.models import CallContext, GatewayError


def make_mcp_server(gateway: MCPSecurityGateway, context: Callable[[], CallContext]) -> Server:
    server = Server("camel-security-gateway", version="1")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool.model_validate(tool) for tool in await gateway.list_tools(context=context())]

    async def call_tool(request: types.CallToolRequest) -> types.ServerResult:
        try:
            server_id, separator, tool = request.params.name.partition("__")
            if not separator:
                raise GatewayError("qualified_tool_name_required")
            result = await gateway.call_tool(server_id, tool, request.params.arguments or {}, context=context())
            if result.output is None:
                code = "confirmation_required" if result.confirmation_id else "call_denied"
                payload = {
                    "status": code,
                    "confirmation_id": result.confirmation_id,
                    "confirmation_text": result.confirmation_text,
                }
                return types.ServerResult(
                    types.CallToolResult(
                        content=[types.TextContent(type="text", text=json.dumps(payload))], isError=True
                    )
                )
            # Server-supplied role text remains inside the untrusted payload envelope.
            return types.ServerResult(
                types.CallToolResult(content=[types.TextContent(type="text", text=result.output.model_dump_json())])
            )
        except GatewayError as err:
            return types.ServerResult(
                types.CallToolResult(content=[types.TextContent(type="text", text=str(err))], isError=True)
            )

    server.request_handlers[types.CallToolRequest] = call_tool
    return server


async def serve_stdio(gateway: MCPSecurityGateway, context: CallContext) -> None:
    server = make_mcp_server(gateway, lambda: context)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def streamable_http_app(
    gateway: MCPSecurityGateway,
    *,
    authenticate: Callable[[Request], Awaitable[CallContext | None]],
    allowed_hosts: frozenset[str],
    allowed_origins: frozenset[str] = frozenset(),
) -> Starlette:
    if not allowed_hosts:
        raise ValueError("explicit_http_host_allowlist_required")
    current: contextvars.ContextVar[CallContext] = contextvars.ContextVar("gateway_call_context")
    server = make_mcp_server(gateway, current.get)
    manager = StreamableHTTPSessionManager(server, json_response=True, stateless=True)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    class Endpoint:
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            request = Request(scope, receive)
            status = None
            if request.headers.get("host", "") not in allowed_hosts:
                status = 421
            origin = request.headers.get("origin")
            if origin is not None and origin not in allowed_origins:
                status = 403
            if status is not None:
                await Response(status_code=status)(scope, receive, send)
                return
            authenticated = await authenticate(request)
            if authenticated is None:
                await Response(status_code=401)(scope, receive, send)
                return
            if request.method != "POST":
                # JSON-response Streamable HTTP does not offer a standalone SSE
                # stream or persistent sessions (both are optional in MCP).
                await Response(status_code=405)(scope, receive, send)
                return
            # Bound the frame before the MCP SDK parses protocol models.
            chunks = []
            size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 524288:
                    await Response(status_code=413)(scope, receive, send)
                    return
                chunks.append(chunk)
            body = b"".join(chunks)
            delivered = False

            async def bounded_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            token = current.set(authenticated)
            try:
                await manager.handle_request(scope, bounded_receive, send)
            finally:
                current.reset(token)

    return Starlette(routes=[Route("/mcp", Endpoint(), methods=["GET", "POST", "DELETE"])], lifespan=lifespan)
