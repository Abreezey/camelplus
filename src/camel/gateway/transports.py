"""MCP SDK v1 upstream transports, with pinned process/endpoint identity.

HTTP connects to validated IP literals with the original Host and TLS SNI.
Proxies and automatic redirects are disabled, closing DNS-check/use and redirect
bypasses. Deployment credentials remain on this trusted side of the gateway.
"""

import asyncio
import hashlib
import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from camel.gateway.models import GatewayError, ServerManifest, ToolManifest
from camel.normalization.models import digest
from camel.normalization.net import NetworkPolicy, NetworkTarget, Resolver, resolve_dns


class PinnedHTTPTransport(httpx.AsyncBaseTransport):
    """Recheck DNS before every request, then connect to the approved address."""

    def __init__(
        self,
        policy: NetworkPolicy,
        *,
        resolver: Resolver = resolve_dns,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._policy, self._resolver = policy, resolver
        self._inner = transport or httpx.AsyncHTTPTransport(retries=0, trust_env=False)
        self._targets: dict[tuple[str, int], NetworkTarget] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        target = await asyncio.to_thread(self._policy.target, str(request.url), self._resolver)
        key = (target.host, target.port)
        if key in self._targets:
            if self._targets[key].addresses != target.addresses:
                raise GatewayError("dns_rebinding")
        else:
            self._targets[key] = target
        pinned = request.url.copy_with(host=target.addresses[0])
        headers = request.headers.copy()
        headers["host"] = request.url.netloc.decode("ascii")
        forwarded = httpx.Request(
            request.method,
            pinned,
            headers=headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": target.host},
        )
        response = await self._inner.handle_async_request(forwarded)
        if 300 <= response.status_code < 400:
            await response.aclose()
            raise GatewayError("upstream_redirect_requires_new_authorization")
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class SessionTransport:
    """An initialized session; only the gateway receives this object."""

    def __init__(self, session: ClientSession, endpoint_identity: str, server_info: dict[str, Any]) -> None:
        self._session = session
        self._identity = endpoint_identity + ":" + digest(server_info)

    @property
    def identity(self) -> str:
        return self._identity

    async def snapshot(self) -> ServerManifest:
        tools: list[ToolManifest] = []
        cursor = None
        seen: set[str] = set()
        for _ in range(32):
            page = await self._session.list_tools(cursor=cursor)
            for tool in page.tools:
                tools.append(
                    ToolManifest(
                        name=tool.name,
                        description=tool.description or "",
                        input_schema=tool.inputSchema,
                        annotations=tool.annotations.model_dump(mode="json") if tool.annotations else {},
                    )
                )
            if len(tools) > 512:
                raise GatewayError("tool_manifest_budget_exceeded")
            cursor = page.nextCursor
            if cursor is None:
                return ServerManifest(identity=self._identity, tools=tuple(tools))
            if cursor in seen:
                raise GatewayError("tool_manifest_pagination_loop")
            seen.add(cursor)
        raise GatewayError("tool_manifest_page_budget_exceeded")

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await self._session.call_tool(name, arguments)
        return result.model_dump(mode="json", by_alias=True)


def stdio_identity(command: str, args: tuple[str, ...], env: dict[str, str]) -> str:
    executable = Path(command)
    if not executable.is_absolute() or not executable.is_file():
        raise GatewayError("stdio_requires_absolute_executable")
    files = {str(executable.resolve()): hashlib.sha256(executable.read_bytes()).hexdigest()}
    # Pin script files passed as explicit absolute arguments as well as Python/bash.
    for arg in args:
        path = Path(arg)
        if path.is_absolute() and path.is_file():
            files[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
    return "stdio:" + digest({"command": str(executable.resolve()), "args": args, "env": env, "files": files})


@asynccontextmanager
async def connect_stdio(
    command: str,
    args: tuple[str, ...] = (),
    *,
    expected_identity: str,
    env: dict[str, str] | None = None,
) -> AsyncIterator[SessionTransport]:
    environment = dict(env or {})
    identity = stdio_identity(command, args, environment)
    if not hmac.compare_digest(identity, expected_identity):
        raise GatewayError("stdio_identity_mismatch")
    async with stdio_client(StdioServerParameters(command=command, args=list(args), env=environment)) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=30)) as session:
            initialized = await session.initialize()
            yield SessionTransport(session, identity, initialized.serverInfo.model_dump(mode="json"))


@asynccontextmanager
async def connect_http(
    url: str,
    policy: NetworkPolicy,
    *,
    headers: dict[str, str] | None = None,
    resolver: Resolver = resolve_dns,
) -> AsyncIterator[SessionTransport]:
    target = policy.target(url, resolver)
    if target.url != url:
        raise GatewayError("http_endpoint_must_be_canonical")

    def factory(
        headers: dict[str, str] | None = None, timeout: httpx.Timeout | None = None, auth: httpx.Auth | None = None
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout or httpx.Timeout(30),
            auth=auth,
            transport=PinnedHTTPTransport(policy, resolver=resolver),
            follow_redirects=False,
            trust_env=False,
        )

    async with streamablehttp_client(url, headers=headers, httpx_client_factory=factory) as (read, write, _):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=30)) as session:
            initialized = await session.initialize()
            yield SessionTransport(
                session, "https-endpoint:" + digest(target.url), initialized.serverInfo.model_dump(mode="json")
            )
