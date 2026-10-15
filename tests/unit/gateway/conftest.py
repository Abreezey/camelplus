"""Gateway fixtures keep upstream handles on the trusted side of each test."""

import copy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from camel.audit import AuditStore
from camel.gateway import CallContext, MCPSecurityGateway, ServerManifest, ToolManifest
from camel.normalization import EffectNormalizer, NetworkPolicy, NormalizationContext, ToolBinding
from camel.policy import PolicyEngine, load_rules
from camel.policy.ticket import InMemoryTicketStore


@pytest.fixture()
def anyio_backend():
    return "asyncio"


class FakeTransport:
    def __init__(self, root: Path):
        self.root = root
        self.manifest = ServerManifest(
            identity="server:test:1",
            tools=(
                ToolManifest(
                    name="read",
                    description="Read one workspace file",
                    input_schema={
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                ),
            ),
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.error: Exception | None = None
        self.snapshot_error: Exception | None = None
        self.returned: dict[str, Any] | None = None

    async def snapshot(self) -> ServerManifest:
        if self.snapshot_error is not None:
            raise self.snapshot_error
        return self.manifest

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, copy.deepcopy(arguments)))
        if self.error is not None:
            raise self.error
        if self.returned is not None:
            return self.returned
        return {"content": [{"type": "text", "text": (self.root / arguments["path"]).read_text()}], "isError": False}


@pytest.fixture()
def env(tmp_path: Path):
    (tmp_path / "note").write_text("hello")
    context = CallContext(
        subject="user:alice",
        trace_id="trace",
        session_id="session",
        normalization=NormalizationContext(workspace=tmp_path, cwd=tmp_path),
        model_version="model:test",
        code_commit="test-commit",
    )
    audit = AuditStore(":memory:")
    now = [datetime(2026, 10, 15, tzinfo=timezone.utc)]
    tickets = InMemoryTicketStore()
    engine = PolicyEngine(load_rules("id: allow\nwhen: {}\nthen: ALLOW"))
    gateway = MCPSecurityGateway(
        engine=engine,
        normalizer=EffectNormalizer(
            NetworkPolicy(allowed_hosts=frozenset({"example.com"})), resolver=lambda *_: ("93.184.216.34",)
        ),
        audit=audit,
        signing_key=b"gateway-test-key",
        ticket_store=tickets,
        now_fn=lambda: now[0],
    )
    return SimpleNamespace(
        root=tmp_path,
        context=context,
        audit=audit,
        now=now,
        tickets=tickets,
        engine=engine,
        gateway=gateway,
        transport=FakeTransport(tmp_path),
        binding=ToolBinding(adapter="fs", operation="read"),
    )


async def register(env, *, bindings=None, **kwargs):
    return await env.gateway.register(
        "files",
        env.transport,
        expected_identity=env.transport.manifest.identity,
        expected_digest=env.transport.manifest.digest,
        bindings=bindings or {"read": env.binding},
        context=env.context,
        **kwargs,
    )
