"""Versioned gateway envelopes; server text cannot supply trusted labels or identity."""

from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from camel.core.contract import IntentContract
from camel.core.decision import Decision
from camel.core.labels import TrustLabel
from camel.normalization.ingress import TextView
from camel.normalization.models import NormalizationContext, digest


class GatewayError(ValueError):
    """Fail-closed gateway rejection; messages are stable codes, never raw secrets."""


class ToolManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    description: str = ""
    input_schema: dict[str, Any]
    annotations: dict[str, Any] = Field(default_factory=dict)


class ServerManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    identity: str
    tools: tuple[ToolManifest, ...]

    @property
    def digest(self) -> str:
        return digest(
            {
                "identity": self.identity,
                "tools": [t.model_dump(mode="json") for t in sorted(self.tools, key=lambda t: t.name)],
            }
        )


class MCPTransport(Protocol):
    """Upstream transport owned exclusively by the trusted gateway process."""

    async def snapshot(self) -> ServerManifest: ...
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


class CallContext(BaseModel):
    """Authenticated context supplied by the host, not MCP request arguments."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str
    trace_id: str
    session_id: str
    normalization: NormalizationContext
    contract: IntentContract | None = None
    parameter_labels: dict[str, TrustLabel] = Field(default_factory=dict)
    model_version: str | None = None
    code_commit: str | None = None


class ToolResultEnvelope(BaseModel):
    """Only this envelope, never a naked server return, reaches the Agent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    event_id: str
    server_id: str
    server_identity: str
    tool: str
    manifest_digest: str
    labels: TrustLabel
    payload: dict[str, Any]
    suspicious_content: bool = False
    text_views: dict[str, TextView] = Field(default_factory=dict)


class GatewayResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    decisions: tuple[Decision, ...]
    output: ToolResultEnvelope | None = None
    confirmation_id: str | None = None
    confirmation_text: str | None = None
