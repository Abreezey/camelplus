"""Restricted, immutable planner records; source content is always data."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from camel.core import CanonicalEffect, Decision, IntentContract, TrustLabel


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Resource(Record):
    resource_id: str = Field(min_length=1)
    kind: Literal["document", "code"]

    @field_validator("resource_id")
    @classmethod
    def concrete_identifier(cls, value: str) -> str:
        if any(char in value for char in "*?["):
            raise ValueError("catalog identifiers must be concrete, not glob patterns")
        return value


class Organization(Record):
    policy_id: str = Field(min_length=1)
    resources: tuple[Resource, ...] = Field(min_length=1)
    forbidden_data_classes: frozenset[str]
    max_resources: int = Field(default=8, strict=True, ge=1, le=64)
    max_nodes: int = Field(default=32, strict=True, ge=1, le=128)
    max_effects: int = Field(default=64, strict=True, ge=1, le=256)
    max_sources: int = Field(default=64, strict=True, ge=1, le=256)
    max_source_characters: int = Field(default=32000, strict=True, ge=1, le=1000000)
    max_ttl_seconds: int = Field(default=3600, strict=True, ge=1, le=86400)


class TrustedTask(Record):
    """Constructed only by the trusted ingress; never deserialize from model output."""

    task_id: str = Field(min_length=1)
    principal: str = Field(min_length=1)
    template: str = Field(min_length=1)
    resource_ids: tuple[str, ...]
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        return value


class CompiledTask(Record):
    issued_at: datetime
    task: TrustedTask
    organization: Organization
    contract: IntentContract
    fingerprint: str


class Compilation(Record):
    status: Literal["READY", "UNSUPPORTED", "REQUIRES_AUTHORIZATION", "DENIED"]
    reasons: tuple[str, ...]
    compiled: CompiledTask | None


class DataField(Record):
    name: str = Field(min_length=1)
    value: str


class Source(Record):
    """Host-supplied provenance; candidates can reference IDs but cannot supply labels."""

    source_id: str = Field(min_length=1)
    label: TrustLabel
    fields: tuple[DataField, ...] = Field(min_length=1)
    parent_ids: tuple[str, ...] = ()
    producer_node_id: str | None = None

    @field_validator("label", mode="before")
    @classmethod
    def complete_label(cls, value):
        if isinstance(value, TrustLabel):
            return value
        if not isinstance(value, dict) or set(value) != set(TrustLabel.model_fields):
            raise ValueError("source labels require all public fields; no defaults are inferred")
        return value


class Binding(Record):
    source_id: str = Field(min_length=1)
    field: str = Field(min_length=1)


class DataSlot(Record):
    name: str = Field(min_length=1)
    binding: Binding | None


class ToolNode(Record):
    node_id: str = Field(min_length=1)
    tool_id: str = Field(min_length=1)
    tool_version: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    effect_refs: tuple[str, ...] = Field(min_length=1, max_length=1)
    source_ids: tuple[str, ...] = Field(min_length=1)
    depends_on: tuple[str, ...]
    data_slots: tuple[DataSlot, ...]


class CandidatePlan(Record):
    schema_version: Literal[1] = 1
    task_id: str = Field(min_length=1)
    nodes: tuple[ToolNode, ...] = Field(min_length=1, max_length=128)


class ToolSpec(Record):
    tool_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    template: Literal["read_document", "review_code"]
    data_slots: frozenset[str]


class NormalizedCall(Record):
    """Trusted adapter result; fixture_stub is explicit and never a production claim."""

    node_id: str
    tool_id: str
    tool_version: str
    request_fingerprint: str
    backend: Literal["fixture_stub", "production_adapter"]
    effects: tuple[CanonicalEffect, ...] = Field(min_length=1)


class GraphEdge(Record):
    source: str
    target: str
    kind: Literal["authorization", "data", "dependency", "derived", "tool_result"]


class Explanation(Record):
    task_id: str
    node_id: str
    effect_id: str
    source_ids: tuple[str, ...]
    decision: Decision


class PlanValidation(Record):
    status: Literal["READY", "DENIED", "REQUIRES_AUTHORIZATION"]
    contract_fingerprint: str
    candidate_fingerprint: str
    ordered_nodes: tuple[str, ...]
    edges: tuple[GraphEdge, ...]
    effects: tuple[CanonicalEffect, ...]
    explanations: tuple[Explanation, ...]
    executable_node_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    normalization_backends: tuple[str, ...]
