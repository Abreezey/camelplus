"""Normalization inputs and results (module B, arch.md §6.1/§6.4).

Contexts and labels are supplied by the trusted ingress, never by tool arguments.
Failure is represented by an irreversible FAILED effect as well as a reason;
callers must not execute a partial normalization result.
"""

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from camel.core.effect import CanonicalEffect, DataReference, EffectType, NormalizationConfidence
from camel.core.labels import Confidentiality, TrustLabel


class NormalizationError(ValueError):
    """An input cannot be reduced safely within the configured boundary."""


class NormalizationContext(BaseModel):
    """Trusted filesystem boundary and value-level provenance for one call."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    workspace: Path
    cwd: Path
    parent_ids: tuple[str, ...] = ()
    data_refs: tuple[DataReference, ...] = ()
    resource_labels: dict[str, TrustLabel] = Field(default_factory=dict)


class NormalizationResult(BaseModel):
    """All effects of one invocation, including failures discovered mid-parse."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    effects: tuple[CanonicalEffect, ...]
    failures: tuple[str, ...] = ()
    arguments: dict[str, Any] | None = None

    @property
    def blocked(self) -> bool:
        return bool(self.failures) or any(
            e.normalization_confidence is NormalizationConfidence.FAILED for e in self.effects
        )


def digest(value: Any) -> str:
    """Canonical JSON digest; sequence order is security-relevant."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


def make_effect(
    context: NormalizationContext, effect_type: EffectType, operation: str, **fields: Any
) -> CanonicalEffect:
    return CanonicalEffect(
        effect_id=f"fx_{uuid.uuid4().hex}",
        type=effect_type,
        operation=operation,
        data_refs=fields.pop("data_refs", context.data_refs),
        derived_from=context.parent_ids,
        **fields,
    )


def failed(context: NormalizationContext, reason: str) -> NormalizationResult:
    return NormalizationResult(
        effects=(
            make_effect(
                context,
                EffectType.EXEC,
                "normalization_failed",
                normalization_confidence=NormalizationConfidence.FAILED,
            ),
        ),
        failures=(reason,),
    )


class EffectSpec(BaseModel):
    """Trusted mapping for a pinned MCP tool with no built-in adapter.

    Each resource field expands into a separate effect: multi-resource ordering
    must never decide which target the executor accesses. Message destinations
    are principal identifiers; network URLs use the network adapter instead.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: EffectType
    operation: str
    resource_fields: tuple[str, ...] = ()
    destination_field: str | None = None
    required_capabilities: frozenset[str] = Field(default_factory=frozenset)


class ToolBinding(BaseModel):
    """Deployment-owned effect semantics, pinned separately from tool descriptions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter: str
    operation: str = ""
    argument_map: dict[str, str] = Field(default_factory=dict)
    effects: tuple[EffectSpec, ...] = ()
    result_label: TrustLabel = Field(default_factory=lambda: TrustLabel(confidentiality=Confidentiality.SECRET))

    def arguments(self, supplied: dict[str, Any]) -> dict[str, Any]:
        mapped = {self.argument_map.get(k, k): v for k, v in supplied.items()}
        if len(mapped) != len(supplied):
            raise NormalizationError("colliding_argument_mapping")
        return mapped
