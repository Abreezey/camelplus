"""Canonical effects: vendor-tool calls reduced to a stable representation (arch.md §5.3).

Policies never depend on vendor tool names; they depend on canonical effects
produced by the normalization layer (module B). One tool call may expand to
several effects (e.g. a shell pipeline can yield READ + EXEC + EGRESS).

Deviation from arch.md §5.3: ``data_refs`` entries carry their ``TrustLabel``
inline (instead of a bare ``value://`` string), because the IFC rules in the
policy engine need the confidentiality/integrity of each data reference and
must not depend on an external value store.
"""

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from camel.core.labels import TrustLabel


class EffectType(str, enum.Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXEC = "EXEC"
    EGRESS = "EGRESS"
    REPO_MUTATE = "REPO_MUTATE"
    DELEGATE = "DELEGATE"
    MEMORY_READ = "MEMORY_READ"
    MEMORY_WRITE = "MEMORY_WRITE"
    AUTH_CHANGE = "AUTH_CHANGE"


class Reversibility(str, enum.Enum):
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"


class NormalizationConfidence(str, enum.Enum):
    EXACT = "exact"
    INFERRED = "inferred"
    FAILED = "failed"


class DataReference(BaseModel):
    """A reference to a value used by an effect, with its trust label."""

    model_config = ConfigDict(frozen=True)

    ref: str
    label: TrustLabel = Field(default_factory=TrustLabel)


class CanonicalEffect(BaseModel):
    """A normalized external effect, the unit of policy decisions."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal[1] = 1
    effect_id: str
    type: EffectType
    operation: str
    resources: tuple[str, ...] = ()
    data_refs: tuple[DataReference, ...] = ()
    destination: str | None = None
    reversibility: Reversibility = Reversibility.IRREVERSIBLE
    required_capabilities: frozenset[str] = Field(default_factory=frozenset)
    derived_from: tuple[str, ...] = ()
    normalization_confidence: NormalizationConfidence = NormalizationConfidence.EXACT

    @property
    def is_side_effecting(self) -> bool:
        return self.type not in {EffectType.READ, EffectType.MEMORY_READ}

    @property
    def is_high_impact(self) -> bool:
        """High-impact effects fail closed when normalization fails (I6)."""
        return self.is_side_effecting and self.reversibility == Reversibility.IRREVERSIBLE
