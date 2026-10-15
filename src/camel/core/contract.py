"""Intent contracts: the trusted user's authorized goal and effect scope (arch.md §5.2).

The Intent Compiler (module D) compiles contracts from trusted user messages
and organizational policy only. External content can enter the plan as data
but must never modify the contract. This module only defines the data model
and the deterministic checks the policy engine needs.
"""

import fnmatch
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from camel.core.effect import CanonicalEffect, EffectType


class AllowedEffect(BaseModel):
    """One effect pattern the principal has authorized.

    ``operation`` is a glob over ``CanonicalEffect.operation`` (``None`` = any);
    ``resource`` is a glob that every resource of the effect must match.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    effect: EffectType
    operation: str | None = None
    resource: str = "**"

    def covers(self, effect: CanonicalEffect) -> bool:
        if effect.type != self.effect:
            return False
        if self.operation is not None and not fnmatch.fnmatchcase(effect.operation, self.operation):
            return False
        return all(fnmatch.fnmatchcase(r, self.resource) for r in effect.resources)


class DelegationSpec(BaseModel):
    """Whether and how this contract may be delegated to child agents."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: bool = False
    max_depth: int = Field(default=0, strict=True, ge=0)
    child_ceiling: frozenset[EffectType] = Field(default_factory=frozenset)


class IntentContract(BaseModel):
    """The compiled, trusted statement of what the agent may do (arch.md §5.2)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    contract_id: str
    principal: str
    goal: str
    allowed_effects: tuple[AllowedEffect, ...] = ()
    forbidden_data_classes: frozenset[str] = Field(default_factory=frozenset)
    allowed_destinations: tuple[str, ...] = ()
    side_effect_budget: int = Field(default=0, strict=True, ge=0)
    delegation: DelegationSpec = Field(default_factory=DelegationSpec)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def _expires_at_must_be_tz_aware(cls, v: datetime) -> datetime:
        """Naive datetimes would crash expiry comparison with a TypeError
        instead of producing a structured rejection; fail at construction."""
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return v

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def allows_effect(self, effect: CanonicalEffect) -> bool:
        return any(allowed.covers(effect) for allowed in self.allowed_effects)

    def allows_destination(self, destination: str) -> bool:
        return any(fnmatch.fnmatchcase(destination, pattern) for pattern in self.allowed_destinations)


def _pattern_contained(child: str, parent: str) -> bool:
    """Prove only equality, universal parents, or concrete child membership."""
    if parent in {"*", "**"} or child == parent:
        return True
    if any(char in child for char in "*?["):
        return False
    return fnmatch.fnmatchcase(child, parent)


def validate_child_contract(
    parent: IntentContract,
    child: IntentContract,
    depth: int,
) -> list[str]:
    """Check the delegation invariant I2: Authority(child) ⊆ Authority(parent) ∩ IntentContract.

    Returns a list of violations; empty means the delegation is valid.

    Effect patterns use conservative containment proofs; unproven glob
    subsets are rejected. Destination containment retains the existing
    exact-pattern or universal-parent approximation.
    """
    violations: list[str] = []
    if not parent.delegation.allowed:
        violations.append("delegation_not_allowed")
        return violations
    if depth > parent.delegation.max_depth:
        violations.append(f"delegation_depth_exceeded:{depth}>{parent.delegation.max_depth}")
    parent_types = {a.effect for a in parent.allowed_effects}
    ceiling = parent_types
    if parent.delegation.child_ceiling:
        ceiling = ceiling & parent.delegation.child_ceiling
    child_types = {a.effect for a in child.allowed_effects}
    if not child_types <= ceiling:
        violations.append(f"child_effect_types_exceed_ceiling:{sorted(child_types - ceiling)}")
    for index, effect in enumerate(child.allowed_effects):
        if not any(
            effect.effect == allowed.effect
            and _pattern_contained(
                effect.operation if effect.operation is not None else "**",
                allowed.operation if allowed.operation is not None else "**",
            )
            and _pattern_contained(effect.resource, allowed.resource)
            for allowed in parent.allowed_effects
        ):
            violations.append(f"child_effect_scope_exceeds_parent:{index}")
    for pattern in child.allowed_destinations:
        if pattern not in parent.allowed_destinations and "**" not in parent.allowed_destinations:
            violations.append(f"child_destination_exceeds_parent:{pattern}")
    if child.side_effect_budget > parent.side_effect_budget:
        violations.append("child_budget_exceeds_parent")
    if child.expires_at > parent.expires_at:
        violations.append("child_expiry_exceeds_parent")
    return violations
