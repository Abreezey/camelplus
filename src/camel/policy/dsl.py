"""Typed, default-deny YAML policy DSL v0 (arch.md §6.5).

Rules are compiled through Pydantic into pure predicates over
``(CanonicalEffect, IntentContract | None, destination domain)``. Unknown
condition keys and unknown enum values are rejected at compile time — a
malformed policy must never load silently.

Example::

    id: deny-secret-egress
    when:
      effect.type: EGRESS
      any_data.confidentiality_at_least: secret
      destination.domain_not_in: [corp]
    then: DENY

All conditions in one rule are AND-ed. A rule with an empty ``when`` matches
every effect (useful for an explicit catch-all ``ALLOW``).
"""

import fnmatch
from typing import Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from camel.core.contract import IntentContract
from camel.core.decision import DecisionOutcome
from camel.core.effect import CanonicalEffect, EffectType, NormalizationConfidence
from camel.core.labels import Confidentiality, Integrity


class DomainResolver(Protocol):
    """Resolves a destination to a trust domain (implemented by the engine's classifier)."""

    def domain_of(self, destination: str | None) -> str: ...


class Conditions(BaseModel):
    """The ``when`` block of a rule. ``None`` fields are not checked."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    effect_type: tuple[EffectType, ...] | None = Field(None, alias="effect.type")
    effect_operation: tuple[str, ...] | None = Field(None, alias="effect.operation")
    effect_resource_matches: str | None = Field(None, alias="effect.resource_matches")
    destination_domain_in: tuple[str, ...] | None = Field(None, alias="destination.domain_in")
    destination_domain_not_in: tuple[str, ...] | None = Field(None, alias="destination.domain_not_in")
    any_data_confidentiality_at_least: Confidentiality | None = Field(None, alias="any_data.confidentiality_at_least")
    any_data_integrity_at_most: Integrity | None = Field(None, alias="any_data.integrity_at_most")
    any_data_class_in: tuple[str, ...] | None = Field(None, alias="any_data.data_class_in")
    contract_missing_allowed_effect: bool | None = Field(None, alias="contract.missing_allowed_effect")
    normalization_failed: bool | None = Field(None, alias="normalization.failed")

    @field_validator(
        "effect_type",
        "effect_operation",
        "destination_domain_in",
        "destination_domain_not_in",
        "any_data_class_in",
        mode="before",
    )
    @classmethod
    def _wrap_scalar(cls, v: object) -> object:
        """Accept a scalar where a list is expected (YAML ergonomics)."""
        if isinstance(v, str):
            return (v,)
        return v

    def matches(self, effect: CanonicalEffect, contract: IntentContract | None, resolver: DomainResolver) -> bool:
        if self.effect_type is not None and effect.type not in self.effect_type:
            return False
        if self.effect_operation is not None and effect.operation not in self.effect_operation:
            return False
        if self.effect_resource_matches is not None and not any(
            fnmatch.fnmatchcase(r, self.effect_resource_matches) for r in effect.resources
        ):
            return False
        if self.destination_domain_in is not None:
            if resolver.domain_of(effect.destination) not in self.destination_domain_in:
                return False
        if self.destination_domain_not_in is not None:
            if resolver.domain_of(effect.destination) in self.destination_domain_not_in:
                return False
        if self.any_data_confidentiality_at_least is not None and not any(
            d.label.confidentiality_at_least(self.any_data_confidentiality_at_least) for d in effect.data_refs
        ):
            return False
        if self.any_data_integrity_at_most is not None and not any(
            d.label.integrity_at_most(self.any_data_integrity_at_most) for d in effect.data_refs
        ):
            return False
        if self.any_data_class_in is not None:
            wanted = set(self.any_data_class_in)
            if not any(d.label.data_classes & wanted for d in effect.data_refs):
                return False
        if self.contract_missing_allowed_effect:
            if contract is not None and contract.allows_effect(effect):
                return False
        if self.normalization_failed is not None:
            failed = effect.normalization_confidence == NormalizationConfidence.FAILED
            if failed != self.normalization_failed:
                return False
        return True


def _empty_conditions() -> Conditions:
    # model_validate({}) instead of Conditions(): pyright mis-infers the
    # constructor signature for models with dotted field aliases.
    return Conditions.model_validate({})


class PolicyRule(BaseModel):
    """One compiled rule: ``id``, ``when`` conditions, ``then`` outcome."""

    model_config = ConfigDict(frozen=True)

    id: str
    when: Conditions = Field(default_factory=_empty_conditions)
    then: DecisionOutcome

    def matches(self, effect: CanonicalEffect, contract: IntentContract | None, resolver: DomainResolver) -> bool:
        return self.when.matches(effect, contract, resolver)


def load_rules(document: str) -> list[PolicyRule]:
    """Compile a (possibly multi-document) YAML policy string into rules.

    Raises ``ValueError`` wrapping the validation errors on any malformed
    document — fail closed at load time, never at decision time.
    """
    rules: list[PolicyRule] = []
    seen_ids: set[str] = set()
    for i, doc in enumerate(yaml.safe_load_all(document)):
        if doc is None:
            continue
        try:
            rule = PolicyRule.model_validate(doc)
        except ValidationError as e:
            raise ValueError(f"Invalid policy rule in document {i}: {e}") from e
        if rule.id in seen_ids:
            raise ValueError(f"Duplicate policy rule id: {rule.id}")
        seen_ids.add(rule.id)
        rules.append(rule)
    return rules
