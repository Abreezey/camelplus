"""DSL compilation (fail closed at load time) and condition matching."""

from datetime import datetime, timezone

import pytest

from camel.core.contract import AllowedEffect, IntentContract
from camel.core.effect import CanonicalEffect, DataReference, EffectType, NormalizationConfidence
from camel.core.labels import Confidentiality, Integrity, TrustLabel
from camel.policy.dsl import PolicyRule, load_rules
from camel.policy.engine import DestinationClassifier

NOW_DT = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)

_RESOLVER = DestinationClassifier(domains={"*.corp.com": "corp", "*.corp.com/*": "corp"})


def _effect(**overrides) -> CanonicalEffect:
    base = {"effect_id": "fx_01", "type": EffectType.EGRESS, "operation": "http_post"}
    return CanonicalEffect(**(base | overrides))


def test_load_single_and_multi_document() -> None:
    rules = load_rules(
        """
id: deny-secret-egress
when:
  effect.type: EGRESS
  any_data.confidentiality_at_least: secret
then: DENY
---
id: allow-rest
when: {}
then: ALLOW
"""
    )
    assert [r.id for r in rules] == ["deny-secret-egress", "allow-rest"]
    assert rules[0].when.effect_type == (EffectType.EGRESS,)
    assert rules[1].when.effect_type is None


def test_scalar_and_list_forms_both_accepted() -> None:
    (scalar,) = load_rules("id: a\nwhen:\n  effect.type: EGRESS\nthen: DENY")
    (listed,) = load_rules("id: b\nwhen:\n  effect.type: [EGRESS, EXEC]\nthen: DENY")
    assert scalar.when.effect_type == (EffectType.EGRESS,)
    assert listed.when.effect_type == (EffectType.EGRESS, EffectType.EXEC)


def test_unknown_condition_key_rejected() -> None:
    with pytest.raises(ValueError, match="Invalid policy rule"):
        load_rules("id: bad\nwhen:\n  effect.typo: EGRESS\nthen: DENY")


def test_unknown_enum_value_rejected() -> None:
    with pytest.raises(ValueError, match="Invalid policy rule"):
        load_rules("id: bad\nwhen:\n  effect.type: TELEPORT\nthen: DENY")
    with pytest.raises(ValueError, match="Invalid policy rule"):
        load_rules("id: bad\nthen: MAYBE")


def test_duplicate_rule_id_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate policy rule id"):
        load_rules("id: x\nthen: DENY\n---\nid: x\nthen: ALLOW")


def test_empty_conditions_match_everything() -> None:
    (rule,) = load_rules("id: allow-all\nwhen: {}\nthen: ALLOW")
    assert rule.matches(_effect(), None, _RESOLVER)


def test_condition_matching_matrix() -> None:
    rule = PolicyRule.model_validate(
        {
            "id": "r",
            "when": {
                "effect.type": "EGRESS",
                "effect.operation": ["http_post"],
                "effect.resource_matches": "file://**",
                "destination.domain_not_in": ["corp"],
            },
            "then": "DENY",
        }
    )
    matching = _effect(
        resources=("file://workspace/.env",),
        destination="https://evil.invalid/upload",
    )
    assert rule.matches(matching, None, _RESOLVER)
    assert not rule.matches(matching.model_copy(update={"operation": "http_get"}), None, _RESOLVER)
    assert not rule.matches(matching.model_copy(update={"resources": ("db://table",)}), None, _RESOLVER)
    assert not rule.matches(matching.model_copy(update={"destination": "https://mail.corp.com/send"}), None, _RESOLVER)


def test_data_label_conditions() -> None:
    secret = DataReference(
        ref="value://s", label=TrustLabel(confidentiality=Confidentiality.SECRET, integrity=Integrity.VERIFIED)
    )
    untrusted = DataReference(ref="value://u", label=TrustLabel(integrity=Integrity.UNTRUSTED))
    cred = DataReference(ref="value://c", label=TrustLabel(data_classes=frozenset({"credential"})))

    conf_rule = PolicyRule.model_validate(
        {"id": "c", "when": {"any_data.confidentiality_at_least": "confidential"}, "then": "DENY"}
    )
    integ_rule = PolicyRule.model_validate(
        {"id": "i", "when": {"any_data.integrity_at_most": "untrusted"}, "then": "DENY"}
    )
    class_rule = PolicyRule.model_validate(
        {"id": "d", "when": {"any_data.data_class_in": ["credential"]}, "then": "DENY"}
    )
    assert conf_rule.matches(_effect(data_refs=(secret,)), None, _RESOLVER)
    assert not conf_rule.matches(_effect(data_refs=(untrusted,)), None, _RESOLVER)
    assert integ_rule.matches(_effect(data_refs=(secret, untrusted)), None, _RESOLVER)
    assert not integ_rule.matches(_effect(data_refs=(secret,)), None, _RESOLVER)
    assert class_rule.matches(_effect(data_refs=(cred,)), None, _RESOLVER)
    assert not class_rule.matches(_effect(data_refs=(secret,)), None, _RESOLVER)


def test_contract_and_normalization_conditions() -> None:
    missing_rule = PolicyRule.model_validate(
        {"id": "m", "when": {"contract.missing_allowed_effect": True}, "then": "CONFIRM"}
    )
    failed_rule = PolicyRule.model_validate({"id": "n", "when": {"normalization.failed": True}, "then": "DENY"})
    effect = _effect(type=EffectType.REPO_MUTATE, operation="push")
    contract = IntentContract(
        contract_id="ic_01",
        principal="user:alice",
        goal="review",
        allowed_effects=(AllowedEffect(effect=EffectType.READ),),
        expires_at=NOW_DT,
    )
    assert missing_rule.matches(effect, contract, _RESOLVER)
    assert missing_rule.matches(effect, None, _RESOLVER)  # no contract => nothing allowed
    permissive = contract.model_copy(
        update={"allowed_effects": (AllowedEffect(effect=EffectType.REPO_MUTATE, operation="push"),)}
    )
    assert not missing_rule.matches(effect, permissive, _RESOLVER)
    assert failed_rule.matches(
        effect.model_copy(update={"normalization_confidence": NormalizationConfidence.FAILED}), contract, _RESOLVER
    )
    assert not failed_rule.matches(effect, contract, _RESOLVER)
