"""D0 acceptance probes; failures preserve public-interface gaps for owner A.

Run without pytest: python -m unittest discover -s tests/unit/d0 -v.
No tool effects, model calls, or host-sensitive resources are used.
"""

import unittest
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from camel.core import (
    AllowedEffect,
    Authority,
    CanonicalEffect,
    DataReference,
    DecisionComposer,
    DecisionOutcome,
    DelegationSpec,
    EffectType,
    HardVerdict,
    IntentContract,
    RiskSignal,
    validate_child_contract,
)

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)
EXPIRY = NOW + timedelta(hours=1)


def contract(**changes) -> IntentContract:
    return IntentContract.model_validate(
        {
            "contract_id": "d0-parent",
            "principal": "user:synthetic",
            "goal": "read synthetic repository documentation",
            "expires_at": EXPIRY,
            "allowed_effects": (
                AllowedEffect(effect=EffectType.READ, operation="read_file", resource="repo://demo/docs/*"),
            ),
            "delegation": DelegationSpec(allowed=True, max_depth=1, child_ceiling=frozenset({EffectType.READ})),
        }
        | changes
    )


def signal(confidence: object = 0.9, **changes) -> RiskSignal:
    return RiskSignal.model_validate(
        {"name": "synthetic-risk", "confidence": confidence, "detector_version": "d0-v1"} | changes
    )


class OutputBoundaryTests(unittest.TestCase):
    def test_unknown_risk_field_rejected(self):
        with self.assertRaises(ValidationError):
            signal(authorized=True)

    def test_unknown_contract_field_rejected(self):
        with self.assertRaises(ValidationError):
            contract(authorization_source="external-tool-text")

    def test_string_confidence_rejected(self):
        with self.assertRaises(ValidationError):
            signal("0.9")

    def test_boolean_confidence_rejected(self):
        with self.assertRaises(ValidationError):
            signal(True)

    def test_out_of_range_and_nonfinite_confidence_rejected(self):
        for value in (-0.1, 1.1, float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                signal(value)

    def test_confidence_endpoints_accepted(self):
        self.assertEqual(signal(0.0).confidence, 0.0)
        self.assertEqual(signal(1.0).confidence, 1.0)

    def test_unknown_effect_enum_rejected(self):
        with self.assertRaises(ValidationError):
            CanonicalEffect.model_validate({"effect_id": "d0-effect", "type": "ROOT", "operation": "noop"})

    def test_missing_label_defaults_to_data_only(self):
        # D1's fixture loader must explicitly reject missing labels before this constructor.
        self.assertEqual(DataReference(ref="value://synthetic").label.authority, Authority.DATA_ONLY)

    def test_negative_side_effect_budget_rejected(self):
        with self.assertRaises(ValidationError):
            contract(side_effect_budget=-1)


class DecisionBoundaryTests(unittest.TestCase):
    def compose(self, verdict, signals=()):
        return DecisionComposer().compose(verdict, signals, policy_version="d0-synthetic")

    def test_default_deny(self):
        self.assertEqual(self.compose(HardVerdict()).decision, DecisionOutcome.DENY)

    def test_no_allow_plus_high_risk_stays_deny(self):
        result = self.compose(HardVerdict(), (signal(),))
        self.assertEqual(result.decision, DecisionOutcome.DENY)

    def test_explicit_allow_plus_high_risk_confirms(self):
        result = self.compose(HardVerdict(allowed=True), (signal(),))
        self.assertEqual(result.decision, DecisionOutcome.CONFIRM)

    def test_hard_deny_dominates_allow_confirm_and_risk(self):
        result = self.compose(
            HardVerdict(allowed=True, hard_reasons=("synthetic-hard-rule",), confirm_reasons=("confirm",)),
            (signal(),),
        )
        self.assertEqual(result.decision, DecisionOutcome.DENY)

    def test_replay_is_deterministic(self):
        verdict = HardVerdict(allowed=True)
        self.assertEqual(self.compose(verdict, (signal(),)), self.compose(verdict, (signal(),)))


class DelegationBoundaryTests(unittest.TestCase):
    def test_identical_scope_accepted(self):
        self.assertEqual(validate_child_contract(contract(), contract(contract_id="d0-child"), 1), [])

    def test_resource_expansion_rejected(self):
        child = contract(allowed_effects=(AllowedEffect(effect=EffectType.READ, operation="read_file", resource="**"),))
        self.assertTrue(validate_child_contract(contract(), child, 1))

    def test_operation_expansion_rejected(self):
        child = contract(
            allowed_effects=(AllowedEffect(effect=EffectType.READ, operation="*", resource="repo://demo/docs/*"),)
        )
        self.assertTrue(validate_child_contract(contract(), child, 1))

    def test_empty_ceiling_does_not_expand_parent_effect_types(self):
        parent = contract(delegation=DelegationSpec(allowed=True, max_depth=1))
        child = contract(allowed_effects=(AllowedEffect(effect=EffectType.WRITE),))
        self.assertTrue(validate_child_contract(parent, child, 1))

    def test_effect_type_expansion_with_explicit_ceiling_rejected(self):
        child = contract(allowed_effects=(AllowedEffect(effect=EffectType.WRITE),))
        self.assertTrue(validate_child_contract(contract(), child, 1))

    def test_child_expiry_expansion_rejected(self):
        self.assertTrue(validate_child_contract(contract(), contract(expires_at=EXPIRY + timedelta(seconds=1)), 1))

    def test_contract_expired_at_deadline(self):
        self.assertFalse(contract().is_expired(NOW))
        self.assertTrue(contract().is_expired(EXPIRY))


if __name__ == "__main__":
    unittest.main()
