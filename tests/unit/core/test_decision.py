"""Decision composer invariants I1 (hard DENY is final) and I7 (risk only escalates)."""

import pytest

from camel.core.decision import (
    DEFAULT_DENY_REASON,
    DecisionComposer,
    DecisionOutcome,
    HardVerdict,
    RiskSignal,
)

_COMPOSER = DecisionComposer(confirm_threshold=0.5)
_HIGH_RISK = RiskSignal(name="indirect_instruction", confidence=0.9, detector_version="det-v1")
_LOW_RISK = RiskSignal(name="style_anomaly", confidence=0.1, detector_version="det-v1")


def _compose(verdict: HardVerdict, signals=()):
    return _COMPOSER.compose(verdict, signals, policy_version="sha256:test", contract_id="ic_01")


def test_i1_hard_deny_cannot_become_allow() -> None:
    verdict = HardVerdict(hard_reasons=("secret_to_untrusted_egress",), allowed=True)
    decision = _compose(verdict)
    assert decision.decision == DecisionOutcome.DENY
    assert "secret_to_untrusted_egress" in decision.hard_reasons


def test_i7_risk_signals_cannot_override_hard_deny() -> None:
    verdict = HardVerdict(hard_reasons=("ifc_violation",))
    decision = _compose(verdict, (_HIGH_RISK,))
    assert decision.decision == DecisionOutcome.DENY
    # Signals are still recorded for audit, they just cannot change the outcome.
    assert decision.risk_signals == (_HIGH_RISK,)


def test_risk_at_threshold_escalates_to_confirm() -> None:
    decision = _compose(HardVerdict(allowed=True), (_HIGH_RISK,))
    assert decision.decision == DecisionOutcome.CONFIRM
    decision = _compose(HardVerdict(allowed=True), (_LOW_RISK,))
    assert decision.decision == DecisionOutcome.ALLOW


def test_confirm_reasons_escalate_to_confirm() -> None:
    decision = _compose(HardVerdict(confirm_reasons=("contract_missing_allowed_effect",), allowed=True))
    assert decision.decision == DecisionOutcome.CONFIRM
    assert decision.confirm_reasons == ("contract_missing_allowed_effect",)


def test_default_deny_without_explicit_allow() -> None:
    decision = _compose(HardVerdict())
    assert decision.decision == DecisionOutcome.DENY
    assert decision.hard_reasons == (DEFAULT_DENY_REASON,)


def test_allow_only_with_explicit_allow_and_no_signals() -> None:
    decision = _compose(HardVerdict(allowed=True))
    assert decision.decision == DecisionOutcome.ALLOW
    assert decision.hard_reasons == ()
    assert decision.policy_version == "sha256:test"
    assert decision.contract_id == "ic_01"


def test_replay_consistency_same_inputs_same_decision() -> None:
    verdict = HardVerdict(hard_reasons=("x",), confirm_reasons=("y",), allowed=True)
    assert _compose(verdict, (_HIGH_RISK,)) == _compose(verdict, (_HIGH_RISK,))


def test_threshold_validation() -> None:
    with pytest.raises(ValueError):
        DecisionComposer(confirm_threshold=1.5)
