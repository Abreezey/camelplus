"""Policy engine: fixed evaluation order and invariants I1/I4/I6/I7."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from camel.core.contract import AllowedEffect, IntentContract
from camel.core.decision import DecisionOutcome, RiskSignal
from camel.core.effect import CanonicalEffect, DataReference, EffectType, NormalizationConfidence
from camel.core.labels import Confidentiality, TrustLabel
from camel.policy.dsl import PolicyRule, load_rules
from camel.policy.engine import DestinationClassifier, PolicyEngine

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(hours=1)
EARLIER = NOW - timedelta(hours=1)

FIXTURES = Path(__file__).parents[3] / "src" / "camel" / "policy" / "fixtures"

ALLOW_ALL = PolicyRule.model_validate({"id": "allow-all", "when": {}, "then": "ALLOW"})
_CLASSIFIER = DestinationClassifier(
    domains={"https://*.corp.com/*": "corp"},
    domain_clearance={"corp": Confidentiality.SECRET},
)


def _engine(rules=(ALLOW_ALL,), classifier=_CLASSIFIER) -> PolicyEngine:
    return PolicyEngine(list(rules), classifier)


def _effect(**overrides) -> CanonicalEffect:
    base = {"effect_id": "fx_01", "type": EffectType.READ, "operation": "read_file"}
    return CanonicalEffect(**(base | overrides))


def _egress(confidentiality: Confidentiality, destination: str) -> CanonicalEffect:
    return _effect(
        type=EffectType.EGRESS,
        operation="http_post",
        resources=("file://workspace/.env",),
        data_refs=(DataReference(ref="value://d1", label=TrustLabel(confidentiality=confidentiality)),),
        destination=destination,
    )


def _contract(**overrides) -> IntentContract:
    base = {
        "contract_id": "ic_01",
        "principal": "user:alice",
        "goal": "review repo",
        "allowed_effects": (AllowedEffect(effect=EffectType.READ, resource="repo://**"),),
        "expires_at": LATER,
    }
    return IntentContract(**(base | overrides))


def test_allow_happy_path() -> None:
    decision = _engine().evaluate(_effect(resources=("repo://a.py",)), now=NOW, contract=_contract())
    assert decision.decision == DecisionOutcome.ALLOW
    assert decision.policy_version.startswith("sha256:")


def test_i4_secret_to_untrusted_destination_hard_denied() -> None:
    decision = _engine().evaluate(_egress(Confidentiality.SECRET, "https://evil.invalid/up"), now=NOW)
    assert decision.decision == DecisionOutcome.DENY
    assert any(r.startswith("ifc_confidentiality_violation") for r in decision.hard_reasons)


def test_secret_to_cleared_destination_allowed() -> None:
    decision = _engine().evaluate(_egress(Confidentiality.SECRET, "https://mail.corp.com/send"), now=NOW)
    assert decision.decision == DecisionOutcome.ALLOW


def test_unknown_destination_gets_default_low_clearance() -> None:
    decision = _engine().evaluate(_egress(Confidentiality.INTERNAL, "https://unknown.example/"), now=NOW)
    assert decision.decision == DecisionOutcome.DENY


def test_egress_without_destination_treated_as_untrusted() -> None:
    """destination=None on EGRESS is an *unknown* destination: fail closed (I4)."""
    secret = _egress(Confidentiality.SECRET, "https://x/").model_copy(update={"destination": None})
    decision = _engine().evaluate(secret, now=NOW)
    assert decision.decision == DecisionOutcome.DENY
    assert any(r.startswith("ifc_confidentiality_violation") for r in decision.hard_reasons)


def test_egress_without_destination_public_data_still_confirmed_under_contract() -> None:
    """Public data passes IFC, but an egress to an unknown destination is
    outside any contract's destination scope -> CONFIRM, never silent ALLOW."""
    public = _egress(Confidentiality.PUBLIC, "https://x/").model_copy(update={"destination": None})
    contract = _contract(
        allowed_effects=(AllowedEffect(effect=EffectType.EGRESS, operation="http_post"),),
        allowed_destinations=("https://*.corp.com/*",),
    )
    decision = _engine().evaluate(public, now=NOW, contract=contract)
    assert decision.decision == DecisionOutcome.CONFIRM
    assert "contract_destination_not_allowed" in decision.confirm_reasons


def test_i6_normalization_failed_high_impact_denied_low_impact_confirmed() -> None:
    high = _effect(type=EffectType.EXEC, operation="run", normalization_confidence=NormalizationConfidence.FAILED)
    assert _engine().evaluate(high, now=NOW).decision == DecisionOutcome.DENY
    low = _effect(normalization_confidence=NormalizationConfidence.FAILED)
    assert _engine().evaluate(low, now=NOW).decision == DecisionOutcome.CONFIRM


def test_contract_expired_hard_denied() -> None:
    decision = _engine().evaluate(_effect(resources=("repo://a.py",)), now=NOW, contract=_contract(expires_at=EARLIER))
    assert decision.decision == DecisionOutcome.DENY
    assert "contract_expired" in decision.hard_reasons


def _egress_to_principal(
    confidentiality: Confidentiality, readers: frozenset[str] | None, destination: str
) -> CanonicalEffect:
    return _effect(
        type=EffectType.EGRESS,
        operation="send_email",
        data_refs=(
            DataReference(ref="value://body", label=TrustLabel(confidentiality=confidentiality, readers=readers)),
        ),
        destination=destination,
    )


def test_camel_recipients_subset_readers_idiom() -> None:
    """The core CaMeL policy idiom: data may flow to a destination principal that is

    explicitly in its readers set, even when the domain's clearance is low
    (e.g. emailing a document to someone the document is shared with).
    """
    shared_with_alice = frozenset({"alice@corp.com"})
    # Recipient is in readers: allowed despite untrusted-domain clearance.
    decision = _engine().evaluate(
        _egress_to_principal(Confidentiality.INTERNAL, shared_with_alice, "alice@corp.com"), now=NOW
    )
    assert decision.decision == DecisionOutcome.ALLOW
    # Recipient NOT in readers: hard deny (the injection case — attacker-chosen address).
    decision = _engine().evaluate(
        _egress_to_principal(Confidentiality.INTERNAL, shared_with_alice, "mallory@evil.com"), now=NOW
    )
    assert decision.decision == DecisionOutcome.DENY
    assert any(r.startswith("ifc_confidentiality_violation") for r in decision.hard_reasons)


def test_readers_channel_requires_explicit_readers_set() -> None:
    """readers=None (public) must NOT open the readers channel: unknown destinations

    remain default-deny via the clearance path alone.
    """
    decision = _engine().evaluate(_egress_to_principal(Confidentiality.INTERNAL, None, "alice@corp.com"), now=NOW)
    assert decision.decision == DecisionOutcome.DENY


def test_secret_data_follows_readers_channel_like_camel() -> None:
    """Matches CaMeL semantics: even secret data may go to a principal in its readers."""
    readers = frozenset({"alice@corp.com"})
    assert (
        _engine().evaluate(_egress_to_principal(Confidentiality.SECRET, readers, "alice@corp.com"), now=NOW).decision
        == DecisionOutcome.ALLOW
    )
    assert (
        _engine().evaluate(_egress_to_principal(Confidentiality.SECRET, readers, "bob@corp.com"), now=NOW).decision
        == DecisionOutcome.DENY
    )


def test_contract_scope_violations_confirm() -> None:
    write = _effect(type=EffectType.WRITE, operation="save", resources=("repo://a.py",))
    decision = _engine().evaluate(write, now=NOW, contract=_contract(side_effect_budget=0))
    assert decision.decision == DecisionOutcome.CONFIRM
    assert "contract_missing_allowed_effect" in decision.confirm_reasons
    assert "contract_side_effect_budget_exceeded" in decision.confirm_reasons

    egress = _egress(Confidentiality.PUBLIC, "https://api.example/")
    decision = _engine().evaluate(egress, now=NOW, contract=_contract(allowed_destinations=()))
    assert decision.decision == DecisionOutcome.CONFIRM
    assert "contract_destination_not_allowed" in decision.confirm_reasons


def test_contract_forbidden_data_class_hard_denied() -> None:
    effect = _effect(
        data_refs=(DataReference(ref="value://k", label=TrustLabel(data_classes=frozenset({"credential"}))),)
    )
    decision = _engine().evaluate(effect, now=NOW, contract=_contract(forbidden_data_classes=frozenset({"credential"})))
    assert decision.decision == DecisionOutcome.DENY
    assert any(r.startswith("contract_forbidden_data_class") for r in decision.hard_reasons)


def test_deny_rule_beats_allow_rule_regardless_of_order() -> None:
    deny = PolicyRule.model_validate({"id": "deny-read", "when": {"effect.type": "READ"}, "then": "DENY"})
    for rules in ([ALLOW_ALL, deny], [deny, ALLOW_ALL]):
        decision = _engine(rules).evaluate(_effect(), now=NOW)
        assert decision.decision == DecisionOutcome.DENY
        assert "rule:deny-read" in decision.hard_reasons


def test_default_deny_when_no_allow_rule_matches() -> None:
    deny = PolicyRule.model_validate({"id": "deny-exec", "when": {"effect.type": "EXEC"}, "then": "DENY"})
    decision = _engine((deny,)).evaluate(_effect(), now=NOW)
    assert decision.decision == DecisionOutcome.DENY
    assert any(r.startswith("default_deny") for r in decision.hard_reasons)


def test_i7_risk_signal_escalates_but_never_overrides_hard_deny() -> None:
    signal = RiskSignal(name="intent_drift", confidence=0.9, detector_version="v1")
    allow_decision = _engine().evaluate(_effect(resources=("repo://a",)), now=NOW, risk_signals=(signal,))
    assert allow_decision.decision == DecisionOutcome.CONFIRM

    deny = PolicyRule.model_validate({"id": "deny-read", "when": {"effect.type": "READ"}, "then": "DENY"})
    deny_decision = _engine((ALLOW_ALL, deny)).evaluate(_effect(), now=NOW, risk_signals=(signal,))
    assert deny_decision.decision == DecisionOutcome.DENY


def test_policy_version_stable_and_rule_sensitive() -> None:
    assert _engine().policy_version == _engine().policy_version
    other = PolicyEngine([ALLOW_ALL], DestinationClassifier())
    assert other.policy_version != _engine().policy_version


def test_fixture_deny_secret_egress() -> None:
    rules = load_rules((FIXTURES / "deny_secret_egress.yaml").read_text())
    decision = _engine([*rules, ALLOW_ALL]).evaluate(_egress(Confidentiality.SECRET, "https://evil.invalid/"), now=NOW)
    assert decision.decision == DecisionOutcome.DENY
    assert "rule:deny-secret-egress" in decision.hard_reasons


def test_fixture_confirm_repo_push() -> None:
    rules = load_rules((FIXTURES / "confirm_repo_push.yaml").read_text())
    push = _effect(type=EffectType.REPO_MUTATE, operation="push", resources=("repo://current",))
    # Contract only authorizes READ: push must be confirmed, not silently allowed (arch.md §8.2).
    decision = _engine([*rules, ALLOW_ALL]).evaluate(push, now=NOW, contract=_contract())
    assert decision.decision == DecisionOutcome.CONFIRM
    assert "rule:confirm-repo-push" in decision.confirm_reasons
    # With the contract authorizing the push, the rule no longer fires.
    permissive = _contract(
        allowed_effects=(AllowedEffect(effect=EffectType.REPO_MUTATE, operation="push", resource="repo://**"),),
        side_effect_budget=1,
    )
    decision = _engine([*rules, ALLOW_ALL]).evaluate(push, now=NOW, contract=permissive, side_effects_used=0)
    assert decision.decision == DecisionOutcome.ALLOW


def test_evaluation_is_deterministic() -> None:
    effect = _egress(Confidentiality.SECRET, "https://evil.invalid/")
    engine = _engine()
    assert engine.evaluate(effect, now=NOW) == engine.evaluate(effect, now=NOW)
