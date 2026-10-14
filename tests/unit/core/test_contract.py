"""Intent contract checks, including the delegation invariant I2."""

from datetime import datetime, timedelta, timezone

from camel.core.contract import AllowedEffect, DelegationSpec, IntentContract, validate_child_contract
from camel.core.effect import CanonicalEffect, EffectType

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(hours=1)
EARLIER = NOW - timedelta(hours=1)


def _contract(**overrides) -> IntentContract:
    base = {
        "contract_id": "ic_01",
        "principal": "user:alice",
        "goal": "review_current_repository",
        "expires_at": LATER,
    }
    return IntentContract(**(base | overrides))


def _effect(
    effect_type=EffectType.READ, operation="read_file", resources=("repo://current/a.py",), **kw
) -> CanonicalEffect:
    return CanonicalEffect(effect_id="fx_01", type=effect_type, operation=operation, resources=resources, **kw)


def test_allows_effect_with_operation_and_resource_globs() -> None:
    contract = _contract(
        allowed_effects=(AllowedEffect(effect=EffectType.READ, operation="read_*", resource="repo://**"),)
    )
    assert contract.allows_effect(_effect())
    assert not contract.allows_effect(_effect(operation="delete_file"))
    assert not contract.allows_effect(_effect(resources=("file:///etc/passwd",)))
    assert not contract.allows_effect(_effect(effect_type=EffectType.WRITE))


def test_allowed_effect_requires_all_resources_to_match() -> None:
    contract = _contract(allowed_effects=(AllowedEffect(effect=EffectType.READ, resource="repo://**"),))
    assert not contract.allows_effect(_effect(resources=("repo://ok", "file:///etc/passwd")))


def test_effect_without_resources_matches_any_resource_glob() -> None:
    contract = _contract(allowed_effects=(AllowedEffect(effect=EffectType.EXEC, operation="run_tests"),))
    assert contract.allows_effect(_effect(effect_type=EffectType.EXEC, operation="run_tests", resources=()))


def test_expiry() -> None:
    contract = _contract()
    assert not contract.is_expired(NOW)
    assert contract.is_expired(LATER)
    assert _contract(expires_at=EARLIER).is_expired(NOW)


def test_allows_destination() -> None:
    contract = _contract(allowed_destinations=("https://*.corp.com/*",))
    assert contract.allows_destination("https://mail.corp.com/send")
    assert not contract.allows_destination("https://evil.invalid/")


def test_valid_delegation_passes_i2() -> None:
    parent = _contract(
        allowed_effects=(AllowedEffect(effect=EffectType.READ), AllowedEffect(effect=EffectType.EGRESS)),
        allowed_destinations=("https://*.corp.com/*",),
        side_effect_budget=2,
        delegation=DelegationSpec(allowed=True, max_depth=1, child_ceiling=frozenset({EffectType.READ})),
    )
    child = _contract(
        contract_id="ic_02",
        allowed_effects=(AllowedEffect(effect=EffectType.READ),),
        side_effect_budget=0,
    )
    assert validate_child_contract(parent, child, depth=1) == []


def test_delegation_violations_detected() -> None:
    parent = _contract(delegation=DelegationSpec(allowed=False))
    child = _contract(contract_id="ic_02")
    assert validate_child_contract(parent, child, depth=0) == ["delegation_not_allowed"]

    parent = _contract(
        allowed_effects=(AllowedEffect(effect=EffectType.READ),),
        allowed_destinations=("https://corp.com/",),
        delegation=DelegationSpec(allowed=True, max_depth=1, child_ceiling=frozenset({EffectType.READ})),
    )
    child = _contract(
        contract_id="ic_02",
        allowed_effects=(AllowedEffect(effect=EffectType.EGRESS),),
        allowed_destinations=("https://evil.invalid/",),
        side_effect_budget=5,
        expires_at=LATER + timedelta(hours=1),
    )
    violations = validate_child_contract(parent, child, depth=2)
    assert any(v.startswith("delegation_depth_exceeded") for v in violations)
    assert any(v.startswith("child_effect_types_exceed_ceiling") for v in violations)
    assert any(v.startswith("child_destination_exceeds_parent") for v in violations)
    assert "child_budget_exceeds_parent" in violations
    assert "child_expiry_exceeds_parent" in violations


def test_json_roundtrip() -> None:
    contract = _contract(
        allowed_effects=(AllowedEffect(effect=EffectType.READ, operation="read_*", resource="repo://**"),),
        forbidden_data_classes=frozenset({"credential"}),
        delegation=DelegationSpec(allowed=True, max_depth=1, child_ceiling=frozenset({EffectType.READ})),
    )
    assert IntentContract.model_validate_json(contract.model_dump_json()) == contract
