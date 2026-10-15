"""Regression coverage for default-deny and conservative delegation scopes."""

from datetime import datetime, timedelta, timezone

from camel.core import (
    AllowedEffect,
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


def make_contract(*effects: AllowedEffect) -> IntentContract:
    return IntentContract(
        contract_id="proposal-synthetic",
        principal="user:synthetic",
        goal="synthetic document read",
        allowed_effects=effects,
        delegation=DelegationSpec(allowed=True, max_depth=1),
        expires_at=NOW + timedelta(hours=1),
    )


def read(operation: str | None, resource: str) -> AllowedEffect:
    return AllowedEffect(effect=EffectType.READ, operation=operation, resource=resource)


def test_concrete_narrowing_is_accepted() -> None:
    parent = make_contract(read("read_*", "repo://demo/docs/*"))
    child = make_contract(read("read_file", "repo://demo/docs/a.md"))
    assert validate_child_contract(parent, child, 1) == []


def test_identical_globs_are_accepted() -> None:
    parent = make_contract(read("read_*", "repo://demo/docs/*"))
    assert validate_child_contract(parent, parent, 1) == []


def test_global_parent_scope_is_accepted() -> None:
    parent = make_contract(read(None, "**"))
    child = make_contract(read("read_*", "repo://demo/docs/*"))
    assert validate_child_contract(parent, child, 1) == []


def test_empty_ceiling_still_cannot_add_types() -> None:
    parent = make_contract(read(None, "**"))
    child = make_contract(AllowedEffect(effect=EffectType.WRITE))
    assert validate_child_contract(parent, child, 1)


def test_child_cannot_remove_operation_restriction() -> None:
    parent = make_contract(read("read_file", "**"))
    child = make_contract(read(None, "**"))
    assert validate_child_contract(parent, child, 1)


def test_concrete_resource_outside_parent_is_rejected() -> None:
    parent = make_contract(read("read_file", "repo://demo/docs/*"))
    child = make_contract(read("read_file", "repo://demo/private/a.md"))
    assert validate_child_contract(parent, child, 1)


def test_empty_operation_is_not_universal() -> None:
    parent = make_contract(read("", "**"))
    child = make_contract(read("read_file", "**"))
    assert validate_child_contract(parent, child, 1)


def test_unproven_glob_subset_is_conservatively_rejected() -> None:
    parent = make_contract(read("read_*", "repo://demo/docs/*"))
    child = make_contract(read("read_*", "repo://demo/docs/guides/*"))
    assert validate_child_contract(parent, child, 1)


def test_cannot_mix_operation_and_resource_from_different_parent_entries() -> None:
    parent = make_contract(read("read_docs", "repo://docs/*"), read("read_logs", "repo://logs/*"))
    child = make_contract(read("read_docs", "repo://logs/*"))
    assert validate_child_contract(parent, child, 1)


def test_explicit_confirm_route_is_preserved_without_allow() -> None:
    result = DecisionComposer().compose(
        HardVerdict(confirm_reasons=("deterministic-confirm-rule",)), policy_version="proposal-synthetic"
    )
    assert result.decision == DecisionOutcome.CONFIRM


def test_high_risk_alone_cannot_create_confirm_route() -> None:
    risk = RiskSignal(name="synthetic", confidence=0.9, detector_version="proposal-v1")
    result = DecisionComposer().compose(HardVerdict(), (risk,), policy_version="proposal-synthetic")
    assert result.decision == DecisionOutcome.DENY
