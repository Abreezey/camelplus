"""Strict contract and risk boundaries preserve valid Python/JSON callers."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from camel.core import AllowedEffect, DelegationSpec, EffectType, IntentContract, RiskSignal

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


@pytest.mark.parametrize("confidence", ["0.9", True, False, None, float("nan"), float("inf"), -0.1, 1.1])
def test_invalid_confidence_rejected(confidence: object) -> None:
    with pytest.raises(ValidationError):
        RiskSignal.model_validate({"name": "synthetic", "confidence": confidence, "detector_version": "d0-v1"})


@pytest.mark.parametrize("confidence", [0, 1, 0.5])
def test_valid_json_numeric_confidence_preserved(confidence: int | float) -> None:
    payload = {"name": "synthetic", "confidence": confidence, "detector_version": "d0-v1"}
    signal = RiskSignal.model_validate_json(json.dumps(payload))
    assert signal.confidence == confidence
    assert RiskSignal.model_validate_json(signal.model_dump_json()) == signal


@pytest.mark.parametrize("budget", [-1, "1", True, False, 1.5])
def test_invalid_budget_rejected(budget: object) -> None:
    with pytest.raises(ValidationError):
        IntentContract.model_validate(
            {
                "contract_id": "synthetic",
                "principal": "user:synthetic",
                "goal": "read synthetic documentation",
                "expires_at": NOW + timedelta(hours=1),
                "side_effect_budget": budget,
            }
        )


@pytest.mark.parametrize("depth", [-1, "1", True, 1.5])
def test_invalid_delegation_depth_rejected(depth: object) -> None:
    with pytest.raises(ValidationError):
        DelegationSpec.model_validate({"allowed": True, "max_depth": depth})


def test_nested_authorization_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        AllowedEffect.model_validate({"effect": EffectType.READ, "authorized_by_tool": True})
    with pytest.raises(ValidationError):
        DelegationSpec.model_validate({"allowed": True, "authorization_source": "tool"})


def test_strict_schema_exposes_unknown_field_and_budget_constraints() -> None:
    schema = IntentContract.model_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["side_effect_budget"]["minimum"] == 0
    assert schema["$defs"]["AllowedEffect"]["additionalProperties"] is False
    assert RiskSignal.model_json_schema()["additionalProperties"] is False
