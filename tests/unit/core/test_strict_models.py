"""Core security models must reject unknown fields (supports I6).

A misspelled field (e.g. ``normalization_confidnce``) must fail validation
loudly instead of being silently dropped while the real field falls back to
a safe-looking default.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from camel.core.contract import IntentContract
from camel.core.effect import CanonicalEffect, DataReference, EffectType
from camel.core.labels import TrustLabel
from camel.policy.ticket import CapabilityTicket


def test_effect_rejects_misspelled_normalization_confidence() -> None:
    with pytest.raises(ValidationError):
        CanonicalEffect(
            effect_id="fx_1",
            type=EffectType.EXEC,
            operation="run",
            **{"normalization_confidnce": "failed"},  # type: ignore[call-arg]
        )


def test_effect_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        CanonicalEffect(
            effect_id="fx_1",
            type=EffectType.READ,
            operation="read",
            **{"unknown_key": 1},  # type: ignore[call-arg]
        )


def test_data_reference_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        DataReference(ref="value://x", **{"labl": {}})  # type: ignore[call-arg]


def test_trust_label_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        TrustLabel(**{"confidentality": "secret"})  # type: ignore[call-arg]


def test_contract_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        IntentContract(
            contract_id="c1",
            principal="user:alice",
            goal="g",
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            **{"allowed_efects": []},  # type: ignore[call-arg]
        )


def test_ticket_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        CapabilityTicket(
            ticket_id="t1",
            subject="user:alice",
            effect_hash="sha256:x",
            resource="r",
            destination=None,
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            signature="sig",
            **{"max_usess": 5},  # type: ignore[call-arg]
        )
