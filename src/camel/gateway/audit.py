"""Authenticated audit payloads; plaintext summaries never contain tool values."""

import base64
import hmac
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from camel.audit import AuditContext
from camel.audit.store import decision_payload
from camel.core.decision import Decision
from camel.core.effect import CanonicalEffect
from camel.gateway.models import GatewayError
from camel.normalization.models import digest


def _cipher(signing_key: bytes) -> Fernet:
    key = hmac.digest(signing_key, b"camel.gateway.audit.v1", "sha256")
    return Fernet(base64.urlsafe_b64encode(key))


def protected_decision_payload(
    decision: Decision, effect: CanonicalEffect, context: AuditContext, *, signing_key: bytes, event_id: str
) -> dict[str, Any]:
    """Keep exact replay inputs encrypted, separate from the public summary."""
    original = decision_payload(decision, effect, context)
    envelope = json.dumps({"event_id": event_id, "payload": original}, sort_keys=True).encode()
    return {
        "decision": {
            "decision": decision.decision.value,
            "policy_version": decision.policy_version,
            "hard_reasons": [reason.split(":", 1)[0] for reason in decision.hard_reasons],
            "confirm_reasons": [reason.split(":", 1)[0] for reason in decision.confirm_reasons],
        },
        "effect": {"effect_id": effect.effect_id, "type": effect.type.value, "derived_from": list(effect.derived_from)},
        "context": context.model_dump(),
        "payload_digest": digest(original),
        "protected_payload": _cipher(signing_key).encrypt(envelope).decode("ascii"),
        "payload_format": "gateway-fernet-v1",
    }


def recover_decision_payload(payload: dict[str, Any], *, signing_key: bytes, event_id: str) -> dict[str, Any]:
    """Trusted offline replay only; never expose this through MCP or reports."""
    try:
        if payload["payload_format"] != "gateway-fernet-v1":
            raise ValueError("unsupported payload format")
        envelope = json.loads(_cipher(signing_key).decrypt(payload["protected_payload"].encode("ascii")))
        original = envelope["payload"]
        if envelope["event_id"] != event_id or not hmac.compare_digest(digest(original), payload["payload_digest"]):
            raise ValueError("audit payload binding mismatch")
        return original
    except (InvalidToken, KeyError, ValueError, TypeError, AttributeError) as error:
        raise GatewayError("audit_payload_invalid") from error
