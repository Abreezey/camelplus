"""Advisory risks cannot authorize tools; incomplete parsing blocks dependent effects."""

from datetime import datetime

from camel.core import CanonicalEffect, DecisionOutcome, IntentContract, RiskSignal
from camel.detection.models import DetectionResult, ParseOutcome, SafetyAssessment
from camel.policy import PolicyEngine


def assess_effect(
    effect: CanonicalEffect,
    *,
    detection: DetectionResult,
    engine: PolicyEngine,
    contract: IntentContract | None,
    now: datetime,
    parse_required: bool = False,
    parsed: ParseOutcome | None = None,
    side_effects_used: int = 0,
) -> SafetyAssessment:
    signals = list(detection.signals)
    blocked = []
    if detection.status != "OK":
        blocked.append("detection_incomplete")
    if (parse_required or parsed is not None) and (parsed is None or parsed.status != "OK"):
        blocked.append("required_parse_incomplete")
        signals.append(
            RiskSignal(
                name="parse_failure",
                confidence=1.0,
                detector_version="d3a-parse-v1",
                evidence=(parsed.status if parsed is not None else "MISSING",),
            )
        )
    decision = engine.evaluate(
        effect, now=now, contract=contract, risk_signals=tuple(signals), side_effects_used=side_effects_used
    )
    if decision.decision != DecisionOutcome.ALLOW:
        blocked.append("policy_not_allow")
    return SafetyAssessment(
        decision=decision,
        executable=not blocked,
        blocked_reasons=tuple(blocked),
        parse_status=parsed.status if parsed else None,
    )
