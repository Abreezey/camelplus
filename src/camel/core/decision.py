"""Three-state decisions and the deterministic decision composer (arch.md §5.4, §7).

Composition rules (fixed, not configurable per call):

1. Any hard reason => DENY (I1).
2. Otherwise, any confirm reason, or any risk signal at or above the
   confirmation threshold => CONFIRM.
3. Otherwise, ALLOW only if a deterministic layer explicitly allowed.
4. Otherwise DENY (default deny).

Risk signals can only escalate a decision towards CONFIRM/DENY; they can
never override a hard DENY or turn a non-allowed effect into an ALLOW (I7).
"""

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DecisionOutcome(str, enum.Enum):
    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    DENY = "DENY"


class RiskSignal(BaseModel):
    """Output of a detector/verifier. Purely advisory; see module docstring."""

    model_config = ConfigDict(frozen=True)

    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    detector_version: str
    evidence: tuple[str, ...] = ()


class Decision(BaseModel):
    """The final, auditable outcome for one candidate effect (arch.md §5.4)."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal[1] = 1
    decision: DecisionOutcome
    hard_reasons: tuple[str, ...] = ()
    confirm_reasons: tuple[str, ...] = ()
    risk_signals: tuple[RiskSignal, ...] = ()
    policy_version: str
    contract_id: str | None = None
    evidence: tuple[str, ...] = ()
    safe_alternative: str | None = None


class HardVerdict(BaseModel):
    """Intermediate output of the deterministic layers, before risk merging."""

    model_config = ConfigDict(frozen=True)

    hard_reasons: tuple[str, ...] = ()
    confirm_reasons: tuple[str, ...] = ()
    allowed: bool = False


DEFAULT_DENY_REASON = "default_deny:no_explicit_allow"


class DecisionComposer:
    """Merges deterministic verdicts with advisory risk signals into a Decision."""

    def __init__(self, confirm_threshold: float = 0.5) -> None:
        if not 0.0 <= confirm_threshold <= 1.0:
            raise ValueError("confirm_threshold must be in [0, 1]")
        self._confirm_threshold = confirm_threshold

    def compose(
        self,
        verdict: HardVerdict,
        risk_signals: tuple[RiskSignal, ...] = (),
        *,
        policy_version: str,
        contract_id: str | None = None,
        evidence: tuple[str, ...] = (),
        safe_alternative: str | None = None,
    ) -> Decision:
        if verdict.hard_reasons:
            outcome = DecisionOutcome.DENY
            hard_reasons = verdict.hard_reasons
        elif verdict.confirm_reasons or any(s.confidence >= self._confirm_threshold for s in risk_signals):
            outcome = DecisionOutcome.CONFIRM
            hard_reasons = ()
        elif verdict.allowed:
            outcome = DecisionOutcome.ALLOW
            hard_reasons = ()
        else:
            outcome = DecisionOutcome.DENY
            hard_reasons = (DEFAULT_DENY_REASON,)
        return Decision(
            decision=outcome,
            hard_reasons=hard_reasons,
            confirm_reasons=verdict.confirm_reasons,
            risk_signals=risk_signals,
            policy_version=policy_version,
            contract_id=contract_id,
            evidence=evidence,
            safe_alternative=safe_alternative,
        )
