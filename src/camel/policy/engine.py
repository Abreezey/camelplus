"""Deterministic policy engine (arch.md §6.5, §7).

Evaluation order is fixed (simplified from arch.md §7 for the layers that
module A owns):

1. Normalization failure: failed + high-impact effect => hard DENY (I6);
   failed + low-impact => CONFIRM.
2. IFC: any data whose confidentiality exceeds the destination's clearance
   => hard DENY (I4).
3. Intent Contract: expired contract or forbidden data class => hard DENY;
   effect/destination/budget outside the contract => CONFIRM.
4. DSL rules: every matching rule fires; DENY rules add hard reasons,
   CONFIRM rules add confirm reasons, ALLOW rules mark the effect allowed.
5. Composition (DecisionComposer): hard DENY wins; then risk escalation;
   an effect is ALLOW-ed only if an explicit ALLOW rule matched
   (default deny otherwise).

The engine never constructs or upgrades trust labels, and risk signals are
merged only by the composer, which can never override a hard DENY (I1, I7).
"""

import fnmatch
import hashlib
import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from camel.core.contract import IntentContract
from camel.core.decision import Decision, DecisionComposer, DecisionOutcome, HardVerdict, RiskSignal
from camel.core.effect import CanonicalEffect, NormalizationConfidence
from camel.core.labels import Confidentiality
from camel.policy.dsl import PolicyRule


class DestinationClassifier(BaseModel):
    """Maps destinations to trust domains and domains to clearance levels.

    ``domains`` maps globs (matched against the destination string) to domain
    names; the first matching pattern wins. Unknown destinations fall back to
    ``default_domain`` with ``default_clearance`` — unknown means untrusted.
    """

    model_config = ConfigDict(frozen=True)

    domains: dict[str, str] = Field(default_factory=dict)
    domain_clearance: dict[str, Confidentiality] = Field(default_factory=dict)
    default_domain: str = "untrusted"
    default_clearance: Confidentiality = Confidentiality.PUBLIC

    def domain_of(self, destination: str | None) -> str:
        if destination is None:
            return self.default_domain
        for pattern, domain in self.domains.items():
            if fnmatch.fnmatchcase(destination, pattern):
                return domain
        return self.default_domain

    def clearance_of(self, domain: str) -> Confidentiality:
        return self.domain_clearance.get(domain, self.default_clearance)


class PolicyEngine:
    """Evaluates canonical effects against contract, IFC and DSL rules."""

    def __init__(
        self,
        rules: list[PolicyRule],
        classifier: DestinationClassifier | None = None,
        confirm_threshold: float = 0.5,
    ) -> None:
        self._rules = list(rules)
        self._classifier = classifier or DestinationClassifier()
        self._composer = DecisionComposer(confirm_threshold)
        self._policy_version = self._compute_version()

    @property
    def policy_version(self) -> str:
        return self._policy_version

    def _compute_version(self) -> str:
        payload = json.dumps(
            {
                "rules": [r.model_dump(mode="json") for r in self._rules],
                "classifier": self._classifier.model_dump(mode="json"),
            },
            sort_keys=True,
        )
        return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()[:16]

    def evaluate(
        self,
        effect: CanonicalEffect,
        *,
        now: datetime,
        contract: IntentContract | None = None,
        risk_signals: tuple[RiskSignal, ...] = (),
        side_effects_used: int = 0,
        evidence: tuple[str, ...] = (),
        safe_alternative: str | None = None,
    ) -> Decision:
        """Evaluate one effect and return the final three-state decision.

        ``now`` is required (fail closed): contract expiry is always checked
        when a contract is provided.
        """
        hard: list[str] = []
        confirm: list[str] = []
        allowed = False

        # 1. Normalization failure handling (I6).
        if effect.normalization_confidence == NormalizationConfidence.FAILED:
            if effect.is_high_impact:
                hard.append("normalization_failed_high_impact")
            else:
                confirm.append("normalization_failed_low_impact")

        # 2. IFC: data may flow to a destination iff either
        #    a) its confidentiality fits the destination domain's clearance (I4), or
        #    b) the destination principal is explicitly in the data's readers set —
        #       the core CaMeL policy idiom (recipients ⊆ readers, e.g. send_email).
        #    Channel (b) requires an explicit readers set: readers=None (public) only
        #    uses channel (a), so unknown destinations stay default-deny.
        if effect.destination is not None:
            domain = self._classifier.domain_of(effect.destination)
            clearance = self._classifier.clearance_of(domain)
            for data in effect.data_refs:
                via_clearance = data.label.flows_to(clearance)
                via_readers = data.label.readers is not None and data.label.readable_by(effect.destination)
                if not (via_clearance or via_readers):
                    hard.append(f"ifc_confidentiality_violation:{data.ref}->{domain}")

        # 3. Intent Contract scope.
        if contract is not None:
            if contract.is_expired(now):
                hard.append("contract_expired")
            for data in effect.data_refs:
                bad = data.label.data_classes & contract.forbidden_data_classes
                if bad:
                    hard.append(f"contract_forbidden_data_class:{sorted(bad)}")
            if not contract.allows_effect(effect):
                confirm.append("contract_missing_allowed_effect")
            if effect.destination is not None and not contract.allows_destination(effect.destination):
                confirm.append("contract_destination_not_allowed")
            if effect.is_side_effecting and side_effects_used >= contract.side_effect_budget:
                confirm.append("contract_side_effect_budget_exceeded")

        # 4. DSL rules.
        for rule in self._rules:
            if not rule.matches(effect, contract, self._classifier):
                continue
            if rule.then == DecisionOutcome.DENY:
                hard.append(f"rule:{rule.id}")
            elif rule.then == DecisionOutcome.CONFIRM:
                confirm.append(f"rule:{rule.id}")
            else:
                allowed = True

        # 5. Composition (I1, I7 enforced by DecisionComposer).
        return self._composer.compose(
            HardVerdict(hard_reasons=tuple(hard), confirm_reasons=tuple(confirm), allowed=allowed),
            risk_signals,
            policy_version=self._policy_version,
            contract_id=contract.contract_id if contract is not None else None,
            evidence=evidence,
            safe_alternative=safe_alternative,
        )
