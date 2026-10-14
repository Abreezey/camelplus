"""Compatibility conversions between the legacy two-state world and core models (arch.md §9).

These adapters let existing code (``camel.capabilities``,
``camel.security_policy``) interoperate with the new models without moving or
rewriting the legacy modules. Known approximations of the legacy model:

- The legacy ``Capabilities`` has no confidentiality dimension; values with
  non-public readers are mapped to ``INTERNAL`` (not higher).
- Legacy trusted sources map to ``TRUSTED_USER`` integrity; anything else to
  ``UNTRUSTED``. There is no legacy equivalent of ``VERIFIED``/``TRUSTED_SYSTEM``.
- ``CONFIRM`` has no legacy representation; converting it back yields
  ``Denied`` with a "requires confirmation" reason (fail closed).
"""

from camel.capabilities import Capabilities, readers, sources
from camel.core.decision import Decision, DecisionOutcome
from camel.core.labels import Confidentiality, Integrity, TrustLabel
from camel.security_policy import Allowed, Denied, SecurityPolicyResult

_TRUSTED_LEGACY_SOURCES = {
    sources.SourceEnum.User,
    sources.SourceEnum.CaMeL,
    sources.SourceEnum.Assistant,
    sources.SourceEnum.TrustedToolSource,
}


def _legacy_source_is_trusted(source: sources.Source) -> bool:
    if source in _TRUSTED_LEGACY_SOURCES:
        return True
    return (
        isinstance(source, sources.Tool)
        and len(source.inner_sources) > 0
        and source.inner_sources.issubset(_TRUSTED_LEGACY_SOURCES)
    )


def trust_label_from_capabilities(caps: Capabilities, *, provenance: frozenset[str] = frozenset()) -> TrustLabel:
    """Convert legacy ``Capabilities`` metadata into a ``TrustLabel``.

    ``provenance`` carries event ids when the caller knows them; the legacy
    model only names sources, which are recorded in ``data_classes``-free form
    as provenance strings prefixed with ``legacy:``.
    """
    all_trusted = all(_legacy_source_is_trusted(s) for s in caps.sources_set)
    legacy_provenance = frozenset(f"legacy:{s}" for s in caps.sources_set) | provenance
    if isinstance(caps.readers_set, readers.Public):
        return TrustLabel(
            provenance=legacy_provenance,
            integrity=Integrity.TRUSTED_USER if all_trusted else Integrity.UNTRUSTED,
            confidentiality=Confidentiality.PUBLIC,
            readers=None,
        )
    return TrustLabel(
        provenance=legacy_provenance,
        integrity=Integrity.TRUSTED_USER if all_trusted else Integrity.UNTRUSTED,
        confidentiality=Confidentiality.INTERNAL,
        readers=frozenset(str(r) for r in caps.readers_set),
    )


def decision_from_legacy(
    result: SecurityPolicyResult,
    *,
    policy_version: str = "legacy",
    contract_id: str | None = None,
    evidence: tuple[str, ...] = (),
) -> Decision:
    """Upgrade a legacy two-state result into a three-state ``Decision``."""
    if isinstance(result, Allowed):
        return Decision(
            decision=DecisionOutcome.ALLOW,
            policy_version=policy_version,
            contract_id=contract_id,
            evidence=evidence,
        )
    return Decision(
        decision=DecisionOutcome.DENY,
        hard_reasons=(result.reason,),
        policy_version=policy_version,
        contract_id=contract_id,
        evidence=evidence,
    )


def legacy_from_decision(decision: Decision) -> SecurityPolicyResult:
    """Downgrade a ``Decision`` for legacy callers. CONFIRM maps to Denied (fail closed)."""
    if decision.decision == DecisionOutcome.ALLOW:
        return Allowed()
    if decision.decision == DecisionOutcome.CONFIRM:
        return Denied("Decision requires user confirmation; legacy two-state callers must treat it as denied.")
    return Denied("; ".join(decision.hard_reasons) or "denied")
