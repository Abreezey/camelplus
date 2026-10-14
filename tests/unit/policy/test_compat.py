"""Legacy compatibility conversions and golden parity tests against the old policies.

Golden tests run the *actual* legacy policy functions
(``base_security_policy``, ``make_trusted_fields_policy``) on real
``CaMeLValue`` objects and compare outcomes with the new engine running the
semantically equivalent DSL fixtures.
"""

from datetime import datetime, timezone
from pathlib import Path

# Imported for side effects: the installed agentdojo version has a cross-version
# circular import that only resolves when agentdojo.task_suite is initialized first.
import agentdojo.task_suite  # noqa: F401

from camel.capabilities import Capabilities, is_public, readers, sources
from camel.core.decision import DecisionOutcome
from camel.core.effect import CanonicalEffect, DataReference, EffectType
from camel.core.labels import Confidentiality, Integrity
from camel.interpreter.value import CaMeLStr, CaMeLValue
from camel.pipeline_elements.security_policies.agentdojo_security_policies import make_trusted_fields_policy
from camel.policy.compat import decision_from_legacy, legacy_from_decision, trust_label_from_capabilities
from camel.policy.dsl import load_rules
from camel.policy.engine import PolicyEngine
from camel.security_policy import Allowed, Denied

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
FIXTURES = Path(__file__).parents[3] / "src" / "camel" / "policy" / "fixtures"

USER_CAPS = Capabilities(frozenset({sources.SourceEnum.User}), readers.Public())
UNTRUSTED_TOOL_CAPS = Capabilities(frozenset({sources.Tool("email_search")}), readers.Public())
PRIVATE_USER_CAPS = Capabilities(frozenset({sources.SourceEnum.User}), frozenset({"user:alice"}))


def _value(caps: Capabilities, text: str = "x") -> CaMeLValue:
    return CaMeLStr.from_raw(text, caps, ())


def _effect_from_kwargs(tool_name: str, kwargs: dict[str, CaMeLValue]) -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_golden",
        type=EffectType.WRITE,
        operation=tool_name,
        data_refs=tuple(
            DataReference(ref=f"value://{name}", label=trust_label_from_capabilities(value.metadata))
            for name, value in kwargs.items()
        ),
    )


def test_label_conversion_public_trusted() -> None:
    label = trust_label_from_capabilities(USER_CAPS)
    assert label.integrity == Integrity.TRUSTED_USER
    assert label.confidentiality == Confidentiality.PUBLIC
    assert label.readers is None
    assert label.provenance  # legacy sources recorded


def test_label_conversion_untrusted_tool_source() -> None:
    label = trust_label_from_capabilities(UNTRUSTED_TOOL_CAPS)
    assert label.integrity == Integrity.UNTRUSTED


def test_label_conversion_non_public_readers() -> None:
    label = trust_label_from_capabilities(PRIVATE_USER_CAPS)
    assert label.confidentiality == Confidentiality.INTERNAL
    assert label.readers == frozenset({"user:alice"})


def test_legacy_decision_roundtrip() -> None:
    assert decision_from_legacy(Allowed()).decision == DecisionOutcome.ALLOW
    denied = decision_from_legacy(Denied("no policy matched"))
    assert denied.decision == DecisionOutcome.DENY
    assert denied.hard_reasons == ("no policy matched",)
    assert isinstance(legacy_from_decision(decision_from_legacy(Allowed())), Allowed)
    back = legacy_from_decision(denied)
    assert isinstance(back, Denied) and "no policy matched" in back.reason


def test_confirm_downgrades_to_denied_for_legacy_callers() -> None:
    confirm = decision_from_legacy(Allowed()).model_copy(update={"decision": DecisionOutcome.CONFIRM})
    result = legacy_from_decision(confirm)
    assert isinstance(result, Denied)
    assert "confirmation" in result.reason


def test_golden_parity_base_security_policy() -> None:
    """base_public_only.yaml must agree with the legacy non-public-data gate.

    Reference: ``SecurityPolicyEngine.check_policy``'s actual enforcement path
    (``Denied`` iff any dependency is not ``is_public``). We deliberately do
    not reference ``base_security_policy``: it compares the whole
    ``get_all_readers`` return *tuple* against ``Public()`` and therefore
    denies unconditionally — a latent bug in the research artifact, reported
    in the handoff doc.
    """
    rules = load_rules((FIXTURES / "base_public_only.yaml").read_text())
    engine = PolicyEngine(rules)

    cases = [
        # (kwargs, legacy is_public gate outcome, new expectation)
        ({"body": _value(USER_CAPS)}, True, DecisionOutcome.ALLOW),
        ({"body": _value(PRIVATE_USER_CAPS)}, False, DecisionOutcome.DENY),
        ({"body": _value(USER_CAPS), "secret": _value(PRIVATE_USER_CAPS)}, False, DecisionOutcome.DENY),
    ]
    for kwargs, legacy_allows, new_outcome in cases:
        assert all(is_public(v) for v in kwargs.values()) == legacy_allows
        decision = engine.evaluate(_effect_from_kwargs("send_email", kwargs), now=NOW)
        assert decision.decision == new_outcome


def test_golden_parity_trusted_fields_policy() -> None:
    """trusted_parameters_only.yaml must agree with make_trusted_fields_policy."""
    rules = load_rules((FIXTURES / "trusted_parameters_only.yaml").read_text())
    engine = PolicyEngine(rules)
    legacy_policy = make_trusted_fields_policy(("email_id",))

    cases = [
        ({"email_id": _value(USER_CAPS)}, Allowed, DecisionOutcome.ALLOW),
        ({"email_id": _value(UNTRUSTED_TOOL_CAPS)}, Denied, DecisionOutcome.DENY),
    ]
    for kwargs, legacy_type, new_outcome in cases:
        assert isinstance(legacy_policy("delete_email", kwargs), legacy_type)
        decision = engine.evaluate(_effect_from_kwargs("delete_email", kwargs), now=NOW)
        assert decision.decision == new_outcome
