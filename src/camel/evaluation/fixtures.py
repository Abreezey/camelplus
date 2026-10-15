"""Strict fixture boundaries and frozen family splits for D1."""

import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator
from typing_extensions import Self

from camel.core import CanonicalEffect, DecisionOutcome, IntentContract, TrustLabel
from camel.core.effect import EffectType, NormalizationConfidence


class StrictRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def explicit_label(value: object) -> object:
    """Validate fixture completeness before reusing the actual public label model."""
    if not isinstance(value, dict) or set(value) != set(TrustLabel.model_fields):
        raise ValueError("fixture label must explicitly contain every public field and no unknown fields")
    if not value["provenance"]:
        raise ValueError("fixture label requires nonempty provenance")
    return value


ExplicitLabel = Annotated[TrustLabel, BeforeValidator(explicit_label)]


class InputEvent(StrictRecord):
    event_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    content: str = Field(min_length=1)
    label: ExplicitLabel
    parent_ids: tuple[str, ...] = ()
    memory_state: Literal["not_memory", "active", "expired", "quarantined"]

    @model_validator(mode="after")
    def source_in_label(self) -> Self:
        if self.source_id not in self.label.provenance:
            raise ValueError("source_id must be present in explicit label provenance")
        return self


class CandidateCall(StrictRecord):
    call_id: str = Field(min_length=1)
    type: EffectType
    operation: str = Field(min_length=1)
    resources: tuple[str, ...] = Field(min_length=1)
    destination: str | None
    data_event_ids: tuple[str, ...] = Field(min_length=1)
    normalization_confidence: NormalizationConfidence
    recorded_response: str


class ForbiddenObservable(StrictRecord):
    type: EffectType
    resource: str | None
    destination: str | None
    contains: str | None


class SuccessOracle(StrictRecord):
    required_effect_ids: tuple[str, ...]
    expected_responses: dict[str, str]


class Scenario(StrictRecord):
    case_id: str = Field(min_length=1)
    family_id: str = Field(min_length=1)
    source_type: Literal[
        "direct", "web", "document", "mail_issue", "tool_result", "tool_description", "cross_mcp", "memory"
    ]
    split: Literal["dev", "validation", "test"]
    variant: Literal["attack", "benign"]
    task: str = Field(min_length=1)
    authorized_scope: IntentContract
    input_events: tuple[InputEvent, ...] = Field(min_length=1)
    candidate_calls: tuple[CandidateCall, ...] = Field(min_length=1)
    expected_labels: dict[str, ExplicitLabel]
    expected_effects: tuple[str, ...]
    expected_decision: dict[str, DecisionOutcome]
    forbidden_observables: tuple[ForbiddenObservable, ...]
    benign_success_oracle: SuccessOracle | None
    required_components: tuple[Literal["memory_lifecycle_gate"], ...]
    truth_rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def references_and_truth(self) -> Self:
        events: set[str] = set()
        for event in self.input_events:
            if event.event_id in events or not set(event.parent_ids) <= events:
                raise ValueError("event IDs must be unique and parents must precede children")
            events.add(event.event_id)
        calls = {call.call_id for call in self.candidate_calls}
        if len(calls) != len(self.candidate_calls):
            raise ValueError("duplicate candidate call ID")
        if set(self.expected_labels) != events or set(self.expected_decision) != calls:
            raise ValueError("every event/call needs explicit independent truth")
        if not set(self.expected_effects) <= calls or len(set(self.expected_effects)) != len(self.expected_effects):
            raise ValueError("invalid expected recorded-effect IDs")
        for call in self.candidate_calls:
            if not set(call.data_event_ids) <= events:
                raise ValueError("candidate refers to missing source event")
        if (self.variant == "benign") != (self.benign_success_oracle is not None):
            raise ValueError("benign cases require a completion oracle; attacks must not have one")
        if self.variant == "attack" and not self.forbidden_observables:
            raise ValueError("attack requires an independent forbidden-effect oracle")
        if self.benign_success_oracle is not None:
            oracle = self.benign_success_oracle
            if not oracle.required_effect_ids or set(oracle.expected_responses) != set(oracle.required_effect_ids):
                raise ValueError("benign oracle needs concrete effect IDs and responses")
            if not set(oracle.required_effect_ids) <= calls:
                raise ValueError("oracle refers to unknown call")
        return self


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_dataset(directory: Path) -> tuple[list[Scenario], dict]:
    """Verify bytes before parsing; no split, source or truth repair is permitted."""
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported fixture manifest schema")
    for name in ("cases.jsonl", "policy.yaml"):
        if sha256(directory / name) != manifest["sha256"][name]:
            raise ValueError(f"frozen fixture hash mismatch: {name}")
    now = datetime.fromisoformat(manifest["clock"])
    if now.tzinfo is None:
        raise ValueError("fixture clock must have a timezone")
    cases = [
        Scenario.model_validate_json(line)
        for line in (directory / "cases.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    if len({case.case_id for case in cases}) != len(cases):
        raise ValueError("duplicate case ID")
    families: dict[str, list[Scenario]] = {}
    text_splits: dict[str, str] = {}
    for case in cases:
        families.setdefault(case.family_id, []).append(case)
        for event in case.input_events:
            fingerprint = hashlib.sha256(" ".join(event.content.split()).casefold().encode()).hexdigest()
            if fingerprint in text_splits and text_splits[fingerprint] != case.split:
                raise ValueError("identical normalized source text crosses splits")
            text_splits[fingerprint] = case.split
    for family, pair in families.items():
        if len(pair) != 2 or {case.variant for case in pair} != {"attack", "benign"}:
            raise ValueError(f"family must have exactly one attack/benign pair: {family}")
        if len({case.split for case in pair}) != 1 or len({case.source_type for case in pair}) != 1:
            raise ValueError("paired family crosses source category or split")
        if pair[0].task != pair[1].task or pair[0].authorized_scope != pair[1].authorized_scope:
            raise ValueError("paired cases must share the trusted task and authorized scope")
        if manifest["family_split"].get(family) != pair[0].split:
            raise ValueError("family differs from frozen split")
    if set(families) != set(manifest["family_split"]):
        raise ValueError("frozen family list mismatch")
    counts = dict(Counter(case.split for case in cases))
    if counts != manifest["case_counts"]:
        raise ValueError("frozen case counts mismatch")
    return cases, manifest


def canonical_effect(call: CandidateCall, labels: dict[str, TrustLabel]) -> CanonicalEffect:
    """Fixed canonical-effect stub, explicitly not B's production normalizer."""
    return CanonicalEffect.model_validate(
        {
            "effect_id": call.call_id,
            "type": call.type,
            "operation": call.operation,
            "resources": call.resources,
            "destination": call.destination,
            "data_refs": [{"ref": event_id, "label": labels[event_id]} for event_id in call.data_event_ids],
            "derived_from": call.data_event_ids,
            "normalization_confidence": call.normalization_confidence,
        }
    )
