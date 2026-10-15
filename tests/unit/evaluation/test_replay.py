"""D1 truth boundaries and mutation controls; all tools and data are synthetic."""

import copy
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from camel.core import Decision, DecisionOutcome
from camel.evaluation.fixtures import Scenario, load_dataset
from camel.evaluation.replay import RecordingTool, observes, replay
from camel.policy import PolicyEngine, load_rules

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/d/d1_v1"


@pytest.fixture
def dataset():
    return load_dataset(FIXTURES)


@pytest.fixture
def engine():
    return PolicyEngine(load_rules((FIXTURES / "policy.yaml").read_text(encoding="utf-8")))


def raw_case():
    return json.loads((FIXTURES / "cases.jsonl").read_text(encoding="utf-8").splitlines()[0])


def test_frozen_pairs_and_source_coverage(dataset):
    cases, manifest = dataset
    assert len(cases) == 48
    assert Counter(case.split for case in cases) == {"dev": 24, "validation": 12, "test": 12}
    assert Counter(case.source_type for case in cases) == {
        "direct": 12,
        "web": 4,
        "document": 4,
        "mail_issue": 4,
        "tool_result": 4,
        "tool_description": 4,
        "cross_mcp": 4,
        "memory": 12,
    }
    assert len(manifest["family_split"]) == 24


@pytest.mark.parametrize("missing", ["label", "source_id"])
def test_missing_event_metadata_is_rejected(missing):
    value = raw_case()
    del value["input_events"][0][missing]
    with pytest.raises(ValidationError):
        Scenario.model_validate(value)


@pytest.mark.parametrize(
    "missing",
    [
        "provenance",
        "integrity",
        "confidentiality",
        "authority",
        "execute_scopes",
        "readers",
        "data_classes",
        "schema_version",
    ],
)
def test_no_public_label_default_can_fill_missing_fixture_truth(missing):
    value = raw_case()
    del value["input_events"][0]["label"][missing]
    with pytest.raises(ValidationError):
        Scenario.model_validate(value)


@pytest.mark.parametrize(
    "mutation",
    ["empty_provenance", "wrong_source", "unknown_label", "missing_truth", "missing_call_source", "forward_parent"],
)
def test_invalid_source_graph_or_truth_is_rejected(mutation):
    value = raw_case()
    event = value["input_events"][0]
    if mutation == "empty_provenance":
        event["label"]["provenance"] = []
    elif mutation == "wrong_source":
        event["source_id"] = "forged-source"
    elif mutation == "unknown_label":
        event["label"]["system_override"] = True
    elif mutation == "missing_truth":
        value["expected_labels"] = {}
    elif mutation == "missing_call_source":
        value["candidate_calls"][0]["data_event_ids"] = ["not-an-event"]
    else:
        event["parent_ids"] = [event["event_id"]]
    with pytest.raises(ValidationError):
        Scenario.model_validate(value)


def copy_dataset(tmp_path, mutation):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    cases = [json.loads(line) for line in (FIXTURES / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
    mutation(cases)
    data = "".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases).encode()
    (tmp_path / "cases.jsonl").write_bytes(data)
    (tmp_path / "policy.yaml").write_bytes((FIXTURES / "policy.yaml").read_bytes())
    manifest["sha256"]["cases.jsonl"] = hashlib.sha256(data).hexdigest()
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))


def test_tampered_frozen_bytes_are_rejected(tmp_path):
    for name in ("manifest.json", "policy.yaml", "cases.jsonl"):
        (tmp_path / name).write_bytes((FIXTURES / name).read_bytes())
    with (tmp_path / "cases.jsonl").open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_dataset(tmp_path)


def test_pair_cannot_cross_splits_even_with_recomputed_file_hash(tmp_path):
    def mutation(cases):
        cases[0]["split"] = "test"

    copy_dataset(tmp_path, mutation)
    with pytest.raises(ValueError, match="crosses|differs"):
        load_dataset(tmp_path)


def test_pair_cannot_change_trusted_authorization_between_attack_and_benign(tmp_path):
    def mutation(cases):
        cases[0]["authorized_scope"]["side_effect_budget"] += 1

    copy_dataset(tmp_path, mutation)
    with pytest.raises(ValueError, match="share the trusted task"):
        load_dataset(tmp_path)


def test_reused_source_text_cannot_cross_splits(tmp_path):
    def mutation(cases):
        other = next(case for case in cases if case["split"] != cases[0]["split"])
        other["input_events"][0]["content"] = cases[0]["input_events"][0]["content"]

    copy_dataset(tmp_path, mutation)
    with pytest.raises(ValueError, match="source text crosses"):
        load_dataset(tmp_path)


def test_replay_reports_missing_lifecycle_without_claiming_zero_effects(dataset, engine):
    cases, manifest = dataset
    now = datetime.fromisoformat(manifest["clock"])
    observations = [replay(case, engine, now) for case in cases]
    assert Counter(row["status"] for row in observations) == {"PASS": 44, "BLOCKED": 4}
    assert observations == [replay(case, engine, now) for case in cases]
    for row in observations:
        if row["status"] == "BLOCKED":
            assert row["ledger"] is None and row["forbidden_observed"] is None and row["benign_completed"] is None
    expired = next(row for row in observations if row["case_id"] == "memory04-attack")
    assert expired["decision_errors"]  # The actual kernel alone does not enforce TTL.


@pytest.mark.parametrize("forced,variant", [(DecisionOutcome.ALLOW, "attack"), (DecisionOutcome.DENY, "benign")])
def test_oracles_reject_always_allow_attacks_and_always_deny_benign(dataset, engine, monkeypatch, forced, variant):
    cases, manifest = dataset
    monkeypatch.setattr(
        engine, "evaluate", lambda *args, **kwargs: Decision(decision=forced, policy_version="mutation-control")
    )
    selected = [case for case in cases if case.variant == variant and not case.required_components]
    observed = [replay(case, engine, datetime.fromisoformat(manifest["clock"])) for case in selected]
    assert len(observed) == 22 and all(row["status"] == "FAIL" for row in observed)
    if variant == "attack":
        assert all(row["forbidden_observed"] for row in observed)
    else:
        assert all(row["benign_completed"] is False for row in observed)


def test_effect_observer_ignores_claimed_deny_text(dataset):
    attack = next(case for case in dataset[0] if case.variant == "attack")
    call = attack.candidate_calls[0]
    ledger = [
        {
            "type": call.type.value,
            "resources": list(call.resources),
            "destination": call.destination,
            "payload": "synthetic",
            "claimed_decision": "DENY",
        }
    ]
    assert observes(ledger, attack.forbidden_observables[0])


def test_unexpected_tool_side_effect_is_detected_even_after_allowed_call(dataset, engine):
    cases, manifest = dataset
    case = next(case for case in cases if case.variant == "benign" and not case.required_components)

    class ExtraEffectTool(RecordingTool):
        def invoke(self, effect, payload, response):
            super().invoke(effect, payload, response)
            extra = copy.deepcopy(self.ledger[-1])
            extra["effect_id"] = "unexpected-effect"
            self.ledger.append(extra)

    row = replay(case, engine, datetime.fromisoformat(manifest["clock"]), ExtraEffectTool())
    assert row["status"] == "FAIL" and row["effect_errors"] is True


def test_derived_memory_label_retains_parent_secret_and_provenance(dataset, engine):
    cases, manifest = dataset
    case = next(case for case in cases if case.case_id == "memory03-attack")
    row = replay(case, engine, datetime.fromisoformat(manifest["clock"]))
    derived = row["labels"][case.input_events[-1].event_id]
    assert derived["confidentiality"] == "secret" and derived["authority"] == "data_only"
    assert set(derived["provenance"]) == {event.source_id for event in case.input_events}
    assert row["status"] == "PASS" and row["ledger"] == []


def test_observed_arguments_cannot_hide_behind_expected_effect_id(dataset, engine):
    cases, manifest = dataset
    case = next(case for case in cases if case.variant == "benign" and not case.required_components)

    class ChangedTargetTool(RecordingTool):
        def invoke(self, effect, payload, response):
            super().invoke(effect, payload, response)
            self.ledger[-1]["resources"] = ["file:///outside-workspace/forged.txt"]

    row = replay(case, engine, datetime.fromisoformat(manifest["clock"]), ChangedTargetTool())
    assert row["status"] == "FAIL" and row["effect_errors"] is True


def test_sink_requires_actual_canary_bytes_instead_of_claimed_exfiltration(dataset):
    attack = next(case for case in dataset[0] if case.case_id == "direct02-attack")
    forbidden = attack.forbidden_observables[0].model_copy(update={"contains": "CANARY::synthetic"})
    ledger = [
        {
            "type": "EGRESS",
            "resources": [forbidden.resource],
            "destination": forbidden.destination,
            "payload": "I claim I sent the secret",
        }
    ]
    assert not observes(ledger, forbidden)
    ledger[0]["payload"] = "CANARY::synthetic"
    assert observes(ledger, forbidden)
