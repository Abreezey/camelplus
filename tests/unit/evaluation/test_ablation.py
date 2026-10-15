"""Ablation switches must leave the actual decision path, not only report flags."""

import copy
from datetime import datetime
from pathlib import Path

import pytest

from camel.detection.rules import detect
from camel.evaluation.ablation import (
    ARMS,
    Choice,
    choose,
    join_sources,
    paired_bootstrap,
    replay_choice,
    summarize,
    wilson,
)
from camel.evaluation.fixtures import load_dataset
from camel.policy import PolicyEngine, load_rules

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/d/d1_v1"


@pytest.fixture
def data():
    cases, manifest = load_dataset(FIXTURES)
    return (
        cases,
        datetime.fromisoformat(manifest["clock"]),
        PolicyEngine(load_rules((FIXTURES / "policy.yaml").read_text(encoding="utf-8"))),
    )


@pytest.mark.parametrize("arm", list(ARMS))
def test_disabled_callbacks_are_never_invoked(data, arm):
    case = data[0][0]
    _, views = join_sources(case)
    calls = []

    def callback(name, value):
        def run():
            calls.append(name)
            if name not in ARMS[arm]:
                raise AssertionError("disabled_layer_called")
            return value

        return run

    choice = choose(
        arm,
        rules=callback("R", detect(views)),
        embedding=callback("E", False),
        verifier=callback("V", {"status": "OK", "injection": False}),
        source_ids=tuple(view.source_id for view in views),
    )
    assert tuple(calls) == ARMS[arm] == choice.invoked


def test_disabled_verifier_failure_has_no_contribution(data):
    _, views = join_sources(data[0][0])
    choice = choose(
        "rules_embedding",
        rules=lambda: detect(views),
        embedding=lambda: False,
        verifier=lambda: (_ for _ in ()).throw(AssertionError("must not call")),
        source_ids=("s",),
    )
    assert not choice.incomplete


def test_enabled_failure_is_unknown_even_if_other_layer_detects(data):
    case = next(case for case in data[0] if case.case_id == "direct01-attack")
    _, views = join_sources(case)
    choice = choose(
        "rules_verifier",
        rules=lambda: detect(views),
        embedding=lambda: False,
        verifier=lambda: {"status": "INVALID_OR_FAILED_RESPONSE"},
        source_ids=("s",),
    )
    assert choice.incomplete and choice.prediction is None
    row = replay_choice(case, data[2], data[1], choice)
    assert row["classification"] == "UNKNOWN" and not row["ledger"]
    assert all(item["actual"]["decision"] == "DENY" for item in row["decisions"].values())


def test_kernel_only_is_not_reported_as_a_perfect_benign_classifier(data):
    case = data[0][1]
    row = replay_choice(case, data[2], data[1], Choice((), None, (), False, ()))
    assert row["classification"] == "NA"
    assert summarize([row])["precision"] is None


@pytest.mark.parametrize("name", ["memory04-attack", "memory06-attack"])
def test_memory_gate_removed_only_in_recording_harness(data, name):
    case = next(case for case in data[0] if case.case_id == name)
    choice = Choice((), None, (), False, ())
    unchanged = replay_choice(case, data[2], data[1], choice)
    ablated = replay_choice(case, data[2], data[1], choice, lifecycle_disabled=True)
    assert unchanged["ledger"] is None and unchanged["forbidden_observed"] is None
    assert ablated["ledger"] and ablated["forbidden_observed"] == [0]
    assert unchanged["labels"] == ablated["labels"]


def test_blocked_attack_not_counted_as_observed_safe(data):
    case = next(case for case in data[0] if case.case_id == "memory04-attack")
    row = replay_choice(case, data[2], data[1], Choice((), None, (), False, ()))
    metric = summarize([row])["attack_forbidden_recorded"]
    assert metric["denominator"] == 0 and metric["rate"] is None


def test_unknown_attack_retains_recall_denominator(data):
    case = data[0][0]
    row = replay_choice(case, data[2], data[1], Choice(("V",), None, (), True, ("V",)))
    metric = summarize([row])
    assert metric["counts"]["UNKNOWN"] == 1
    assert metric["recall"]["denominator"] == 1 and metric["recall"]["numerator"] == 0


def test_zero_events_wilson_interval_is_not_zero_width():
    metric = wilson(0, 6)
    assert metric["ci95"][1] > 0.3
    assert wilson(0, 0)["ci95"] is None


@pytest.mark.parametrize("successes,total", [(-1, 6), (7, 6), (True, 6), (1, 1.5)])
def test_invalid_ratio_inputs_refused(successes, total):
    with pytest.raises(ValueError):
        wilson(successes, total)


def paired_data(data):
    cases, now, engine = data
    pair = [case for case in cases if case.family_id == "memory04"]
    return [replay_choice(case, engine, now, Choice((), None, (), False, ()), lifecycle_disabled=True) for case in pair]


def test_bootstrap_samples_family_pairs_and_reproduces(data):
    rows = paired_data(data)
    result = paired_bootstrap(rows, rows, replicates=25, seed=4)
    assert result == paired_bootstrap(rows, rows, replicates=25, seed=4)
    assert result["families"] == 1
    assert result["left_minus_right"]["benign_completed"]["ci95"] == [0, 0]
    assert result["left_minus_right"]["detected_attacks"]["status"] == "NOT_APPLICABLE_NO_DETECTOR"


def test_bootstrap_rejects_missing_or_changed_pairs(data):
    rows = paired_data(data)
    with pytest.raises(ValueError, match="population"):
        paired_bootstrap(rows, rows[:1], replicates=5)
    other = copy.deepcopy(rows)
    other[0]["split"] = "different"
    with pytest.raises(ValueError, match="metadata"):
        paired_bootstrap(rows, other, replicates=5)
    with pytest.raises(ValueError, match="attack_benign"):
        paired_bootstrap(rows[:1], rows[:1], replicates=5)


def test_bootstrap_does_not_hide_unobserved_forbidden_outcomes(data):
    rows = paired_data(data)
    for row in rows:
        row["forbidden_observed"] = None
    result = paired_bootstrap(rows, rows, replicates=5)
    assert result["left_minus_right"]["forbidden_effect_observed"]["point"] is None
    assert result["raw_deltas"]["forbidden_effect_observed"] == []
