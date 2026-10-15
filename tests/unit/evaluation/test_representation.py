"""Representation provenance, conditional labels, evidence and paired denominators."""

import copy
from pathlib import Path

import pytest

from camel.evaluation.fixtures import load_dataset
from camel.evaluation.representation import VARIANTS, mutate, observe, paired, summarize

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/d/d1_v1"


@pytest.mark.parametrize("variant", VARIANTS)
def test_roundtrip_preserves_unicode_existing_separators_and_markup(variant):
    text = "AbZ 09\t\n中文\u0430\u200b\uff21\u3000😀 /* source excerpt\n </encoded-source>"
    assert mutate(text, variant).recover() == text
    assert mutate("", variant).recover() == ""


def test_unknown_mutation_rejected():
    with pytest.raises(ValueError, match="unknown_representation_variant"):
        mutate("ordinary source", "not_a_variant")


def test_base64_is_data_and_is_not_scanned_as_decoded_instruction():
    case = load_dataset(FIXTURES)[0][0]
    original = observe(case, "identity")
    encoded = observe(case, "base64_wrapper")
    assert original["prediction"] is True
    assert encoded["prediction"] is False
    assert original["labels"] == encoded["labels"]
    assert "我现在是系统管理员" not in encoded["sources"][0]["transformed_text"]


def test_zero_width_and_spacing_misses_are_reported_without_repair():
    case = load_dataset(FIXTURES)[0][0]
    for variant in ("zero_width", "character_spacing"):
        row = observe(case, variant)
        assert row["classification"] == "FN"
        assert row["detection"]["status"] == "OK"


def test_existing_parent_labels_survive_mutation_and_evidence_refers_to_new_view():
    case = next(case for case in load_dataset(FIXTURES)[0] if len(case.input_events) > 1)
    baseline = observe(case, "identity")
    row = observe(case, "comment_wrapper")
    assert row["labels"] == baseline["labels"]
    source_texts = {source["source_id"]: source["transformed_text"] for source in row["sources"]}
    for finding in row["detection"]["findings"]:
        evidence = finding["evidence"]
        assert source_texts[evidence["source_id"]][evidence["start"] : evidence["end"]]


def test_unchanged_ascii_free_case_is_not_claimed_as_changed():
    assert mutate("中文", "ascii_case_swap").text == "中文"
    assert mutate("中文", "fullwidth").text == "中文"


def test_unknown_stays_in_planned_attack_recall_denominator():
    cases = load_dataset(FIXTURES)[0][:2]
    rows = [observe(case, "identity") for case in cases]
    rows[0]["classification"] = "UNKNOWN"
    rows[0]["prediction"] = None
    result = summarize(rows)
    assert result["recall"]["denominator"] == 1
    assert result["recall"]["numerator"] == 0
    assert result["counts"]["UNKNOWN"] == 1


def test_paired_family_resampling_is_reproducible_and_identity_has_zero_delta():
    rows = [observe(case, "identity") for case in load_dataset(FIXTURES)[0][:4]]
    first = paired(rows, rows, replicates=100)
    assert first == paired(rows, rows, replicates=100)
    assert first["families"] == 2
    assert first["left_minus_identity"]["attack_detected"]["ci95"] == [0, 0]


@pytest.mark.parametrize("problem", ["missing", "duplicate", "wrong_split", "incomplete_family"])
def test_unfair_paired_populations_rejected(problem):
    rows = [observe(case, "identity") for case in load_dataset(FIXTURES)[0][:4]]
    current, reference = copy.deepcopy(rows), copy.deepcopy(rows)
    if problem == "missing":
        current.pop()
    elif problem == "duplicate":
        current.append(current[0])
    elif problem == "wrong_split":
        current[0]["split"] = "other"
    else:
        current.pop()
        reference.pop()
    with pytest.raises(ValueError):
        paired(current, reference, replicates=10)


@pytest.mark.parametrize("budget", [True, 0, -1, 1.5])
def test_invalid_bootstrap_budget_rejected(budget):
    with pytest.raises(ValueError, match="invalid_bootstrap_budget"):
        paired([], [], replicates=budget)
