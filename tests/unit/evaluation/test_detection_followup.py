"""Frozen data, leakage checks, and honest denominators for new scenarios."""

import shutil
from pathlib import Path

import pytest

from camel.evaluation.detection_followup import load_pairs, metrics, nearest_neighbors, validate_pairs

ROOT = Path(__file__).resolve().parents[3]


def test_dataset_has_36_complete_disjoint_pairs():
    pairs, _, old = load_pairs(ROOT)
    assert len(pairs) == 36
    assert sum(len(pair.cases) for pair in pairs) == 72
    assert len({case.case_id for pair in pairs for case in pair.cases}) == 72
    validate_pairs(pairs, tuple(text for _, text in old))


@pytest.mark.parametrize("field,value", [("split", "test"), ("mechanism", "exfiltration"), ("source_type", "memory")])
def test_rejects_broken_group_stratification(field, value):
    pairs, _, old = load_pairs(ROOT)
    with pytest.raises(ValueError, match="imbalance|12_pairs"):
        validate_pairs((pairs[0].model_copy(update={field: value}), *pairs[1:]), tuple(t for _, t in old))


@pytest.mark.parametrize("duplicate", ["old", "new", "pair"])
def test_rejects_duplicate_body_despite_case_and_whitespace(duplicate):
    pairs, _, old = load_pairs(ROOT)
    text = old[0][1] if duplicate == "old" else pairs[1 if duplicate == "new" else 0].cases[1].text
    case = pairs[0].cases[0].model_copy(update={"text": " \n" + text.upper() + "\t"})
    first = pairs[0].model_copy(update={"cases": (case, pairs[0].cases[1])})
    with pytest.raises(ValueError, match="duplicate"):
        validate_pairs((first, *pairs[1:]), tuple(t for _, t in old))


def test_rejects_two_attack_cases():
    pairs, _, _ = load_pairs(ROOT)
    bad = pairs[0].cases[1].model_copy(update={"variant": "attack"})
    with pytest.raises(ValueError, match="one_attack"):
        validate_pairs((pairs[0].model_copy(update={"cases": (pairs[0].cases[0], bad)}), *pairs[1:]), ())


@pytest.mark.parametrize("file", ["pairs.json", "protocol", "old_fixture"])
def test_rejects_changed_frozen_inputs(tmp_path, file):
    for relative in ("tests/fixtures/d/d1_v1", "tests/fixtures/d/detection_v2", "docs/d/evidence"):
        shutil.copytree(ROOT / relative, tmp_path / relative)
    shutil.copyfile(
        ROOT / "docs/d/D_detection_followup_protocol.md", tmp_path / "docs/d/D_detection_followup_protocol.md"
    )
    path = (
        tmp_path
        / {
            "pairs.json": "tests/fixtures/d/detection_v2/pairs.json",
            "protocol": "docs/d/D_detection_followup_protocol.md",
            "old_fixture": "tests/fixtures/d/d1_v1/policy.yaml",
        }[file]
    )
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="mismatch|changed"):
        load_pairs(tmp_path)


def row(case_id, variant, prediction):
    return dict(case_id=case_id, group_id=case_id[:1], variant=variant, prediction=prediction)


def test_unknown_is_not_removed_from_attack_or_benign_denominators():
    result = metrics(
        [row("a1", "attack", True), row("b1", "attack", None), row("a2", "benign", False), row("b2", "benign", None)]
    )
    assert result["end_to_end_recall"]["rate"] == 0.5
    assert result["benign_unflagged_rate"]["rate"] == 0.5
    assert result["counts"]["attack_unknown"] == result["counts"]["benign_unknown"] == 1
    assert result["benign_task_completion"] is result["agent_asr"] is None


def test_no_positive_prediction_does_not_mean_perfect_precision():
    result = metrics([row("a1", "attack", False), row("a2", "benign", False)])
    assert result["precision"]["rate"] is None
    assert result["end_to_end_recall"]["rate"] == 0


@pytest.mark.parametrize("prediction", [1, "false", [], {}])
def test_rejects_truthy_nonboolean_predictions(prediction):
    with pytest.raises(ValueError, match="invalid_prediction"):
        metrics([row("a1", "attack", prediction)])


def test_overlap_audit_excludes_paired_partner_and_is_deterministic():
    pairs, _, old = load_pairs(ROOT)
    forward = nearest_neighbors(pairs, old)
    assert forward == nearest_neighbors(pairs, old)
    reverse = {row["case_id"]: row for row in nearest_neighbors(tuple(reversed(pairs)), old)}
    assert all(row == reverse[row["case_id"]] for row in forward)
    groups = {case.case_id: pair.group_id for pair in pairs for case in pair.cases}
    splits = {case.case_id: pair.split for pair in pairs for case in pair.cases}
    for item in forward:
        assert groups[item["case_id"]] != groups[item["new_other_group"]["case_id"]]
        assert splits[item["case_id"]] != splits[item["new_other_split"]["case_id"]]
        assert all(0 <= item[key]["jaccard"] <= 1 for key in ("old", "new_other_group", "new_other_split"))
