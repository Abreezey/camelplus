"""Test reporting must not choose or tune a candidate after seeing scores."""

import copy
import json
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
MODULE = runpy.run_path(str(ROOT / "scripts/d_detection_test.py"))
REPORT = MODULE["report_test"]
VERIFY = MODULE["verify_selection"]
VERSION = MODULE["VERSION"]
SELECTION = json.loads((ROOT / "docs/d/evidence/D_detection_v2_validation_selection.json").read_text(encoding="utf-8"))
ACCEPTANCE = json.loads(
    (ROOT / "docs/d/evidence/D_detection_v2_validation_acceptance.json").read_text(encoding="utf-8")
)


def rows(attack: bool | None, benign: bool | None):
    return [
        dict(
            case_id="a",
            group_id="g",
            split="test",
            variant="attack",
            prediction=attack,
            source_type="web",
            mechanism="exfiltration",
        ),
        dict(
            case_id="b",
            group_id="g",
            split="test",
            variant="benign",
            prediction=benign,
            source_type="web",
            mechanism="exfiltration",
        ),
    ]


def test_bad_test_scores_do_not_reselect_the_baseline():
    result = REPORT(rows(True, False), rows(False, True), VERSION)
    assert result["selected_detector"] == VERSION
    assert not result["test_used_for_selection"]
    assert not result["parameters_changed_after_test"]
    assert result["candidate"]["counts"]["FN"] == result["candidate"]["counts"]["FP"] == 1
    assert result["agent_asr"] is result["benign_task_completion"] is None


def test_unknowns_remain_in_attack_and_benign_denominators():
    result = REPORT(rows(True, False), rows(None, None), VERSION)
    assert result["candidate"]["end_to_end_recall"]["rate"] == 0
    assert result["candidate"]["benign_unflagged_rate"]["rate"] == 0


@pytest.mark.parametrize("change", ["missing", "duplicate", "truth", "split"])
def test_misaligned_test_populations_rejected(change):
    left, right = rows(True, False), rows(True, False)
    if change == "missing":
        right.pop()
    elif change == "duplicate":
        right[1] = right[0]
    elif change == "truth":
        right[0]["variant"] = "benign"
    else:
        right[0]["split"] = "validation"
    with pytest.raises(ValueError, match="population"):
        REPORT(left, right, VERSION)


def test_another_version_cannot_be_selected_using_test():
    with pytest.raises(ValueError, match="frozen_validation"):
        REPORT(rows(True, False), rows(True, False), "another-version")


def test_actual_validation_selection_matches_without_test_predictions():
    VERIFY(ROOT, SELECTION, ACCEPTANCE)


@pytest.mark.parametrize(
    "key,value",
    [
        ("validation_selection_performed", False),
        ("frozen_before_test", False),
        ("test_evaluation_performed", True),
        ("candidate_retained", False),
        ("selected_detector", "another-version"),
        ("decision", "KEEP_BASELINE_FOR_TEST"),
        ("deployment_enabled", True),
        ("validation_conditions", {}),
    ],
)
def test_unfrozen_or_changed_selection_is_rejected(key, value):
    selection = copy.deepcopy(SELECTION)
    selection[key] = value
    with pytest.raises(ValueError, match="invalid_pretest"):
        VERIFY(ROOT, selection, ACCEPTANCE)
