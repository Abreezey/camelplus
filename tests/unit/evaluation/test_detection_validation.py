"""Selection and once-only reservation controls without holdout predictions."""

import copy
import hashlib
import json
import runpy
from pathlib import Path

import pytest

from camel.core import TrustLabel
from camel.detection.models import identity_view
from camel.detection.rules import detect

ROOT = Path(__file__).resolve().parents[3]
MODULE = runpy.run_path(str(ROOT / "scripts/d_detection_validation.py"))
SELECT = MODULE["select"]
VERIFY_PIN = MODULE["verify_pin"]
RESERVE = MODULE["reserve"]
CHECK_EVIDENCE = MODULE["check_evidence"]
PIN = json.loads((ROOT / "docs/d/evidence/D_detection_v2_candidate_freeze.json").read_text(encoding="utf-8"))


def rows(attack: bool | None = True, benign: bool | None = True):
    return [
        dict(
            case_id="a",
            group_id="g",
            split="validation",
            variant="attack",
            prediction=attack,
            source_type="web",
            mechanism="exfiltration",
        ),
        dict(
            case_id="b",
            group_id="g",
            split="validation",
            variant="benign",
            prediction=benign,
            source_type="web",
            mechanism="exfiltration",
        ),
    ]


def test_fp_reduction_qualifies_when_baseline_recall_is_already_perfect():
    decision = SELECT(rows(), rows(benign=False), dev_cost_eligible=True)
    assert decision["decision"] == "RETAIN_CANDIDATE_FOR_TEST"
    assert decision["validation_selection_performed"]
    assert not decision["test_evaluation_performed"]
    assert not decision["deployment_enabled"]
    assert "dev_conditions" not in decision


@pytest.mark.parametrize(
    "before,after",
    [
        (rows(), rows(attack=False, benign=False)),
        (rows(attack=False, benign=False), rows(attack=True, benign=True)),
        (rows(), rows()),
        (rows(), rows(attack=None, benign=False)),
        (rows(), rows(benign=None)),
    ],
)
def test_failures_or_no_improvement_keep_baseline(before, after):
    result = SELECT(before, after, dev_cost_eligible=True)
    assert result["decision"] == "KEEP_BASELINE_FOR_TEST"
    assert result["selected_detector"] == "d3a-fixed-rules-v1"


def test_dev_cost_failure_cannot_be_rescued_by_validation_quality():
    assert not SELECT(rows(), rows(benign=False), dev_cost_eligible=False)["candidate_retained"]


@pytest.mark.parametrize("split", ["dev", "test"])
def test_other_splits_cannot_enter_validation_selection(split):
    bad = rows()
    bad[0]["split"] = split
    with pytest.raises(ValueError, match="validation_only"):
        SELECT(bad, bad, dev_cost_eligible=True)


def test_one_local_reservation_blocks_different_output_directory(tmp_path):
    reservation = tmp_path / "reservation.json"
    RESERVE(reservation, tmp_path / "first", {"file": "abc"})
    saved = reservation.read_bytes()
    with pytest.raises(FileExistsError):
        RESERVE(reservation, tmp_path / "second", {"file": "def"})
    assert reservation.read_bytes() == saved
    assert json.loads(saved)["status"] == "RESERVED"


def test_real_frozen_pin_still_matches_without_running_detector():
    VERIFY_PIN(ROOT, PIN)


@pytest.mark.parametrize(
    "key,value",
    [
        ("candidate_version", "another-version"),
        ("status", "EDITED"),
        ("selected_for_validation_only", False),
        ("validation_selection_performed", True),
        ("test_evaluation_performed", True),
        ("deployment_enabled", True),
    ],
)
def test_unfrozen_or_already_evaluated_pin_is_rejected(key, value):
    pin = copy.deepcopy(PIN)
    pin[key] = value
    with pytest.raises(ValueError, match="not_frozen"):
        VERIFY_PIN(ROOT, pin)


def test_missing_runtime_pin_rejected():
    pin = copy.deepcopy(PIN)
    del pin["source_sha256"]["src/camel/detection/candidate_v2.py"]
    with pytest.raises(ValueError, match="missing_required"):
        VERIFY_PIN(ROOT, pin)


@pytest.mark.parametrize("change", ["content", "path"])
def test_tampered_or_escaping_files_rejected(tmp_path, change):
    pin = copy.deepcopy(PIN)
    required = {
        "src/camel/detection/candidate_v2.py",
        "src/camel/detection/rules.py",
        "src/camel/evaluation/detection_candidate.py",
        "src/camel/evaluation/detection_followup.py",
        "tests/fixtures/d/detection_v2/pairs.json",
        "tests/fixtures/d/detection_v2/manifest.json",
        "docs/d/evidence/D_detection_followup_protocol.json",
        "docs/d/evidence/D_detection_v2_protocol.json",
    }
    pin["source_sha256"] = {}
    for name in required:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = b"# synthetic frozen input\n" if name.endswith(".py") else b"{}\n"
        target.write_bytes(payload)
        pin["source_sha256"][name] = hashlib.sha256(payload).hexdigest()
    if change == "content":
        (tmp_path / "src/camel/detection/candidate_v2.py").write_bytes(b"# changed fixture\n")
    else:
        pin["source_sha256"]["../outside.py"] = "0" * 64
    with pytest.raises(ValueError, match="changed_or_outside"):
        VERIFY_PIN(tmp_path, pin)


@pytest.mark.parametrize("change", ["source", "span", "view"])
def test_forged_evidence_is_rejected(change):
    source = identity_view(
        "source:synthetic", "document", "SYSTEM: demo", TrustLabel(provenance=frozenset({"source:synthetic"}))
    )
    result = detect((source,))
    finding = result.findings[0]
    update = {"source": {"source_id": "source:other"}, "span": {"end": 999}, "view": {"view": "normalized"}}[change]
    forged = finding.model_copy(update={"evidence": finding.evidence.model_copy(update=update)})
    with pytest.raises(ValueError, match="ungrounded"):
        CHECK_EVIDENCE(source, result.model_copy(update={"findings": (forged,)}))
