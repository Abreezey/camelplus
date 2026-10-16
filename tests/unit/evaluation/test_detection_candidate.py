"""Candidate population alignment, quality tradeoffs and bounded cost checks."""

import time

import pytest

from camel.core import TrustLabel
from camel.detection.models import identity_view
from camel.detection.rules import detect, failed_detection
from camel.evaluation.detection_candidate import distribution, measure_cost, paired_diagnostics


def rows(attack: bool | None = True, benign: bool | None = True):
    return [
        dict(
            case_id="one",
            group_id="g",
            split="dev",
            variant="attack",
            prediction=attack,
            source_type="web",
            mechanism="exfiltration",
        ),
        dict(
            case_id="two",
            group_id="g",
            split="dev",
            variant="benign",
            prediction=benign,
            source_type="web",
            mechanism="exfiltration",
        ),
    ]


def test_only_reducing_fp_can_qualify_without_a_recall_ceiling():
    result = paired_diagnostics(rows(), rows(benign=False))
    assert result["dev_quality_conditions_met"]
    assert not result["validation_selection_performed"]


@pytest.mark.parametrize("candidate", [rows(attack=False, benign=False), rows(attack=None, benign=False), rows()])
def test_new_fn_unknown_or_no_improvement_does_not_qualify(candidate):
    assert not paired_diagnostics(rows(), candidate)["dev_quality_conditions_met"]


def test_different_or_duplicate_populations_are_rejected():
    with pytest.raises(ValueError, match="population"):
        paired_diagnostics(rows(), rows()[:1])
    with pytest.raises(ValueError, match="population"):
        paired_diagnostics(rows(), [rows()[0], rows()[0]])
    bad = rows()
    bad[0]["split"] = "test"
    with pytest.raises(ValueError, match="metadata"):
        paired_diagnostics(rows(), bad)


def test_cost_discards_warmup_and_counts_all_local_calls():
    source = identity_view(
        "source:cost", "document", "ordinary facts", TrustLabel(provenance=frozenset({"source:cost"}))
    )
    result = measure_cost(((source,),), detect, detect, rounds=4, warmup=1, deadline=time.monotonic() + 10)
    assert result["calls"] == dict(baseline=4, candidate=4)
    assert result["baseline"]["samples"] == result["candidate"]["samples"] == 3
    assert result["p95_limit_seconds"] >= 0.005


def test_cost_deadline_and_unknown_fail_explicitly():
    source = identity_view("source:cost", "document", "facts", TrustLabel(provenance=frozenset({"source:cost"})))
    with pytest.raises(TimeoutError):
        measure_cost(((source,),), detect, detect, deadline=time.monotonic() - 1)
    with pytest.raises(ValueError, match="unknown"):
        measure_cost(
            ((source,),), detect, lambda _: failed_detection(("source:cost",), "fault"), deadline=time.monotonic() + 10
        )


@pytest.mark.parametrize("values", [[], [float("nan")], [-1.0], [float("inf")]])
def test_invalid_timings_are_rejected(values):
    with pytest.raises(ValueError):
        distribution(values)
