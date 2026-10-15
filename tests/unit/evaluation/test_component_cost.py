"""Timing boundaries and result checks matter more than mirroring the timer."""

import pytest

from camel.evaluation.component_cost import Workload, measure, percentile


def test_warmup_not_recorded_and_validation_not_timed():
    activity = []

    def clock():
        activity.append("clock")
        return activity.count("clock") * 10

    def call(index):
        activity.append("invoke")
        return {"index": index}

    def check(result, index):
        activity.append("check")
        return result == {"index": index}

    result = measure(Workload("test", ("a", "b"), call, check, "synthetic", False), warmup=1, iterations=3, clock=clock)
    assert activity[:2] == ["invoke", "check"]
    assert activity[2:6] == ["clock", "invoke", "clock", "check"]
    assert [row["elapsed_ns"] for row in result["raw_samples"]] == [10, 10, 10]
    assert result["per_case_measured_counts"] == {"a": 2, "b": 1}


def test_changed_results_are_not_silently_accepted():
    state = iter([1, 2])
    with pytest.raises(ValueError, match="nondeterministic_result"):
        measure(
            Workload("bad", ("a",), lambda index: next(state), lambda result, index: True, "synthetic", False),
            warmup=1,
            iterations=1,
        )


def test_incorrect_result_aborts_instead_of_dropping_sample():
    with pytest.raises(ValueError, match="result_check_failed"):
        measure(
            Workload("bad", ("a",), lambda index: None, lambda result, index: False, "synthetic", False),
            warmup=0,
            iterations=1,
        )


@pytest.mark.parametrize("value", [-1, True, 1.5])
def test_invalid_budgets_refused(value):
    with pytest.raises(ValueError, match="budget"):
        measure(
            Workload("test", ("a",), lambda index: 1, lambda result, index: True, "synthetic", False), iterations=value
        )


def test_nearest_rank_keeps_outliers():
    assert percentile([1, 2, 3, 1000], 0.5) == 2
    assert percentile([1, 2, 3, 1000], 0.95) == 1000


@pytest.mark.parametrize("values,probability", [([], 0.5), ([1], 0), ([True], 0.5), ([-1], 0.5)])
def test_bad_latency_inputs_refused(values, probability):
    with pytest.raises(ValueError):
        percentile(values, probability)
