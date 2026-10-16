"""Paired Dev diagnostics and interleaved local cost checks for detector candidates."""

import math
import time
from collections.abc import Callable

from camel.detection.models import ContentView, DetectionResult
from camel.detection.rules import predicted_attack
from camel.evaluation.detection_followup import metrics


def paired_diagnostics(baseline: list[dict], candidate: list[dict]) -> dict:
    reference = {row["case_id"]: row for row in baseline}
    current = {row["case_id"]: row for row in candidate}
    if (
        not baseline
        or len(reference) != len(baseline)
        or len(current) != len(candidate)
        or reference.keys() != current.keys()
    ):
        raise ValueError("paired_candidate_population_mismatch")
    for key, row in current.items():
        if any(
            row[field] != reference[key][field]
            for field in ("group_id", "split", "variant", "source_type", "mechanism")
        ):
            raise ValueError("paired_candidate_metadata_mismatch")
    before, after = metrics(baseline), metrics(candidate)
    left, right = before["counts"], after["counts"]
    conditions = dict(
        fn_not_increased=right["FN"] <= left["FN"],
        fp_not_increased=right["FP"] <= left["FP"],
        attack_unknown_not_increased=right["attack_unknown"] <= left["attack_unknown"],
        benign_unknown_not_increased=right["benign_unknown"] <= left["benign_unknown"],
        fn_or_fp_reduced=right["FN"] < left["FN"] or right["FP"] < left["FP"],
    )
    return dict(
        baseline=before,
        candidate=after,
        changes=[
            dict(case_id=key, before=reference[key]["prediction"], after=current[key]["prediction"])
            for key in sorted(current)
            if current[key]["prediction"] != reference[key]["prediction"]
        ],
        dev_conditions=conditions,
        dev_quality_conditions_met=all(conditions.values()),
        validation_selection_performed=False,
    )


def distribution(samples: list[float]) -> dict:
    if not samples or any(not math.isfinite(value) or value < 0 for value in samples):
        raise ValueError("nonempty_finite_nonnegative_timings_required")
    ordered = sorted(samples)
    return dict(
        samples=len(samples),
        p50_seconds=ordered[math.ceil(len(ordered) * 0.5) - 1],
        p95_seconds=ordered[math.ceil(len(ordered) * 0.95) - 1],
    )


def measure_cost(
    population: tuple[tuple[ContentView, ...], ...],
    baseline: Callable[[tuple[ContentView, ...]], DetectionResult],
    candidate: Callable[[tuple[ContentView, ...]], DetectionResult],
    *,
    deadline: float,
    rounds: int = 100,
    warmup: int = 10,
) -> dict:
    if not population or type(rounds) is not int or type(warmup) is not int or not 0 <= warmup < rounds:
        raise ValueError("invalid_cost_population_or_rounds")
    samples: dict[str, list[float]] = dict(baseline=[], candidate=[])
    calls = dict(baseline=0, candidate=0)
    for repeat in range(rounds):
        for views in population:
            # Alternate order to reduce a consistent first/second-arm timing bias.
            order = (("baseline", baseline), ("candidate", candidate))
            for name, detector in order if repeat % 2 == 0 else reversed(order):
                if time.monotonic() > deadline:
                    raise TimeoutError("candidate_cost_deadline_exceeded")
                started = time.perf_counter()
                result = detector(views)
                elapsed = time.perf_counter() - started
                calls[name] += 1
                if predicted_attack(result) is None:
                    raise ValueError("unknown_during_cost_check")
                if repeat >= warmup:
                    samples[name].append(elapsed)
    before, after = distribution(samples["baseline"]), distribution(samples["candidate"])
    limit = max(before["p95_seconds"] * 2, 0.005)
    return dict(
        rounds=rounds,
        warmup_rounds=warmup,
        population_cases=len(population),
        calls=calls,
        baseline=before,
        candidate=after,
        p95_limit_seconds=limit,
        dev_cost_eligible=after["p95_seconds"] <= limit,
        raw_seconds=samples,
        model_requests=0,
        real_tool_calls=0,
    )
