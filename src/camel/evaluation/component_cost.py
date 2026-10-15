"""D-only timing protocol. Preparation, result checks and hashing are not timed."""

import hashlib
import json
import math
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from camel.evaluation.replay import stable


@dataclass
class Workload:
    name: str
    case_ids: tuple[str, ...]
    invoke: Callable[[int], Any]
    check: Callable[[Any, int], bool]
    scope: str
    includes_io: bool


def percentile(values: list[int], probability: float) -> int:
    """Nearest-rank percentile, declared before measuring; no trimmed outliers."""
    if not values or not 0 < probability <= 1:
        raise ValueError("invalid_percentile_input")
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("invalid_latency")
    return sorted(values)[math.ceil(len(values) * probability) - 1]


def measure(workload: Workload, *, warmup=100, iterations=1000, clock=time.perf_counter_ns) -> dict[str, Any]:
    if any(type(value) is not int or value < 0 for value in (warmup, iterations)) or iterations < 1:
        raise ValueError("invalid_iteration_budget")
    if not workload.case_ids or len(set(workload.case_ids)) != len(workload.case_ids):
        raise ValueError("unique_nonempty_case_ids_required")
    expected = {}
    rows = []
    for phase, count in (("warmup", warmup), ("measured", iterations)):
        for sequence in range(count):
            index = sequence % len(workload.case_ids)
            before = clock() if phase == "measured" else None
            result = workload.invoke(index)
            elapsed = clock() - before if before is not None else None
            if not workload.check(result, index):
                raise ValueError("workload_result_check_failed:" + workload.name)
            identity = hashlib.sha256(
                json.dumps(stable(result), ensure_ascii=False, sort_keys=True).encode()
            ).hexdigest()
            if index in expected and expected[index] != identity:
                raise ValueError("nondeterministic_result:" + workload.name)
            expected[index] = identity
            if elapsed is not None:
                if elapsed < 0:
                    raise ValueError("nonmonotonic_clock")
                rows.append(
                    dict(
                        sequence=sequence, case_id=workload.case_ids[index], elapsed_ns=elapsed, result_sha256=identity
                    )
                )
    values = [row["elapsed_ns"] for row in rows]
    return dict(
        name=workload.name,
        warmup=warmup,
        iterations=iterations,
        case_count=len(workload.case_ids),
        per_case_measured_counts=dict(Counter(row["case_id"] for row in rows)),
        p50_ms=percentile(values, 0.5) / 1e6,
        p95_ms=percentile(values, 0.95) / 1e6,
        max_ms=max(values) / 1e6,
        min_ms=min(values) / 1e6,
        scope=workload.scope,
        includes_io=workload.includes_io,
        result_checks_passed=warmup + iterations,
        deterministic_result_hashes=True,
        raw_samples=rows,
    )
