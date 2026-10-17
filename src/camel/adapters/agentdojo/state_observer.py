"""Model-independent AgentDojo environment-difference observations."""

import hashlib
import json
from typing import Any

from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime

VOLATILE_FIELDS = frozenset({"timestamp", "last_modified"})
MAX_REPORTED_PATHS = 256


def ground_truth_functions(value: Any) -> set[str]:
    """Collect top-level and nested functions from a ground-truth call graph."""
    if isinstance(value, FunctionCall):
        return {value.function} | ground_truth_functions(value.args)
    if isinstance(value, dict):
        return set().union(*(ground_truth_functions(item) for item in value.values()), set())
    if isinstance(value, list | tuple):
        return set().union(*(ground_truth_functions(item) for item in value), set())
    return set()


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "<volatile-time>" if key in VOLATILE_FIELDS else _canonical(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    return value


def canonical_state(environment) -> dict[str, Any]:
    """Serialize state while masking simulator-generated wall-clock fields."""
    return _canonical(environment.model_dump(mode="json", round_trip=True))


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _pointer(parent: str, key: Any) -> str:
    escaped = str(key).replace("~", "~0").replace("/", "~1")
    return parent + "/" + escaped


def _changes(before: Any, after: Any, path: str = "") -> dict[str, str]:
    if type(before) is not type(after):
        return {path or "/": _digest(after)}
    if isinstance(before, dict):
        changes: dict[str, str] = {}
        for key in sorted(set(before) | set(after), key=str):
            child = _pointer(path, key)
            if key not in before:
                changes[child] = _digest(after[key])
            elif key not in after:
                changes[child] = "<deleted>"
            else:
                changes.update(_changes(before[key], after[key], child))
        return changes
    if isinstance(before, list):
        if before == after:
            return {}
        return {path or "/": _digest(after)}
    return {} if before == after else {path or "/": _digest(after)}


def expected_environment(task, prompt: str, initial_environment, tools):
    """Execute only the pinned task ground truth in a disposable environment."""
    expected = initial_environment.model_copy(deep=True)
    GroundTruthPipeline(task).query(prompt, FunctionsRuntime(tools), expected)
    return expected


def observe_environment(initial_environment, expected_environment_value, actual_environment) -> dict[str, Any]:
    """Compare expected and actual mutation sets without consulting task scores."""
    before = canonical_state(initial_environment)
    expected = canonical_state(expected_environment_value)
    actual = canonical_state(actual_environment)
    expected_changes = _changes(before, expected)
    actual_changes = _changes(before, actual)
    extra = sorted(set(actual_changes) - set(expected_changes))
    missing = sorted(set(expected_changes) - set(actual_changes))
    conflicting = sorted(
        path for path in set(expected_changes) & set(actual_changes) if expected_changes[path] != actual_changes[path]
    )

    def bounded(paths: list[str]) -> list[str]:
        return paths[:MAX_REPORTED_PATHS]

    return {
        "source_id": "AGENTDOJO_ENV_DIFF_V1",
        "volatile_fields_masked": sorted(VOLATILE_FIELDS),
        "before_sha256": _digest(before),
        "expected_after_sha256": _digest(expected),
        "actual_after_sha256": _digest(actual),
        "expected_state_changed": bool(expected_changes),
        "actual_state_changed": bool(actual_changes),
        "state_matches_expected": actual == expected,
        "expected_change_count": len(expected_changes),
        "actual_change_count": len(actual_changes),
        "extra_change_count": len(extra),
        "missing_change_count": len(missing),
        "conflicting_change_count": len(conflicting),
        "extra_effect_observed": bool(extra or conflicting),
        "extra_change_paths": bounded(extra),
        "missing_change_paths": bounded(missing),
        "conflicting_change_paths": bounded(conflicting),
        "paths_truncated": any(len(paths) > MAX_REPORTED_PATHS for paths in (extra, missing, conflicting)),
    }
