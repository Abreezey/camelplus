"""Dispatch admission, durable state and actual inert process termination."""

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from camel.adapters.agentdojo.controller import (
    Call,
    Controller,
    Job,
    Limits,
    Quota,
    bounded_json,
    effect_observation,
    reservation,
    valid_usage,
    write_json,
)
from camel.adapters.agentdojo.results import Episode, aggregate

ROOT = Path(__file__).resolve().parents[3]


def call(**changes):
    fields: dict[str, Any] = dict(role="planner", input_tokens=3, max_output_tokens=2, max_cost_units=1)
    fields.update(changes)
    return Call.model_validate(fields)


def job(index=0, case="complete", calls=None):
    spec = Episode(
        episode_id=f"episode_{index}",
        group="test",
        pipeline_name="synthetic-controller",
        kind="attack",
        user_task_id=f"user_task_{index}",
        injection_task_id="injection_task_0",
        attack_type="important_instructions",
    )
    return Job.model_validate(
        dict(episode=spec.model_dump(), case=case, calls=[c.model_dump() for c in (calls or [call()])])
    )


def limits(**changes):
    quota = dict(requests=10, input_tokens=100, output_tokens=100, cost_units=100)
    fields: dict[str, Any] = dict(
        total=quota,
        roles={role: quota.copy() for role in ["planner", "quarantined", "detector", "embedding"]},
        max_episodes=10,
        total_seconds=20.0,
        episode_seconds=3.0,
        stop_grace_seconds=0.1,
    )
    fields.update(changes)
    return Limits.model_validate(fields)


def usage(**changes):
    value = dict(call_index=0, role="planner", input_tokens=3, output_tokens=2, cost_units=1)
    value.update(changes)
    return [value]


@pytest.fixture(scope="module")
def actual(tmp_path_factory):
    root = tmp_path_factory.mktemp("actual_controller")
    cases = ["complete", "goal", "native_error", "tool_error", "crash", "effect_timeout"]
    instance = Controller(root / "run", [job(i, case) for i, case in enumerate(cases)], limits(episode_seconds=1.5))
    return instance, instance.run()


def test_actual_worker_results_keep_native_errors_and_conservative_tool_policy(actual):
    instance, rows = actual
    assert [row["status"] for row in rows] == [
        "COMPLETED",
        "COMPLETED",
        "NATIVE_ERROR",
        "TOOL_ERROR",
        "ABORTED",
        "TIMEOUT",
    ]
    assert rows[3]["native_security"] is True and rows[3]["scored_attack_goal"] is None
    assert rows[2]["native_error_sha256"] and rows[2]["scored_attack_goal"] is None
    assert instance.used["total"]["requests"] == 6


def test_actual_timeout_stops_process_but_keeps_observed_effect(actual):
    instance, rows = actual
    assert all(state["worker_stopped"] for state in instance.states)
    assert all(state["exit_code"] is not None for state in instance.states)
    timed = rows[-1]
    assert timed["status"] == "TIMEOUT" and timed["independent"]["extra_effect_observed"] is True
    assert timed["independent"]["final"] is False
    assert aggregate(rows)["test"]["attack_extra_effect_positives"] == 2


def test_actual_host_cancel_stops_current_and_preserves_remaining_plan(tmp_path):
    instance = Controller(tmp_path / "run", [job(0, "cancel"), job(1)], limits())
    rows = instance.run(lambda index, directory: (directory / "ready.json").exists())
    assert [row["status"] for row in rows] == ["ABORTED", "NOT_RUN"]
    assert rows[0]["host_reason"] == rows[1]["host_reason"] == "host_cancelled"
    assert instance.states[0]["worker_stopped"] and instance.used["total"]["requests"] == 1
    assert not (instance.root / "episode_001/request.json").exists()


@pytest.mark.parametrize("case", ["bad_usage", "missing_usage"])
def test_unverified_usage_aborts_before_dispatching_remaining_episode(tmp_path, case):
    instance = Controller(tmp_path / "run", [job(0, case), job(1)], limits())
    rows = instance.run()
    assert [row["status"] for row in rows] == ["ABORTED", "NOT_RUN"]
    assert rows[0]["native_utility"] is True and rows[0]["scored_utility"] is None
    assert rows[0]["host_reason"] == "unverified_or_excess_usage"
    assert instance.used["total"] == dict(requests=1, input_tokens=3, output_tokens=2, cost_units=1)


@pytest.mark.parametrize(
    "resource,cap", [("requests", 0), ("input_tokens", 2), ("output_tokens", 1), ("cost_units", 0)]
)
def test_global_caps_deny_before_process_launch_or_reservation(tmp_path, monkeypatch, resource, cap):
    quota = dict(requests=10, input_tokens=100, output_tokens=100, cost_units=100)
    quota[resource] = cap
    instance = Controller(tmp_path / "run", [job()], limits(total=quota))

    def unexpected(*args, **kwargs):
        pytest.fail("process launched after budget denial")

    monkeypatch.setattr("camel.adapters.agentdojo.controller.subprocess.Popen", unexpected)
    rows = instance.run()
    assert rows[0]["status"] == "NOT_RUN"
    assert instance.used["total"]["requests"] == 0
    assert aggregate(rows)["test"]["attack_goal"]["unknown"] == 1


def test_all_role_calls_are_reserved_together_and_role_denial_has_no_partial_charge(tmp_path):
    calls = [call(role=role) for role in ["planner", "quarantined", "detector", "embedding"]]
    instance = Controller(tmp_path / "run", [job(calls=calls)], limits())
    assert instance.admit(0) is None
    assert instance.used["total"] == dict(requests=4, input_tokens=12, output_tokens=8, cost_units=4)
    assert all(value["requests"] == 1 for value in instance.used["roles"].values())
    with pytest.raises(ValueError, match="already_admitted"):
        instance.admit(0)
    role_limits = limits().model_dump()["roles"]
    role_limits["detector"]["requests"] = 0
    denied = Controller(tmp_path / "denied", [job(calls=calls)], limits(roles=role_limits))
    assert denied.admit(0) == "budget_exhausted:detector"
    assert denied.used["total"]["requests"] == 0
    assert all(value["requests"] == 0 for value in denied.used["roles"].values())


def test_missing_role_is_denied_without_silently_using_global_allowance(tmp_path):
    instance = Controller(tmp_path / "run", [job(calls=[call(role="embedding")])], limits(roles={}))
    assert instance.run()[0]["status"] == "NOT_RUN"
    assert instance.states[0]["reason"] == "unconfigured_role:embedding"


def test_durable_reservation_and_complete_plan_exist_before_launch(tmp_path, monkeypatch):
    instance = Controller(tmp_path / "run", [job()], limits())

    def failed_launch(*args, **kwargs):
        ledger = bounded_json(instance.root / "ledger.json")
        assert ledger["episodes"][0]["state"] == "RUNNING"
        assert ledger["episodes"][0]["reservation"]["total"]["requests"] == 1
        assert [event["state"] for event in ledger["events"]] == ["RESERVED", "RUNNING"]
        raise OSError("SYNTHETIC LAUNCH FAILURE")

    monkeypatch.setattr("camel.adapters.agentdojo.controller.subprocess.Popen", failed_launch)
    assert instance.run()[0]["status"] == "ABORTED"
    assert instance.used["total"]["requests"] == 1
    assert instance.states[0]["reason"] == "launch_error"


def test_persistence_failure_prevents_launch(tmp_path, monkeypatch):
    instance = Controller(tmp_path / "run", [job()], limits())

    def failed_save():
        raise OSError("SYNTHETIC DISK ERROR")

    def unexpected(*args, **kwargs):
        pytest.fail("process launched without durable reservation")

    monkeypatch.setattr(instance, "save", failed_save)
    monkeypatch.setattr("camel.adapters.agentdojo.controller.subprocess.Popen", unexpected)
    with pytest.raises(OSError, match="DISK"):
        instance.run()
    assert not (instance.root / "episode_000/request.json").exists()


@pytest.mark.parametrize("trigger", ["deadline", "cancel"])
def test_admission_is_rechecked_after_slow_persistence_before_launch(tmp_path, monkeypatch, trigger):
    clock = [0.0]
    cancelled = [False]
    monkeypatch.setattr("camel.adapters.agentdojo.controller.time.monotonic", lambda: clock[0])
    instance = Controller(tmp_path / "run", [job()], limits(episode_seconds=1.0))
    original = instance.transition

    def slow_transition(index, state, reason=None, **details):
        original(index, state, reason, **details)
        if state == "RUNNING":
            if trigger == "deadline":
                clock[0] = 2.0
            else:
                cancelled[0] = True

    def unexpected(*args, **kwargs):
        pytest.fail("late dispatch occurred after deadline/cancellation")

    monkeypatch.setattr(instance, "transition", slow_transition)
    monkeypatch.setattr("camel.adapters.agentdojo.controller.subprocess.Popen", unexpected)
    rows = instance.run(lambda index, directory: cancelled[0])
    assert rows[0]["status"] == "NOT_RUN"
    assert instance.used["total"]["requests"] == 1
    assert rows[0]["host_reason"] == ("deadline_before_launch" if trigger == "deadline" else "host_cancelled")


def test_expired_total_deadline_leaves_all_planned_episodes_unrun(tmp_path):
    instance = Controller(tmp_path / "run", [job(0), job(1)], limits())
    instance.started -= 21
    rows = instance.run()
    assert [row["status"] for row in rows] == ["NOT_RUN", "NOT_RUN"]
    assert all(row["host_reason"] == "total_wall_deadline" for row in rows)
    assert instance.used["total"]["requests"] == 0
    assert len(bounded_json(instance.root / "ledger.json")["episodes"]) == 2


def test_controller_cannot_retry_or_reuse_directory(actual, tmp_path):
    instance, _ = actual
    with pytest.raises(ValueError, match="retry"):
        instance.run()
    with pytest.raises(FileExistsError):
        Controller(instance.root, [job()], limits())
    with pytest.raises(ValueError, match="duplicate"):
        Controller(tmp_path / "not_created", [job(), job()], limits())
    assert not (tmp_path / "not_created").exists()


@pytest.mark.parametrize(
    "changes", [dict(role="unknown"), dict(input_tokens=True), dict(max_output_tokens=-1), dict(max_cost_units=1.5)]
)
def test_reservations_reject_unknown_roles_or_coerced_quantities(changes):
    with pytest.raises(ValidationError):
        call(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        dict(input_tokens=4),
        dict(output_tokens=3),
        dict(cost_units=2),
        dict(call_index=1),
        dict(role="detector"),
        dict(output_tokens=True),
    ],
)
def test_usage_must_match_role_identity_and_every_reserved_ceiling(changes):
    with pytest.raises(ValueError):
        valid_usage(job(), usage(**changes))
    assert valid_usage(job(), usage())[0]["role"] == "planner"


def test_missing_extra_or_duplicate_usage_is_not_silently_accepted():
    for value in [[], usage() * 2, {}, None]:
        with pytest.raises(ValueError):
            valid_usage(job(), value)
    assert reservation([call(), call(role="detector")])["total"]["requests"] == 2


def test_side_effect_observer_is_bound_to_episode_and_not_native_score(tmp_path):
    path = tmp_path / "state.json"
    write_json(path, dict(episode_id="episode_1", synthetic_goal=True, extra_effect=True))
    assert effect_observation(path, job().episode, final=False) is None
    value = effect_observation(path, job(1).episode, final=False)
    assert value is not None and value.goal_achieved is True and value.final is False
    path.write_text('{"synthetic_goal":true,"synthetic_goal":false}', encoding="utf-8")
    assert effect_observation(path, job().episode, final=True) is None


def test_json_persistence_is_complete_and_bounded(tmp_path):
    path = tmp_path / "ledger.json"
    write_json(path, dict(state="PLANNED"))
    write_json(path, dict(state="ABORTED"))
    assert json.loads(path.read_bytes()) == dict(state="ABORTED")
    assert not path.with_suffix(".tmp").exists()
    with pytest.raises(ValueError, match="too_large"):
        bounded_json(path, 3)


def test_plan_count_limit_and_duration_limits_are_strict(tmp_path):
    with pytest.raises(ValueError, match="episode_limit"):
        Controller(tmp_path / "run", [job(0), job(1)], limits(max_episodes=1))
    assert not (tmp_path / "run").exists()
    with pytest.raises(ValidationError):
        limits(total_seconds=float("inf"))
    with pytest.raises(ValidationError):
        Quota.model_validate(dict(requests=True, input_tokens=1, output_tokens=1, cost_units=1))


def test_formal_control_script_uses_fixed_offline_plan():
    spec = importlib.util.spec_from_file_location("d6_controller_tests", ROOT / "scripts/d6_controller.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.job(0, calls=[module.call("embedding")]).calls[0].role == "embedding"
    assert module.limits().total.requests == 100
