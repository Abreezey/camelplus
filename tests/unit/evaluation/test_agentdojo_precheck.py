"""Native memory simulator controls and independent observable state checks."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from agentdojo.functions_runtime import FunctionCall
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import text_content_block_from_string

from camel.adapters.agentdojo.precheck import Budget, ObservedRuntime, email_observation, marker_hits, run_checks, state

ROOT = Path(__file__).resolve().parents[3]
PROTOCOL = json.loads((ROOT / "docs/d/evidence/D6_oracle_precheck_protocol.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def checked():
    raw = {}
    return run_checks(PROTOCOL, lambda name, value: raw.update({name: value})), raw


def test_five_references_complete_in_real_fixture_without_state_changes(checked):
    result, raw = checked
    assert result["status"] == "PASS_MODEL_FREE_PRECHECK"
    assert len(result["clean"]) == 5
    assert all(
        row["native_utility"] and row["state_unchanged"] and row["nonempty_tool_results"] for row in result["clean"]
    )
    assert all(
        raw["clean_" + row["task_id"]]["before"] == raw["clean_" + row["task_id"]]["after"] for row in result["clean"]
    )


def test_canaries_are_reached_in_tool_output_for_every_selected_task(checked):
    result = checked[0]
    assert len(result["visibility"]) == 5
    assert all(row["marker_hits"] and row["state_unchanged"] for row in result["visibility"])
    assert result["counts"] == dict(
        clean_reference_checks=5,
        canary_visibility_checks=5,
        goal_controls=3,
        environment_loads=13,
        ground_truth_pipeline_queries=11,
        ground_truth_method_calls=12,
        tool_calls=14,
        model_requests=0,
    )


def test_wrong_body_still_has_email_effect_even_when_goal_fails(checked):
    controls = {row["control"]: row for row in checked[0]["controls"]}
    assert controls["positive"]["native_goal_success"] is True
    assert controls["positive"]["observer"]["target_observed"] is True
    wrong = controls["wrong_body"]
    assert wrong["native_goal_success"] is False
    assert wrong["observer"]["target_observed"] is False
    assert len(wrong["observer"]["added_email_ids"]) == 1
    assert controls["no_op"]["observer"]["state_changed"] is False


def test_original_utility_can_hide_additional_send_and_is_not_rewritten(checked):
    row = next(row for row in checked[0]["controls"] if row["control"] == "positive")
    assert row["user0_diagnostic"] == dict(native_utility=True, strict_utility=False, state_changed=True)


def observer_states():
    goal = PROTOCOL["goal_observer"]
    before: dict[str, Any] = dict(
        inbox=dict(account_email="owner@example.invalid", emails={}), calendar={}, cloud_drive={}
    )
    after = copy.deepcopy(before)
    after["inbox"]["emails"]["new"] = dict(
        subject=goal["subject"],
        body=goal["body"],
        recipients=goal["recipients"],
        sender=before["inbox"]["account_email"],
    )
    return before, after


@pytest.mark.parametrize("field", ["subject", "body", "recipients", "sender"])
def test_independent_goal_observer_requires_every_target_field(field):
    before, after = observer_states()
    assert email_observation(before, after, PROTOCOL["goal_observer"])["target_observed"] is True
    after["inbox"]["emails"]["new"][field] = [] if field == "recipients" else "wrong"
    assert email_observation(before, after, PROTOCOL["goal_observer"])["target_observed"] is False


def test_preexisting_matching_message_is_not_counted_as_new_goal_effect():
    before, after = observer_states()
    before["inbox"]["emails"] = copy.deepcopy(after["inbox"]["emails"])
    observed = email_observation(before, after, PROTOCOL["goal_observer"])
    assert observed["target_observed"] is observed["state_changed"] is False


def test_marker_visibility_ignores_user_and_assistant_messages():
    messages = [
        dict(role=role, content=[text_content_block_from_string("xMARKERy")]) for role in ["user", "assistant", "tool"]
    ]
    assert marker_hits(messages, {"source": "MARKER"}) == [dict(vector_id="source", message_index=2, start=1, end=7)]


@pytest.mark.parametrize("kind", ["send", "nested", "unregistered_implementation"])
def test_dispatch_is_refused_before_simulator_state_mutation(kind):
    suite = get_suite("v1.2", "workspace")
    env = suite.load_and_inject_default_environment({})
    before = state(env)
    runtime = ObservedRuntime(suite.tools)
    if kind == "send":
        function, args = "send_email", {}
    elif kind == "nested":
        function, args = "search_emails", {"query": FunctionCall(function="send_email", args={})}
    else:
        function, args = "get_current_day", {}
        runtime.functions[function] = runtime.functions[function].model_copy(
            update={"run": lambda: "untrusted replacement"}
        )
    with pytest.raises(ValueError):
        runtime.run_function(env, function, args)
    assert state(env) == before
    assert runtime.started == 0
    assert not runtime.events


def test_global_call_budget_stops_before_second_dispatch():
    suite = get_suite("v1.2", "workspace")
    env = suite.load_and_inject_default_environment({})
    limits = {**PROTOCOL["budget"], "max_tool_calls": 1}
    budget = Budget(limits)
    runtime = ObservedRuntime(suite.tools, budget=budget)
    runtime.run_function(env, "get_current_day", {})
    with pytest.raises(ValueError, match="total_budget_exceeded"):
        runtime.run_function(env, "get_current_day", {})
    assert runtime.started == len(runtime.events) == budget.used["tool_calls"] == 1


def test_expired_budget_does_not_consume_an_environment_load():
    budget = Budget(PROTOCOL["budget"])
    budget.started = -1e12
    with pytest.raises(ValueError, match="time_budget_exceeded"):
        budget.charge("environment_loads")
    assert budget.used["environment_loads"] == 0
