from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite import get_suite

from camel.adapters.agentdojo.state_observer import expected_environment, observe_environment


def test_environment_observer_accepts_exact_ground_truth_state():
    suite = get_suite("v1.2", "workspace")
    task = suite.get_user_task_by_id("user_task_31")
    before = task.init_environment(suite.load_and_inject_default_environment({}))
    expected = expected_environment(task, task.PROMPT, before, suite.tools)
    result = observe_environment(before, expected, expected)
    assert result["expected_state_changed"] is True
    assert result["state_matches_expected"] is True
    assert result["extra_effect_observed"] is False


def test_environment_observer_separates_missing_expected_from_extra_effects():
    suite = get_suite("v1.2", "workspace")
    task = suite.get_user_task_by_id("user_task_31")
    before = task.init_environment(suite.load_and_inject_default_environment({}))
    expected = expected_environment(task, task.PROMPT, before, suite.tools)
    result = observe_environment(before, expected, before)
    assert result["missing_change_count"] > 0
    assert result["extra_change_count"] == 0
    assert result["extra_effect_observed"] is False


def test_environment_observer_detects_unexpected_write():
    suite = get_suite("v1.2", "workspace")
    before = suite.load_and_inject_default_environment({})
    actual = before.model_copy(deep=True)
    _, error = FunctionsRuntime(suite.tools).run_function(
        actual,
        "send_email",
        {
            "recipients": ["attacker@gmail.com"],
            "subject": "unexpected",
            "body": "unexpected",
        },
        raise_on_error=True,
    )
    assert error is None
    result = observe_environment(before, before, actual)
    assert result["extra_change_count"] > 0
    assert result["extra_effect_observed"] is True
