"""Offline preparation must not confuse task/version selection, episodes or ASR."""

import copy
import os
import subprocess
import sys
from pathlib import Path

import pytest

from camel.adapters.agentdojo.catalog import (
    PROPOSED_INJECTIONS,
    PROPOSED_USERS,
    build_draft,
    cli_options,
    episode_counts,
    inspect_installed,
    oracle_direction_probe,
    validate_selection,
)


@pytest.fixture(scope="module")
def catalog():
    return inspect_installed()


def test_actual_registry_package_and_benchmark_versions_are_separate(catalog):
    assert catalog["package_version"] == "0.1.34"
    assert catalog["benchmark_versions"] == ["v1.2", "v1.2.1"]
    assert len(catalog["suites"]["v1.2"]["workspace"]["user_tasks"]) == 40
    assert catalog["license"]["name"] == "MIT"
    validate_selection(catalog, "v1.2", "workspace", PROPOSED_USERS, PROPOSED_INJECTIONS)


def test_task_implementation_changes_even_when_ids_and_counts_match(catalog):
    older = {task["task_id"]: task for task in catalog["suites"]["v1.2"]["workspace"]["injection_tasks"]}
    newer = {task["task_id"]: task for task in catalog["suites"]["v1.2.1"]["workspace"]["injection_tasks"]}
    assert set(older) == set(newer)
    assert older["injection_task_11"]["source_file"] != newer["injection_task_11"]["source_file"]


def test_five_by_five_is_not_five_attack_episodes():
    result = episode_counts(5, 5, 1)
    assert result == dict(benign=5, attacked=25, injection_goal_as_user_preflight=5, total=35)
    assert episode_counts(5, 1, 4)["total"] == 44


@pytest.mark.parametrize("dimension", [True, 0, -1, 1.5])
def test_invalid_episode_dimensions_are_rejected(dimension):
    with pytest.raises(ValueError, match="positive_integer"):
        episode_counts(dimension, 1, 4)


@pytest.mark.parametrize(
    "problem",
    [
        "duplicate_user",
        "duplicate_injection",
        "empty_user",
        "empty_injection",
        "unknown_task",
        "wrong_version",
        "wrong_suite",
    ],
)
def test_ambiguous_or_missing_task_selection_is_rejected(catalog, problem):
    users: list[str] = list(PROPOSED_USERS)
    injections = list(PROPOSED_INJECTIONS)
    version, suite = "v1.2", "workspace"
    if problem == "duplicate_user":
        users.append(users[0])
    elif problem == "duplicate_injection":
        injections.append(injections[0])
    elif problem == "empty_user":
        users = []
    elif problem == "empty_injection":
        injections = []
    elif problem == "unknown_task":
        users[0] = "user_task_999999"
    elif problem == "wrong_version":
        version = "0.1.34"
    else:
        suite = "not_a_suite"
    with pytest.raises(ValueError):
        validate_selection(catalog, version, suite, users, injections)


def test_proposal_never_creates_approval_or_invents_model_budget(catalog):
    original = copy.deepcopy(catalog)
    draft = build_draft(catalog)
    assert catalog == original
    assert draft["ready"] is draft["execution_enabled"] is False
    assert draft["new_requests_authorized"] == 0
    assert draft["model"] is draft["request_budget"] is draft["monetary_cap"] is None
    assert len(draft["attacked_pairs"]) == 5
    assert all(not group["ready"] for group in draft["groups"])


def test_real_predicate_true_means_attacker_goal_success_not_safety():
    result = oracle_direction_probe()
    assert result["injection_goal_achieved"] is True
    assert result["goal_not_achieved"] is result["empty_post_state"] is False
    assert (
        result["benchmark_episodes"]
        == result["environment_loads"]
        == result["tool_calls"]
        == result["model_requests"]
        == 0
    )


def test_cli_inspection_does_not_execute_source():
    source = (
        "raise RuntimeError('must not execute')\n@click.option('--user-task', '-ut', multiple=True)\ndef main(): pass"
    )
    assert cli_options(source) == ["--user-task"]


def test_preparation_cli_does_not_offer_an_execution_switch(tmp_path):
    root = Path(__file__).resolve().parents[3]
    environment = dict(os.environ, PYTHONPATH=str(root / "src"), PYTHONDONTWRITEBYTECODE="1")
    output = tmp_path / "not_created"
    result = subprocess.run(
        [sys.executable, str(root / "scripts/d6_prepare.py"), "--output", str(output), "--run"],
        cwd=root,
        env=environment,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 2
    assert b"unrecognized arguments: --run" in result.stderr
    assert not output.exists()
