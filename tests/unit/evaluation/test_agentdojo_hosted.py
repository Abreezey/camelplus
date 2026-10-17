import asyncio
import json
from pathlib import Path
from typing import cast

import httpx
import openai
import pytest
from agentdojo import attacks
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite import get_suite
from agentdojo.types import ChatSystemMessage, text_content_block_from_string
from pydantic_ai.messages import ModelResponse
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.deepseek import DeepSeekProvider
from pydantic_ai.settings import ModelSettings

from camel.adapters.agentdojo.controller import bounded_json
from camel.adapters.agentdojo.deepseek import DeepSeekLLM, DeepSeekStructuredModel
from camel.adapters.agentdojo.hosted import (
    SCREENING_ATTACKS,
    BudgetExceededError,
    RequestBudget,
    deepseek_clients,
    duration_metrics,
    full_episodes,
    planned_episodes,
)
from camel.interpreter.interpreter import MetadataEvalMode
from camel.models import make_tools_pipeline


def test_frozen_smoke_population_has_three_balanced_groups():
    episodes = planned_episodes()
    assert len(episodes) == 33
    assert {episode.group for episode in episodes} == {
        "B0_original_agent",
        "B1_original_camel",
        "B3_ABCD",
    }
    for group in {episode.group for episode in episodes}:
        selected = [episode for episode in episodes if episode.group == group]
        assert [sum(episode.kind == kind for episode in selected) for kind in ("benign", "attack", "goal_control")] == [
            5,
            5,
            1,
        ]


def test_full_population_crosses_every_workspace_user_and_injection_task():
    episodes = full_episodes()
    assert len(episodes) == 1842
    for group in {episode.group for episode in episodes}:
        selected = [episode for episode in episodes if episode.group == group]
        assert [sum(episode.kind == kind for episode in selected) for kind in ("benign", "attack", "goal_control")] == [
            40,
            560,
            14,
        ]


@pytest.mark.parametrize(
    "suite_name,per_group",
    [("workspace", 3414), ("travel", 867), ("banking", 889), ("slack", 656)],
)
def test_full_multisuite_population_crosses_all_six_attack_families(suite_name: str, per_group: int):
    episodes = full_episodes(suite_name, SCREENING_ATTACKS)
    assert len(episodes) == per_group * 3
    for group in {episode.group for episode in episodes}:
        selected = [episode for episode in episodes if episode.group == group]
        assert len(selected) == per_group
        assert {episode.attack_type for episode in selected if episode.kind == "attack"} == set(SCREENING_ATTACKS)
        assert {episode.suite for episode in selected} == {suite_name}


def test_smoke_population_can_screen_multiple_attack_families():
    attacks_to_screen = ("direct", "ignore_previous", "tool_knowledge")
    episodes = [episode for episode in planned_episodes(attacks_to_screen) if episode.group == "B0_original_agent"]
    assert len(episodes) == 21
    assert {episode.attack_type for episode in episodes if episode.kind == "attack"} == set(attacks_to_screen)


def test_hosted_runner_group_selection_rejects_empty_or_duplicate_groups(tmp_path: Path):
    from camel.adapters.agentdojo.hosted import run_smoke

    with pytest.raises(ValueError, match="invalid_or_existing"):
        run_smoke(tmp_path / "empty", api_key="unused", groups=())
    with pytest.raises(ValueError, match="invalid_or_existing"):
        run_smoke(
            tmp_path / "duplicate",
            api_key="unused",
            groups=("B0_original_agent", "B0_original_agent"),
        )
    with pytest.raises(ValueError, match="invalid_or_existing"):
        run_smoke(tmp_path / "unknown", api_key="unused", suite="unknown")
    with pytest.raises(ValueError, match="invalid_or_existing"):
        run_smoke(tmp_path / "nonsmoke", api_key="unused", suite="travel")


def test_duration_metrics_keep_planned_and_measured_denominators():
    rows = [
        {"group": "g", "kind": "benign", "duration_seconds": 1.0},
        {"group": "g", "kind": "benign", "duration_seconds": 3.0},
        {"group": "g", "kind": "attack", "duration_seconds": None},
    ]
    result = duration_metrics(rows)["g"]
    assert result["all"] == {
        "planned": 3,
        "measured": 2,
        "total_seconds": 4.0,
        "p50_seconds": 1.0,
        "p95_seconds": 3.0,
    }
    assert result["attack"]["planned"] == 1 and result["attack"]["measured"] == 0


def test_request_budget_is_durable_no_refund_and_never_persists_key(tmp_path: Path):
    budget = RequestBudget(tmp_path / "budget.json", 2)
    clients = deepseek_clients("test-secret-key", budget)
    clients.close()
    budget.reserve("planner")
    budget.reserve("quarantined")
    with pytest.raises(BudgetExceededError, match="exhausted"):
        budget.reserve("planner")
    budget.finish()
    value = bounded_json(budget.path)
    assert value["status"] == "EXHAUSTED"
    assert value["used_requests"] == 2
    assert value["roles"] == {"planner": 1, "quarantined": 1}
    assert value["refund_policy"] == "NO_REFUNDS"
    assert b"test-secret-key" not in budget.path.read_bytes()


def test_request_budget_refuses_existing_ledger(tmp_path: Path):
    path = tmp_path / "budget.json"
    RequestBudget(path, 1)
    with pytest.raises(ValueError, match="existing"):
        RequestBudget(path, 1)


def test_request_budget_records_abort(tmp_path: Path):
    budget = RequestBudget(tmp_path / "budget.json", 1)
    budget.finish("ABORTED")
    assert bounded_json(budget.path)["status"] == "ABORTED"


def test_deepseek_provider_builds_original_and_camel_pipelines_without_network(tmp_path: Path):
    budget = RequestBudget(tmp_path / "budget.json", 1)
    clients = deepseek_clients("test-secret-key", budget)
    try:
        common = (
            "deepseek:deepseek-flash",
            False,
            "important_instructions",
            "medium",
            None,
            "workspace",
            None,
            MetadataEvalMode.NORMAL,
            None,
        )
        original = make_tools_pipeline(
            common[0],  # type: ignore[arg-type]
            True,
            *common[1:],
            provider_client=clients.sync,
            quarantined_model=clients.quarantined,
        )
        camel = make_tools_pipeline(
            common[0],  # type: ignore[arg-type]
            False,
            *common[1:],
            provider_client=clients.sync,
            quarantined_model=clients.quarantined,
        )
        assert original.name == "deepseek-flash"
        assert camel.name == "deepseek-flash+camel"
        assert attacks.load_attack("important_instructions", get_suite("v1.2", "workspace"), original)
        assert budget.used == 0
    finally:
        clients.close()


def test_deepseek_adapter_preserves_system_role_and_bounds_output():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["messages"] == [{"role": "system", "content": [{"type": "text", "text": "system"}]}]
        assert body["max_tokens"] == 123
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1,
                "model": "deepseek-flash",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    client = openai.OpenAI(
        api_key="test",
        base_url="https://example.invalid",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        llm = DeepSeekLLM(client, "deepseek-flash", max_tokens=123)
        messages = [ChatSystemMessage(role="system", content=[text_content_block_from_string("system")])]
        result = llm.query("", FunctionsRuntime(), messages=messages)
        assert result[3][-1]["content"] == [{"type": "text", "content": "OK"}]
    finally:
        client.close()


def test_deepseek_structured_model_disables_thinking(monkeypatch):
    captured = {}

    async def fake_request(self, messages, model_settings, model_request_parameters):
        captured.update(model_settings)
        return cast(ModelResponse, object())

    monkeypatch.setattr(OpenAIModel, "request", fake_request)
    async_client = openai.AsyncOpenAI(api_key="test", base_url="https://example.invalid")
    model = DeepSeekStructuredModel("deepseek-flash", provider=DeepSeekProvider(openai_client=async_client))
    try:
        result = asyncio.run(
            model.request(
                [],
                cast(ModelSettings, {"temperature": 0}),
                cast(ModelRequestParameters, object()),
            )
        )
        assert result is not None
        assert captured == {"temperature": 0, "extra_body": {"thinking": {"type": "disabled"}}}
    finally:
        asyncio.run(async_client.close())
