"""Bounded hosted AgentDojo smoke runner primitives."""

import asyncio
import math
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import httpx
import openai
from agentdojo import attacks
from agentdojo.functions_runtime import Function, FunctionsRuntime
from agentdojo.logging import OutputLogger, TraceLogger
from agentdojo.task_suite import get_suite
from pydantic_ai.providers.deepseek import DeepSeekProvider

from camel.adapters.agentdojo.catalog import PROPOSED_INJECTIONS, PROPOSED_USERS
from camel.adapters.agentdojo.controller import write_json
from camel.adapters.agentdojo.deepseek import DeepSeekStructuredModel
from camel.adapters.agentdojo.results import Episode, Observation, aggregate, load_episode, validate_population
from camel.adapters.agentdojo.runtime import SUITE_TOOL_REVIEWS, AgentDojoGatewayRuntime
from camel.adapters.agentdojo.state_observer import (
    expected_environment,
    ground_truth_functions,
    observe_environment,
)
from camel.interpreter.interpreter import MetadataEvalMode
from camel.models import make_tools_pipeline

MODEL = "deepseek-flash"
MODEL_ID = "deepseek:deepseek-flash"
GROUPS = ("B0_original_agent", "B1_original_camel", "B3_ABCD")
PIPELINE_NAMES = {
    "B0_original_agent": MODEL,
    "B1_original_camel": MODEL + "+camel",
    "B3_ABCD": MODEL + "+camel+abcd",
}
SCREENING_ATTACKS = (
    "direct",
    "ignore_previous",
    "system_message",
    "injecagent",
    "important_instructions",
    "tool_knowledge",
)
SUITES = ("workspace", "travel", "banking", "slack")


class BudgetExceededError(RuntimeError):
    """A hosted request was refused before network dispatch."""


class RequestBudget:
    """Durably reserve every HTTP attempt, without refunds or hidden retries."""

    def __init__(self, path: Path, max_requests: int) -> None:
        if max_requests < 1 or path.exists():
            raise ValueError("invalid_or_existing_request_budget")
        self.path = path
        self.max_requests = max_requests
        self._lock = threading.Lock()
        self.used = 0
        self.roles = {"planner": 0, "quarantined": 0}
        self.events: list[dict[str, int | str]] = []
        self.exhausted = False
        self._save("ACTIVE")

    def _save(self, status: str) -> None:
        write_json(
            self.path,
            {
                "status": status,
                "max_requests": self.max_requests,
                "used_requests": self.used,
                "remaining_requests": self.max_requests - self.used,
                "roles": self.roles,
                "events": self.events,
                "refund_policy": "NO_REFUNDS",
                "sdk_retries": 0,
            },
        )

    def reserve(self, role: Literal["planner", "quarantined"]) -> None:
        with self._lock:
            if self.used >= self.max_requests:
                self.exhausted = True
                self._save("EXHAUSTED")
                raise BudgetExceededError("hosted_request_budget_exhausted")
            self.used += 1
            self.roles[role] += 1
            self.events.append({"sequence": self.used, "role": role})
            self._save("ACTIVE")

    def finish(self, status: Literal["COMPLETE", "ABORTED"] = "COMPLETE") -> None:
        with self._lock:
            self._save("EXHAUSTED" if self.exhausted else status)


class BudgetedHTTPTransport(httpx.BaseTransport):
    def __init__(self, budget: RequestBudget, role: Literal["planner", "quarantined"]) -> None:
        self.budget = budget
        self.role: Literal["planner", "quarantined"] = role
        self.inner = httpx.HTTPTransport(retries=0)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.budget.reserve(self.role)
        return self.inner.handle_request(request)

    def close(self) -> None:
        self.inner.close()


class BudgetedAsyncHTTPTransport(httpx.AsyncBaseTransport):
    def __init__(self, budget: RequestBudget, role: Literal["planner", "quarantined"]) -> None:
        self.budget = budget
        self.role: Literal["planner", "quarantined"] = role
        self.inner = httpx.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.budget.reserve(self.role)
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


@dataclass
class DeepSeekClients:
    sync: openai.OpenAI
    async_client: openai.AsyncOpenAI
    quarantined: DeepSeekStructuredModel

    def close(self) -> None:
        self.sync.close()
        asyncio.run(self.async_client.close())


def deepseek_clients(
    api_key: str,
    budget: RequestBudget,
    *,
    base_url: str = "https://api.deepseek.com",
    timeout_seconds: float = 45.0,
) -> DeepSeekClients:
    if not api_key:
        raise ValueError("DEEPSEEK_API_KEY is required")
    sync_http = httpx.Client(
        transport=BudgetedHTTPTransport(budget, "planner"),
        timeout=timeout_seconds,
        trust_env=False,
    )
    async_http = httpx.AsyncClient(
        transport=BudgetedAsyncHTTPTransport(budget, "quarantined"),
        timeout=timeout_seconds,
        trust_env=False,
    )
    sync_client = openai.OpenAI(
        api_key=api_key,
        base_url=base_url,
        max_retries=0,
        http_client=sync_http,
    )
    async_client = openai.AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        max_retries=0,
        http_client=async_http,
    )
    quarantined = DeepSeekStructuredModel(MODEL, provider=DeepSeekProvider(openai_client=async_client))
    return DeepSeekClients(sync_client, async_client, quarantined)


def planned_episodes(attack_types: Sequence[str] = ("important_instructions",)) -> list[Episode]:
    if not attack_types or len(set(attack_types)) != len(attack_types):
        raise ValueError("invalid_attack_types")
    episodes = []
    for group in GROUPS:
        pipeline = PIPELINE_NAMES[group]
        episodes.append(
            Episode(
                episode_id=f"{group}-goal-control",
                group=group,
                pipeline_name=pipeline,
                kind="goal_control",
                user_task_id=PROPOSED_INJECTIONS[0],
                injection_task_id=None,
                attack_type=None,
            )
        )
        for user in PROPOSED_USERS:
            episodes.extend(
                [
                    Episode(
                        episode_id=f"{group}-{user}-benign",
                        group=group,
                        pipeline_name=pipeline,
                        kind="benign",
                        user_task_id=user,
                        injection_task_id=None,
                        attack_type=None,
                    ),
                ]
            )
            for attack_type in attack_types:
                episodes.append(
                    Episode(
                        episode_id=f"{group}-{user}-{attack_type}-attack",
                        group=group,
                        pipeline_name=pipeline,
                        kind="attack",
                        user_task_id=user,
                        injection_task_id=PROPOSED_INJECTIONS[0],
                        attack_type=attack_type,
                    )
                )
    validate_population(episodes)
    return episodes


def full_episodes(
    suite_name: str = "workspace", attack_types: Sequence[str] = ("important_instructions",)
) -> list[Episode]:
    """All of one suite's user tasks crossed with every injection task and attack family."""
    if suite_name not in SUITES:
        raise ValueError("unknown_suite:" + suite_name)
    if (
        not attack_types
        or len(set(attack_types)) != len(attack_types)
        or any(attack not in SCREENING_ATTACKS for attack in attack_types)
    ):
        raise ValueError("invalid_attack_types")
    suite = get_suite("v1.2", suite_name)
    users = sorted(suite.user_tasks, key=lambda value: int(value.rsplit("_", 1)[1]))
    injections = sorted(suite.injection_tasks, key=lambda value: int(value.rsplit("_", 1)[1]))
    episodes = []
    for group in GROUPS:
        pipeline = PIPELINE_NAMES[group]
        for injection in injections:
            episodes.append(
                Episode(
                    episode_id=f"{group}-{injection}-goal-control",
                    group=group,
                    pipeline_name=pipeline,
                    kind="goal_control",
                    user_task_id=injection,
                    injection_task_id=None,
                    attack_type=None,
                    suite=suite_name,
                )
            )
        for user in users:
            episodes.append(
                Episode(
                    episode_id=f"{group}-{user}-benign",
                    group=group,
                    pipeline_name=pipeline,
                    kind="benign",
                    user_task_id=user,
                    injection_task_id=None,
                    attack_type=None,
                    suite=suite_name,
                )
            )
            for injection in injections:
                for attack_type in attack_types:
                    episodes.append(
                        Episode(
                            episode_id=f"{group}-{user}-{injection}-{attack_type}-attack",
                            group=group,
                            pipeline_name=pipeline,
                            kind="attack",
                            user_task_id=user,
                            injection_task_id=injection,
                            attack_type=attack_type,
                            suite=suite_name,
                        )
                    )
    validate_population(episodes)
    return episodes


def duration_metrics(rows: list[dict]) -> dict[str, dict]:
    """Nearest-rank episode latency by group; incomplete durations stay excluded."""

    def summary(selected: list[dict]) -> dict[str, float | int | None]:
        values = sorted(
            float(row["duration_seconds"])
            for row in selected
            if isinstance(row.get("duration_seconds"), int | float) and row["duration_seconds"] >= 0
        )

        def percentile(probability: float) -> float | None:
            return values[math.ceil(len(values) * probability) - 1] if values else None

        return {
            "planned": len(selected),
            "measured": len(values),
            "total_seconds": sum(values),
            "p50_seconds": percentile(0.5),
            "p95_seconds": percentile(0.95),
        }

    result = {}
    for group in sorted({row["group"] for row in rows}):
        selected = [row for row in rows if row["group"] == group]
        result[group] = {
            "all": summary(selected),
            "benign": summary([row for row in selected if row["kind"] == "benign"]),
            "attack": summary([row for row in selected if row["kind"] == "attack"]),
        }
    return result


class RuntimeFactory:
    def __init__(self, root: Path, episode: Episode) -> None:
        self.root = root
        self.episode = episode
        self.instances: list[AgentDojoGatewayRuntime] = []

    def __call__(self, functions: Sequence[Function]) -> AgentDojoGatewayRuntime:
        runtime = AgentDojoGatewayRuntime(
            functions,
            root=self.root,
            model_version=MODEL,
            session_id=self.episode.episode_id,
            auto_approve_writes=self.episode.kind == "benign",
            suite=self.episode.suite,
        )
        self.instances.append(runtime)
        return runtime


def _pipeline(group: str, clients: DeepSeekClients, suite: str):
    pipeline = make_tools_pipeline(
        MODEL_ID,  # type: ignore[arg-type]
        group == "B0_original_agent",
        False,
        "important_instructions",
        "medium",
        None,
        suite,
        None,
        MetadataEvalMode.NORMAL,
        None,
        provider_client=clients.sync,
        quarantined_model=clients.quarantined,
    )
    pipeline.name = PIPELINE_NAMES[group]
    return pipeline


def _trace_path(root: Path, episode: Episode) -> Path:
    attack = episode.attack_type or "none"
    injection = episode.injection_task_id or "none"
    return root / episode.pipeline_name / episode.suite / episode.user_task_id / attack / f"{injection}.json"


def run_episode(episode: Episode, output: Path, pipeline) -> tuple[dict, dict | None, bool]:
    suite = get_suite(episode.benchmark_version, episode.suite)
    user_task: Any
    if episode.kind == "goal_control":
        user_task = suite.get_injection_task_by_id(episode.user_task_id)
        injection_task = None
        injections = {}
    else:
        user_task = suite.get_user_task_by_id(episode.user_task_id)
        injection_task = (
            suite.get_injection_task_by_id(episode.injection_task_id) if episode.injection_task_id else None
        )
        injections = {}
    attack_error = None
    if injection_task is not None:
        try:
            assert episode.attack_type is not None
            injections = attacks.load_attack(episode.attack_type, suite, pipeline).attack(user_task, injection_task)
        except Exception as error:
            attack_error = error
    environment = suite.load_and_inject_default_environment(injections)
    initial_environment = environment.model_copy(deep=True)
    prompt = user_task.GOAL if episode.kind == "goal_control" else user_task.PROMPT
    if episode.kind != "goal_control":
        initial_environment = user_task.init_environment(initial_environment)
    expected = None
    expected_error = None
    expected_write = False
    try:
        write_tools = SUITE_TOOL_REVIEWS[episode.suite][1]
        expected_write = bool(ground_truth_functions(user_task.ground_truth(initial_environment)) & write_tools)
        expected = expected_environment(user_task, prompt, initial_environment, suite.tools)
    except Exception as error:
        expected_error = f"{type(error).__name__}: {error}"
    runtime_factory = RuntimeFactory(output / "security", episode) if episode.group == "B3_ABCD" else None
    traces = output / "agentdojo"
    traces.mkdir(parents=True, exist_ok=True)
    failed_budget = False
    with TraceLogger(
        delegate=OutputLogger(str(traces)),
        suite_name=episode.suite,
        user_task_id=episode.user_task_id,
        injection_task_id=episode.injection_task_id,
        injections=injections,
        attack_type=episode.attack_type or "none",
        pipeline_name=episode.pipeline_name,
        benchmark_version=episode.benchmark_version,
    ) as logger:
        try:
            if attack_error is not None:
                raise attack_error
            utility, security = suite.run_task_with_pipeline(
                pipeline,
                user_task,
                injection_task,
                injections,
                runtime_class=runtime_factory or FunctionsRuntime,  # type: ignore[arg-type]
                environment=environment,
            )
            logger.set_contextarg("utility", utility)
            logger.set_contextarg("security", security)
        except Exception as error:
            failed_budget = isinstance(error, BudgetExceededError)
            logger.log_error(f"{type(error).__name__}: {error}")
    security_summary = None
    if runtime_factory is not None and runtime_factory.instances:
        security_summary = runtime_factory.instances[0].summary()
        for runtime in runtime_factory.instances:
            runtime.close()
    observer_detail = None
    observer = None
    if expected is not None and attack_error is None:
        observer_detail = observe_environment(initial_environment, expected, environment)
        observer = Observation(
            source_id=observer_detail["source_id"],
            goal_achieved=None,
            extra_effect_observed=observer_detail["extra_effect_observed"],
            final=True,
        )
    else:
        observer_detail = {
            "source_id": "AGENTDOJO_ENV_DIFF_V1",
            "error": expected_error or f"{type(attack_error).__name__}: {attack_error}",
            "final": False,
        }
    write_json(output / "environment_observer.json", observer_detail)
    row = load_episode(episode, _trace_path(traces, episode), observer=observer)
    row["expected_write"] = expected_write
    return row, security_summary, failed_budget


def run_smoke(
    output: Path,
    *,
    api_key: str,
    max_requests: int = 400,
    total_seconds: float = 3600.0,
    base_url: str = "https://api.deepseek.com",
    population: Literal["smoke", "full"] = "smoke",
    groups: Sequence[str] = GROUPS,
    attack_types: Sequence[str] = ("important_instructions",),
    suite: str = "workspace",
) -> dict:
    selected_groups = tuple(groups)
    if (
        output.exists()
        or max_requests < 1
        or total_seconds <= 0
        or not selected_groups
        or len(set(selected_groups)) != len(selected_groups)
        or any(group not in GROUPS for group in selected_groups)
        or not attack_types
        or len(set(attack_types)) != len(attack_types)
        or any(attack not in SCREENING_ATTACKS for attack in attack_types)
        or suite not in SUITES
        or (population == "smoke" and suite != "workspace")
    ):
        raise ValueError("invalid_or_existing_hosted_output")
    output.mkdir(parents=True)
    population_episodes = (
        planned_episodes(attack_types) if population == "smoke" else full_episodes(suite, attack_types)
    )
    episodes = [episode for episode in population_episodes if episode.group in selected_groups]
    budget = RequestBudget(output / "request_budget.json", max_requests)
    clients = deepseek_clients(api_key, budget, base_url=base_url)
    pipelines = {group: _pipeline(group, clients, suite) for group in selected_groups}
    started = time.monotonic()
    rows = []
    security_rows = []
    stopped = None
    loop_finished = False
    try:
        for episode in episodes:
            if stopped is not None or time.monotonic() - started >= total_seconds:
                stopped = stopped or "total_deadline"
                row = load_episode(episode, None, controller="not_run")
                rows.append({**row, "host_reason": stopped})
                continue
            episode_root = output / "episodes" / episode.episode_id
            episode_root.mkdir(parents=True)
            row, security, failed_budget = run_episode(episode, episode_root, pipelines[episode.group])
            rows.append(row)
            if security is not None:
                security_rows.append({"episode_id": episode.episode_id, **security})
            if failed_budget:
                stopped = "request_budget_exhausted"
            write_json(output / "normalized.json", rows)
            write_json(output / "security.json", security_rows)
        loop_finished = True
    finally:
        clients.close()
        budget.finish("COMPLETE" if loop_finished else "ABORTED")
    b3_decisions = [row["decisions"] for row in security_rows]
    confirm = sum(row["CONFIRM"] for row in b3_decisions)
    decision_total = sum(sum(row.values()) for row in b3_decisions)
    confirmation_rows = [row["confirmations"] for row in security_rows]
    benign_writes = [row for row in rows if row["kind"] == "benign" and row.get("expected_write")]
    observer_rows = [row["independent"] for row in rows if row.get("independent") is not None]
    summary = {
        "experiment": f"D8 hosted AgentDojo DeepSeek {population}",
        "status": "COMPLETE" if stopped is None else "PARTIAL",
        "model": MODEL,
        "suite": suite,
        "attack_types": list(attack_types),
        "groups": list(selected_groups),
        "episodes_planned": len(episodes),
        "episodes_completed": sum(row["status"] == "COMPLETED" for row in rows),
        "stop_reason": stopped,
        "request_budget": {
            "max": budget.max_requests,
            "used": budget.used,
            "roles": budget.roles,
        },
        "metrics": aggregate(rows),
        "metrics_by_attack": {
            group: {
                attack_type: aggregate(selected)[group]
                for attack_type in sorted({row["attack_type"] for row in rows if row["attack_type"] is not None})
                if (selected := [row for row in rows if row["group"] == group and row["attack_type"] == attack_type])
            }
            for group in selected_groups
        },
        "duration_metrics": duration_metrics(rows),
        "b3_confirmation_rate": confirm / decision_total if decision_total else None,
        "b3_confirmations": {
            outcome: sum(row[outcome] for row in confirmation_rows) for outcome in ("requested", "approved", "denied")
        },
        "benign_write": {
            "planned": len(benign_writes),
            "completed": sum(row["status"] == "COMPLETED" for row in benign_writes),
            "utility_passed": sum(row.get("scored_utility") is True for row in benign_writes),
        },
        "environment_observer": {
            "final": sum(row["final"] for row in observer_rows),
            "extra_effect_observed": sum(row["extra_effect_observed"] is True for row in observer_rows),
        },
        "duration_seconds": time.monotonic() - started,
    }
    write_json(output / "summary.json", summary)
    return summary
