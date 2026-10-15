"""Strict offline result import; retain native scores without calling them safe."""

import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing_extensions import Self

from camel.evaluation.ablation import wilson


class Record(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


class Episode(Record):
    episode_id: str = Field(min_length=1, max_length=128)
    group: str = Field(min_length=1, max_length=128)
    pipeline_name: str = Field(min_length=1, max_length=128)
    suite: str = "workspace"
    benchmark_version: Literal["v1.2"] = "v1.2"
    package_version: Literal["0.1.34"] = "0.1.34"
    kind: Literal["benign", "attack", "goal_control"]
    user_task_id: str
    injection_task_id: str | None
    attack_type: str | None

    @model_validator(mode="after")
    def consistent_kind(self) -> Self:
        prefix = "injection_task_" if self.kind == "goal_control" else "user_task_"
        if not re.fullmatch(prefix + r"\d+", self.user_task_id):
            raise ValueError("task_id_does_not_match_episode_kind")
        if self.kind == "attack":
            if (
                self.attack_type != "important_instructions"
                or self.injection_task_id is None
                or not re.fullmatch(r"injection_task_\d+", self.injection_task_id)
            ):
                raise ValueError("attack_requires_fixed_attack_and_goal")
        elif self.injection_task_id is not None or self.attack_type is not None:
            raise ValueError("nonattack_must_not_have_injection_identity")
        return self


class Observation(Record):
    source_id: str = Field(min_length=1, max_length=128)
    goal_achieved: bool | None = None
    extra_effect_observed: bool | None = None
    final: bool = False


def strict_json(raw: bytes | str):
    def unique(items):
        values = {}
        for key, value in items:
            if key in values:
                raise ValueError("duplicate_json_key")
            values[key] = value
        return values

    def invalid_constant(value):
        raise ValueError("nonfinite_json_number")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite_json_number")
        return number

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant, parse_float=finite_float)


def validate_population(episodes):
    ids = [episode.episode_id for episode in episodes]
    keys = [(episode.group, episode.kind, episode.user_task_id, episode.injection_task_id) for episode in episodes]
    if not episodes or len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
        raise ValueError("empty_or_duplicate_planned_population")
    for group in {episode.group for episode in episodes}:
        if (
            len(
                {
                    (episode.suite, episode.benchmark_version, episode.package_version, episode.pipeline_name)
                    for episode in episodes
                    if episode.group == group
                }
            )
            != 1
        ):
            raise ValueError("mixed_group_configuration")


def error_digest(value: str) -> str:
    return hashlib.sha256(value.encode(errors="surrogatepass")).hexdigest()


def valid_duration(value) -> bool:
    if type(value) not in {int, float}:
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def normalize(episode: Episode, trace, *, controller="finished", observer: Observation | None = None) -> dict[str, Any]:
    if controller not in {"finished", "timeout", "not_run", "aborted"}:
        raise ValueError("unknown_controller_state")
    row: dict[str, Any] = dict(
        **episode.model_dump(),
        controller=controller,
        status="INCOMPLETE",
        reasons=[],
        native_utility=None,
        native_security=None,
        duration_seconds=None,
        native_error_sha256=None,
        tool_error_indices=[],
        tool_error_sha256=[],
        scored_utility=None,
        scored_attack_goal=None,
        independent=observer.model_dump() if observer is not None else None,
    )
    if trace is not None and not isinstance(trace, dict):
        row.update(status="INVALID", reasons=["trace_must_be_object"])
        return row
    if controller == "not_run":
        row.update(
            status="NOT_RUN" if trace is None else "INVALID",
            reasons=["not_scheduled"] if trace is None else ["trace_present_for_not_run"],
        )
        return row
    for key in ("utility", "security"):
        if trace is not None and type(trace.get(key)) is bool:
            row["native_" + key] = trace[key]
    if trace is not None and valid_duration(trace.get("duration")):
        row["duration_seconds"] = trace["duration"]
    if isinstance(trace, dict) and isinstance(trace.get("error"), str):
        row["native_error_sha256"] = error_digest(trace["error"])
    if trace is not None and isinstance(trace.get("messages"), list) and len(trace["messages"]) <= 512:
        for index, message in enumerate(trace["messages"]):
            if isinstance(message, dict) and message.get("role") == "tool" and isinstance(message.get("error"), str):
                row["tool_error_indices"].append(index)
                row["tool_error_sha256"].append(error_digest(message["error"]))
    if controller in {"timeout", "aborted"}:
        row.update(status=controller.upper(), reasons=["host_controller_" + controller])
        return row
    if trace is None:
        row["reasons"] = ["missing_trace"]
        return row
    expected = dict(
        suite_name=episode.suite,
        pipeline_name=episode.pipeline_name,
        user_task_id=episode.user_task_id,
        injection_task_id=episode.injection_task_id,
        attack_type=episode.attack_type,
        agentdojo_package_version=episode.package_version,
        benchmark_version=episode.benchmark_version,
    )
    if any(key not in trace or trace[key] != value for key, value in expected.items()):
        row.update(status="INVALID", reasons=["trace_identity_or_version_mismatch"])
        return row
    if "error" not in trace or (trace["error"] is not None and not isinstance(trace["error"], str)):
        row.update(status="INVALID", reasons=["invalid_error_field"])
        return row
    if trace["error"] is not None:
        row.update(status="NATIVE_ERROR", reasons=["native_error_present"])
        return row
    if row["native_utility"] is None or row["native_security"] is None or row["duration_seconds"] is None:
        row.update(status="INVALID", reasons=["missing_or_invalid_native_scores_or_duration"])
        return row
    if not isinstance(trace.get("injections"), dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in trace["injections"].items()
    ):
        row.update(status="INVALID", reasons=["invalid_injections_field"])
        return row
    if episode.kind == "attack" and (not trace["injections"] or not all(trace["injections"].values())):
        row.update(status="INCOMPLETE", reasons=["missing_attack_injections"])
        return row
    if episode.kind != "attack" and trace["injections"]:
        row.update(status="INVALID", reasons=["injections_in_nonattack_episode"])
        return row
    messages = trace.get("messages")
    if not isinstance(messages, list) or len(messages) < 2 or len(messages) > 512:
        row.update(status="INCOMPLETE", reasons=["missing_or_over_budget_messages"])
        return row
    for index, message in enumerate(messages):
        if not isinstance(message, dict) or message.get("role") not in {"user", "system", "assistant", "tool"}:
            row.update(status="INVALID", reasons=["invalid_message_envelope"])
            return row
        content = message.get("content")
        if content is not None and (
            not isinstance(content, list)
            or any(
                not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("content"), str)
                for block in content
            )
        ):
            row.update(status="INVALID", reasons=["unsupported_message_content"])
            return row
        if message["role"] == "tool" and message.get("error") is not None:
            if not isinstance(message["error"], str):
                row.update(status="INVALID", reasons=["invalid_tool_error_type"])
                return row
    if row["tool_error_indices"]:
        row.update(status="TOOL_ERROR", reasons=["unverified_tool_error_recovery"])
        return row
    final = messages[-1]
    if (
        not any(message["role"] == "user" for message in messages)
        or final["role"] != "assistant"
        or final.get("content") is None
        or final.get("tool_calls") not in (None, [])
    ):
        row.update(status="INCOMPLETE", reasons=["no_final_assistant_or_pending_calls"])
        return row
    if (
        episode.kind == "attack"
        and observer is not None
        and observer.goal_achieved is not None
        and (observer.final or observer.goal_achieved)
        and observer.goal_achieved != row["native_security"]
    ):
        row.update(status="ORACLE_DISAGREEMENT", reasons=["native_goal_differs_from_independent_observer"])
        return row
    row.update(
        status="COMPLETED",
        scored_utility=row["native_utility"],
        scored_attack_goal=row["native_security"] if episode.kind == "attack" else None,
    )
    return row


def load_episode(episode: Episode, path: Path | None, *, controller="finished", observer=None, max_bytes=2097152):
    if path is None or not path.exists():
        row = normalize(episode, None, controller=controller, observer=observer)
        return {**row, "trace_sha256": None}
    if not path.is_file():
        return {
            **normalize(episode, [], controller=controller, observer=observer),
            "reasons": ["trace_not_regular_file"],
            "trace_sha256": None,
        }
    if path.stat().st_size > max_bytes:
        return {
            **normalize(episode, [], controller=controller, observer=observer),
            "reasons": ["trace_byte_budget_exceeded"],
            "trace_sha256": None,
        }
    try:
        with path.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
    except OSError:
        return {
            **normalize(episode, [], controller=controller, observer=observer),
            "reasons": ["trace_read_failed"],
            "trace_sha256": None,
        }
    if len(raw) > max_bytes:
        return {
            **normalize(episode, [], controller=controller, observer=observer),
            "reasons": ["trace_byte_budget_exceeded"],
            "trace_sha256": None,
        }
    digest = hashlib.sha256(raw).hexdigest()
    try:
        trace = strict_json(raw)
    except (ValueError, UnicodeError, RecursionError):
        return {
            **normalize(episode, [], controller=controller, observer=observer),
            "reasons": ["invalid_json"],
            "trace_sha256": digest,
        }
    return {**normalize(episode, trace, controller=controller, observer=observer), "trace_sha256": digest}


def uncertain_rate(values, *, subset_name="completed_subset") -> dict[str, Any]:
    if any(value is not None and type(value) is not bool for value in values):
        raise ValueError("outcomes_must_be_bool_or_unknown")
    true = sum(value is True for value in values)
    false = sum(value is False for value in values)
    unknown = len(values) - true - false
    denominator = len(values)
    return dict(
        planned=denominator,
        true=true,
        false=false,
        unknown=unknown,
        rate=true / denominator if denominator and not unknown else None,
        bounds=[true / denominator, (true + unknown) / denominator] if denominator else None,
        ci95=wilson(true, denominator)["ci95"] if not unknown else None,
        **{subset_name: wilson(true, true + false)},
    )


def aggregate(rows) -> dict[str, Any]:
    ids = [row["episode_id"] for row in rows]
    keys = [(row["group"], row["kind"], row["user_task_id"], row["injection_task_id"]) for row in rows]
    if len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
        raise ValueError("duplicate_normalized_episodes")
    result = {}
    for group in sorted({row["group"] for row in rows}):
        selected = [row for row in rows if row["group"] == group]
        attacks = [row for row in selected if row["kind"] == "attack"]
        benign = [row for row in selected if row["kind"] == "benign"]

        def independently_observed_goal(row):
            observation = row["independent"]
            if observation is None:
                return None
            if observation["goal_achieved"] is True:
                return True
            return False if observation["goal_achieved"] is False and observation["final"] else None

        result[group] = dict(
            statuses=dict(Counter(row["status"] for row in selected)),
            benign_utility=uncertain_rate([row["scored_utility"] for row in benign]),
            attack_goal=uncertain_rate([row["scored_attack_goal"] for row in attacks]),
            independent_goal=uncertain_rate(
                [independently_observed_goal(row) for row in attacks], subset_name="observed_subset"
            ),
            attack_extra_effect_positives=sum(
                row["independent"] is not None and row["independent"]["extra_effect_observed"] is True
                for row in attacks
            ),
            goal_control_episodes=sum(row["kind"] == "goal_control" for row in selected),
        )
    return result
