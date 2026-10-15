"""Sequential offline controller for fixed synthetic workers, never model execution."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Literal, TypedDict

from pydantic import Field

from camel.adapters.agentdojo.results import (
    Episode,
    Observation,
    Record,
    load_episode,
    strict_json,
    validate_population,
)

Role = Literal["planner", "quarantined", "detector", "embedding"]
Case = Literal[
    "complete",
    "goal",
    "native_error",
    "tool_error",
    "hang",
    "effect_timeout",
    "cancel",
    "crash",
    "bad_usage",
    "missing_usage",
]


class Quota(Record):
    requests: int = Field(ge=0, le=10000)
    input_tokens: int = Field(ge=0, le=100000000)
    output_tokens: int = Field(ge=0, le=100000000)
    cost_units: int = Field(ge=0, le=100000000)


class Limits(Record):
    total: Quota
    roles: dict[Role, Quota]
    max_episodes: int = Field(ge=1, le=128)
    total_seconds: float = Field(gt=0, le=600)
    episode_seconds: float = Field(gt=0, le=60)
    stop_grace_seconds: float = Field(gt=0, le=2)


class Call(Record):
    role: Role
    input_tokens: int = Field(ge=0, le=1000000)
    max_output_tokens: int = Field(ge=0, le=1000000)
    max_cost_units: int = Field(ge=0, le=1000000)


class Job(Record):
    episode: Episode
    case: Case
    calls: list[Call] = Field(min_length=1, max_length=8)


class Usage(Record):
    call_index: int = Field(ge=0)
    role: Role
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_units: int = Field(ge=0)


def write_json(path: Path, value):
    """Durable replacement in a single controller-owned directory."""
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def bounded_json(path: Path, max_bytes=65536):
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("controller_input_too_large")
    return strict_json(raw)


def zero():
    return dict(requests=0, input_tokens=0, output_tokens=0, cost_units=0)


class Reservation(TypedDict):
    total: dict[str, int]
    roles: dict[Role, dict[str, int]]


def reservation(calls: list[Call]) -> Reservation:
    total = zero()
    roles: dict[Role, dict[str, int]] = {}
    for call in calls:
        amount = dict(
            requests=1,
            input_tokens=call.input_tokens,
            output_tokens=call.max_output_tokens,
            cost_units=call.max_cost_units,
        )
        used = roles.setdefault(call.role, zero())
        for key, value in amount.items():
            total[key] += value
            used[key] += value
    return {"total": total, "roles": roles}


def valid_usage(job: Job, value):
    if not isinstance(value, list) or len(value) != len(job.calls):
        raise ValueError("missing_or_extra_usage")
    rows = [Usage.model_validate(row) for row in value]
    for index, (call, used) in enumerate(zip(job.calls, rows, strict=True)):
        if (
            used.call_index != index
            or used.role != call.role
            or used.input_tokens > call.input_tokens
            or used.output_tokens > call.max_output_tokens
            or used.cost_units > call.max_cost_units
        ):
            raise ValueError("usage_exceeds_or_mismatches_reservation")
    return [row.model_dump() for row in rows]


def effect_observation(path: Path, episode: Episode, *, final: bool):
    if not path.exists():
        return None
    try:
        value = bounded_json(path)
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None
    if value != dict(episode_id=episode.episode_id, synthetic_goal=True, extra_effect=True):
        return None
    return Observation(source_id="SYNTHETIC_WORKER_STATE", goal_achieved=True, extra_effect_observed=True, final=final)


class Controller:
    """Only a fixed local synthetic worker. No arbitrary command or model endpoint."""

    def __init__(self, root: Path, jobs: list[Job], limits: Limits):
        validate_population([job.episode for job in jobs])
        if len(jobs) > limits.max_episodes:
            raise ValueError("planned_episode_limit_exceeded")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self.jobs = jobs
        self.limits = limits
        self.started = time.monotonic()
        self.used: dict[str, Any] = dict(total=zero(), roles={role: zero() for role in limits.roles})
        self.states: list[dict[str, Any]] = [
            dict(episode=job.episode.model_dump(), state="PLANNED", reason=None, reservation=None) for job in jobs
        ]
        self.events: list[dict[str, Any]] = []
        self.consumed = False
        self.stop_reason = None
        self.save()

    def save(self):
        write_json(
            self.root / "ledger.json",
            dict(
                profile="SYNTHETIC_ONLY",
                limits=self.limits.model_dump(),
                used=self.used,
                episodes=self.states,
                events=self.events,
                real_model_requests=0,
                refund_policy="NO_REFUNDS_NO_RETRY",
            ),
        )

    def transition(self, index, state, reason=None, **details):
        self.states[index].update(state=state, reason=reason, **details)
        self.events.append(
            dict(sequence=len(self.events), episode_id=self.jobs[index].episode.episode_id, state=state, reason=reason)
        )
        self.save()

    def admit(self, index):
        if self.states[index]["state"] != "PLANNED":
            raise ValueError("episode_already_admitted")
        requested = reservation(self.jobs[index].calls)
        for scope, amount, quota, used in [
            ("total", requested["total"], self.limits.total, self.used["total"]),
            *[
                (role, amount, self.limits.roles.get(role), self.used["roles"].get(role, zero()))
                for role, amount in requested["roles"].items()
            ],
        ]:
            if quota is None:
                return "unconfigured_role:" + scope
            if any(used[key] + value > getattr(quota, key) for key, value in amount.items()):
                return "budget_exhausted:" + scope
        for key, amount in requested["total"].items():
            self.used["total"][key] += amount
        for role, amounts in requested["roles"].items():
            for key, amount in amounts.items():
                self.used["roles"][role][key] += amount
        self.transition(index, "RESERVED", reservation=requested)
        return None

    def stop_worker(self, worker):
        if worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=self.limits.stop_grace_seconds)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=2)
        if worker.poll() is None:
            raise RuntimeError("synthetic_worker_not_stopped")

    def dispatch(self, index, directory, cancelled):
        job = self.jobs[index]
        job_started = time.monotonic()
        deadline = min(self.started + self.limits.total_seconds, job_started + self.limits.episode_seconds)
        write_json(directory / "request.json", job.model_dump())
        self.transition(index, "RUNNING")
        if cancelled(index, directory):
            self.transition(index, "NOT_RUN", "host_cancelled")
            return "not_run"
        if time.monotonic() >= deadline:
            self.transition(index, "NOT_RUN", "deadline_before_launch")
            return "not_run"
        try:
            worker = subprocess.Popen(
                [sys.executable, "-m", "camel.adapters.agentdojo.control_worker", str(directory)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            self.transition(index, "ABORTED", "launch_error", error_type=type(error).__name__)
            return "aborted"
        controller = "finished"
        reason = None
        try:
            while True:
                if cancelled(index, directory):
                    controller, reason = "aborted", "host_cancelled"
                    break
                if time.monotonic() >= deadline:
                    controller, reason = "timeout", "wall_deadline"
                    break
                if worker.poll() is not None:
                    if worker.returncode != 0:
                        controller, reason = "aborted", "worker_nonzero_exit"
                    break
                try:
                    worker.wait(timeout=min(0.02, max(0.001, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass
        finally:
            self.stop_worker(worker)
        details = dict(worker_stopped=True, exit_code=worker.returncode, elapsed_seconds=time.monotonic() - job_started)
        if controller == "finished":
            try:
                details["observed_simulated_usage"] = valid_usage(job, bounded_json(directory / "usage.json"))
            except (OSError, ValueError, UnicodeError, RecursionError):
                controller, reason = "aborted", "unverified_or_excess_usage"
                self.stop_reason = "usage_fault"
        self.transition(index, controller.upper(), reason, **details)
        return controller

    def run(self, cancelled=None):
        if self.consumed:
            raise ValueError("controller_cannot_retry")
        self.consumed = True
        cancelled = cancelled or (lambda index, directory: False)
        rows = []
        for index, job in enumerate(self.jobs):
            directory = self.root / f"episode_{index:03d}"
            directory.mkdir()
            reason = self.stop_reason
            if cancelled(index, directory):
                self.stop_reason = reason = "host_cancelled"
            if time.monotonic() >= self.started + self.limits.total_seconds:
                reason = "total_wall_deadline"
            if reason is None:
                reason = self.admit(index)
            if reason is not None:
                controller = "not_run"
                self.transition(index, "NOT_RUN", reason)
            else:
                controller = self.dispatch(index, directory, cancelled)
                if self.states[index]["reason"] == "host_cancelled":
                    self.stop_reason = "host_cancelled"
            observer = effect_observation(directory / "state.json", job.episode, final=controller == "finished")
            row = load_episode(job.episode, directory / "trace.json", controller=controller, observer=observer)
            row.update(host_reason=self.states[index]["reason"], reservation=self.states[index]["reservation"])
            rows.append(row)
            write_json(self.root / "normalized.json", rows)
        self.save()
        return rows


def file_digest(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
