"""Fixed D workflow processes with host deadlines and separately observed records."""

import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from camel.adapters.agentdojo.controller import bounded_json, file_digest, write_json
from camel.adapters.agentdojo.results import Record
from camel.evaluation.connected import DOCUMENT, FlowCase

Mode = Literal["run", "hang_before", "hang_after", "hang_at_intent", "crash_after", "error_after"]


class ProcessJob(Record):
    job_id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    flow: FlowCase
    mode: Mode = "run"


class ProcessLimits(Record):
    max_planned: int = Field(ge=1, le=128)
    max_started: int = Field(ge=0, le=128)
    total_seconds: float = Field(gt=0, le=600)
    episode_seconds: float = Field(gt=0, le=60)
    stop_grace_seconds: float = Field(default=0.2, gt=0, le=2)
    max_model_requests: int = Field(default=0, ge=0, le=0)


def observe_records(directory: Path, job: ProcessJob) -> dict[str, Any]:
    records, problems = [], []
    paths = sorted((directory / "records").glob("*.json"))
    if len(paths) > 1:
        problems.append("too_many_record_files")
    for path in paths[:2]:
        try:
            value = bounded_json(path, 2097152)
            record = value["record"]
            if (
                path.name != "000.json"
                or value["job_id"] != job.job_id
                or value["case_id"] != job.flow.case_id
                or value["sequence"] != 0
                or record
                != dict(
                    effect_id="read-effect",
                    type="READ",
                    operation="read_file",
                    resources=[DOCUMENT],
                    destination=None,
                    payload=job.flow.memory_text,
                    response=job.flow.memory_text,
                )
            ):
                raise ValueError("record_identity_or_shape_mismatch")
        except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
            problems.append("invalid_record_file")
        else:
            records.append(record)
    intents = sorted((directory / "intents").glob("*.json"))
    return dict(
        records=records,
        problems=problems,
        intent_files=len(intents),
        pending_intents=max(0, len(intents) - len(records)),
    )


class FlowProcessController:
    def __init__(self, root: Path, jobs: list[ProcessJob], limits: ProcessLimits):
        if not jobs or len(jobs) > limits.max_planned or len({job.job_id for job in jobs}) != len(jobs):
            raise ValueError("invalid_planned_workflows")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self.jobs = jobs
        self.limits = limits
        self.started = time.monotonic()
        self.reserved = 0
        self.consumed = False
        self.stopped = None
        self.states: list[dict[str, Any]] = [dict(job=job.model_dump(), state="PLANNED", reason=None) for job in jobs]
        self.save()

    def save(self):
        write_json(
            self.root / "controller.json",
            dict(
                profile="D_ONLY_OFFLINE_WORKFLOW",
                limits=self.limits.model_dump(),
                reserved_starts=self.reserved,
                real_model_requests=0,
                episodes=self.states,
                retry=False,
            ),
        )

    def set_state(self, index, state, reason=None, **details):
        self.states[index].update(state=state, reason=reason, **details)
        self.save()

    def stop_child(self, child):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=self.limits.stop_grace_seconds)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
        if child.poll() is None:
            raise RuntimeError("fixed_workflow_child_not_stopped")

    def dispatch(self, index, directory, cancelled):
        begin = time.monotonic()
        deadline = min(self.started + self.limits.total_seconds, begin + self.limits.episode_seconds)
        self.reserved += 1
        self.set_state(index, "RESERVED")
        write_json(directory / "request.json", self.jobs[index].model_dump())
        self.set_state(index, "STARTING")
        if cancelled(index, directory):
            self.stopped = "host_cancelled"
            self.set_state(index, "NOT_RUN", self.stopped)
            return "NOT_RUN"
        if time.monotonic() >= deadline:
            self.set_state(index, "NOT_RUN", "deadline_before_launch")
            return "NOT_RUN"
        try:
            child = subprocess.Popen(
                [sys.executable, "-m", "camel.evaluation.flow_worker", str(directory)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            self.set_state(index, "ERROR", "launch_error", error_type=type(error).__name__)
            return "ERROR"
        status, reason = "FINISHED", None
        try:
            while True:
                if cancelled(index, directory):
                    status, reason = "ABORTED", "host_cancelled"
                    self.stopped = reason
                    break
                if time.monotonic() >= deadline:
                    status, reason = "TIMEOUT", "wall_deadline"
                    break
                if child.poll() is not None:
                    if child.returncode != 0:
                        status, reason = "ERROR", "worker_nonzero_exit"
                    break
                try:
                    child.wait(timeout=min(0.02, max(0.001, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass
        finally:
            self.stop_child(child)
        self.set_state(
            index,
            status,
            reason,
            worker_stopped=True,
            exit_code=child.returncode,
            elapsed_seconds=time.monotonic() - begin,
        )
        return status

    def collect(self, index, directory, host_status) -> dict[str, Any]:
        job = self.jobs[index]
        observation = observe_records(directory, job)
        errors = sorted((directory / "errors").glob("*.json"))
        row: dict[str, Any] = dict(
            job_id=job.job_id,
            case_id=job.flow.case_id,
            host_status=host_status,
            status=host_status,
            host_reason=self.states[index]["reason"],
            flow_terminal=None,
            completed_flow_terminal=None,
            observation=observation,
            worker_error_files=len(errors),
            result_sha256=None,
            model_requests=0,
            real_tool_calls=0,
            ASR=None,
            task_utility=None,
        )
        path = directory / "result.json"
        if path.exists():
            try:
                if not path.is_file() or path.stat().st_size > 2097152:
                    raise ValueError("result_file_limit")
                row["result_sha256"] = file_digest(path)
                result = bounded_json(path, 2097152)
                if (
                    not isinstance(result, dict)
                    or result.get("case_id") != job.flow.case_id
                    or result.get("model_requests") != 0
                    or result.get("real_tool_calls") != 0
                    or result.get("ledger") != observation["records"]
                    or result.get("status")
                    not in {
                        "RECORDED",
                        "MEMORY_BLOCKED",
                        "WRITE_BLOCKED",
                        "PLAN_INVALID",
                        "PLAN_BLOCKED",
                        "RISK_BLOCKED",
                        "REFRESH_BLOCKED",
                        "SNAPSHOT_CHANGED",
                        "REFRESH_VALIDATION_BLOCKED",
                    }
                ):
                    raise ValueError("invalid_workflow_result")
                row["flow_terminal"] = result["status"]
            except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
                row["result_problem"] = "invalid_or_inconsistent_result"
        if host_status == "FINISHED":
            if errors:
                row["status"] = "ERROR"
            elif observation["problems"] or row.get("result_problem"):
                row["status"] = "INVALID"
            elif row["flow_terminal"] is None or observation["pending_intents"]:
                row["status"] = "INCOMPLETE"
            else:
                row.update(status="COMPLETED", completed_flow_terminal=row["flow_terminal"])
        return row

    def run(self, cancelled=None) -> list[dict[str, Any]]:
        if self.consumed:
            raise ValueError("workflow_run_cannot_retry")
        self.consumed = True
        cancelled = cancelled or (lambda index, directory: False)
        rows = []
        for index, _ in enumerate(self.jobs):
            directory = self.root / f"episode_{index:03d}"
            directory.mkdir()
            reason = self.stopped
            if cancelled(index, directory):
                self.stopped = reason = "host_cancelled"
            if time.monotonic() >= self.started + self.limits.total_seconds:
                reason = "total_wall_deadline"
            if self.reserved >= self.limits.max_started:
                reason = reason or "workflow_start_budget"
            if reason is not None:
                self.set_state(index, "NOT_RUN", reason)
                status = "NOT_RUN"
            else:
                status = self.dispatch(index, directory, cancelled)
            row = self.collect(index, directory, status)
            rows.append(row)
            write_json(self.root / "observations.json", rows)
        return rows
