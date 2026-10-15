"""Real D subprocess outcomes must not erase errors or persisted observations."""

import hashlib
import importlib.util
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from camel.adapters.agentdojo.controller import bounded_json, write_json
from camel.evaluation.connected import controls, run_flow
from camel.evaluation.flow_process import FlowProcessController, ProcessJob, ProcessLimits, observe_records
from camel.evaluation.flow_worker import JournalRecorder


def limits(**changes):
    value: dict[str, Any] = dict(
        max_planned=20,
        max_started=20,
        total_seconds=60.0,
        episode_seconds=6.0,
        stop_grace_seconds=0.1,
        max_model_requests=0,
    )
    value.update(changes)
    return ProcessLimits.model_validate(value)


def job(name="one", mode="run", case_index=0):
    return ProcessJob.model_validate(dict(job_id=name, flow=controls()[case_index][0].model_dump(), mode=mode))


@pytest.fixture(scope="module")
def regular(tmp_path_factory):
    root = tmp_path_factory.mktemp("process_regular")
    jobs = [job("normal"), job("document", case_index=4), job("expiry", case_index=5)]
    controller = FlowProcessController(root / "run", jobs, limits())
    return controller, controller.run(), root


@pytest.fixture(scope="module")
def faults(tmp_path_factory):
    root = tmp_path_factory.mktemp("process_faults")
    jobs = [
        job("before", "hang_before"),
        job("after", "hang_after"),
        job("intent", "hang_at_intent"),
        job("crash", "crash_after"),
        job("error", "error_after"),
    ]
    controller = FlowProcessController(root / "run", jobs, limits(episode_seconds=2.0))
    return controller, controller.run()


def test_fixed_child_runs_actual_flow_with_identical_direct_results(regular):
    controller, rows, root = regular
    assert [row["status"] for row in rows] == ["COMPLETED"] * 3
    for index, spec in enumerate(controller.jobs):
        result = bounded_json(controller.root / f"episode_{index:03d}/result.json", 2097152)
        direct = run_flow(spec.flow, root / f"direct_{index}")
        assert result == direct
    assert rows[0]["completed_flow_terminal"] == "RECORDED"
    assert rows[1]["completed_flow_terminal"] == "RISK_BLOCKED"
    assert rows[2]["completed_flow_terminal"] == "REFRESH_BLOCKED"
    assert all(row["task_utility"] is None and row["ASR"] is None for row in rows)


def test_all_started_children_exit_before_collection(regular, faults):
    for controller, _ in [regular[:2], faults]:
        assert all(state["worker_stopped"] and state["exit_code"] is not None for state in controller.states)
        assert all(state["state"] not in {"RESERVED", "STARTING"} for state in controller.states)


def test_timeout_before_flow_and_after_result_are_both_uncompleted(faults):
    _, rows = faults
    assert rows[0]["status"] == rows[1]["status"] == "TIMEOUT"
    assert rows[0]["flow_terminal"] is None
    assert rows[1]["flow_terminal"] == "RECORDED"
    assert rows[0]["completed_flow_terminal"] is rows[1]["completed_flow_terminal"] is None
    assert not rows[0]["observation"]["records"] and len(rows[1]["observation"]["records"]) == 1


def test_pending_intent_is_preserved_without_claiming_observed_record(faults):
    row = faults[1][2]
    assert row["status"] == "TIMEOUT"
    assert row["observation"]["intent_files"] == row["observation"]["pending_intents"] == 1
    assert row["observation"]["records"] == [] and row["completed_flow_terminal"] is None


def test_crash_and_recorder_error_keep_raw_success_and_positive_record_unscored(faults):
    rows = faults[1][3:]
    assert all(row["status"] == "ERROR" and row["flow_terminal"] == "RECORDED" for row in rows)
    assert all(row["completed_flow_terminal"] is None and len(row["observation"]["records"]) == 1 for row in rows)
    assert rows[1]["host_status"] == "FINISHED" and rows[1]["worker_error_files"] == 1


def test_host_cancel_keeps_record_and_stops_remaining_dispatch(tmp_path):
    controller = FlowProcessController(tmp_path / "run", [job("cancel", "hang_after"), job("remaining")], limits())
    rows = controller.run(lambda index, directory: (directory / "result_ready.json").exists())
    assert [row["status"] for row in rows] == ["ABORTED", "NOT_RUN"]
    assert len(rows[0]["observation"]["records"]) == 1 and rows[0]["completed_flow_terminal"] is None
    assert controller.reserved == 1 and not (controller.root / "episode_001/request.json").exists()


def test_failed_flow_reservation_is_not_refunded(tmp_path):
    controller = FlowProcessController(
        tmp_path / "run", [job("error", "error_after"), job("remaining")], limits(max_started=1)
    )
    rows = controller.run()
    assert [row["status"] for row in rows] == ["ERROR", "NOT_RUN"]
    assert rows[1]["host_reason"] == "workflow_start_budget" and controller.reserved == 1


def test_zero_start_budget_preserves_plan_without_spawning(tmp_path, monkeypatch):
    controller = FlowProcessController(tmp_path / "run", [job("first"), job("second")], limits(max_started=0))

    def unexpected(*args, **kwargs):
        pytest.fail("zero start budget dispatched a child")

    monkeypatch.setattr("camel.evaluation.flow_process.subprocess.Popen", unexpected)
    rows = controller.run()
    assert [row["status"] for row in rows] == ["NOT_RUN", "NOT_RUN"]
    assert controller.reserved == 0 and len(bounded_json(controller.root / "controller.json")["episodes"]) == 2


def test_expired_total_deadline_prevents_first_dispatch(tmp_path):
    controller = FlowProcessController(tmp_path / "run", [job()], limits())
    controller.started -= 61
    assert controller.run()[0]["status"] == "NOT_RUN"
    assert controller.reserved == 0


def test_reservation_is_durable_before_process_launch(tmp_path, monkeypatch):
    controller = FlowProcessController(tmp_path / "run", [job()], limits())

    def failed_launch(*args, **kwargs):
        ledger = bounded_json(controller.root / "controller.json")
        assert ledger["reserved_starts"] == 1 and ledger["episodes"][0]["state"] == "STARTING"
        raise OSError("SYNTHETIC START FAILURE")

    monkeypatch.setattr("camel.evaluation.flow_process.subprocess.Popen", failed_launch)
    row = controller.run()[0]
    assert row["status"] == "ERROR" and row["host_reason"] == "launch_error"
    assert controller.reserved == 1


def test_persistence_failure_cannot_dispatch(tmp_path, monkeypatch):
    controller = FlowProcessController(tmp_path / "run", [job()], limits())

    def failed_save():
        raise OSError("SYNTHETIC DISK FAILURE")

    def unexpected(*args, **kwargs):
        pytest.fail("child dispatched after disk error")

    monkeypatch.setattr(controller, "save", failed_save)
    monkeypatch.setattr("camel.evaluation.flow_process.subprocess.Popen", unexpected)
    with pytest.raises(OSError, match="DISK"):
        controller.run()


@pytest.mark.parametrize("trigger", ["time", "cancel"])
def test_prelaunch_recheck_after_persistence(tmp_path, monkeypatch, trigger):
    clock, cancelled = [0.0], [False]
    monkeypatch.setattr("camel.evaluation.flow_process.time.monotonic", lambda: clock[0])
    controller = FlowProcessController(tmp_path / "run", [job()], limits(episode_seconds=1.0))
    original = controller.set_state

    def delayed(index, state, reason=None, **details):
        original(index, state, reason, **details)
        if state == "STARTING":
            clock[0] = 2.0 if trigger == "time" else 0.0
            cancelled[0] = trigger == "cancel"

    def unexpected(*args, **kwargs):
        pytest.fail("dispatch occurred after cancellation/deadline")

    monkeypatch.setattr(controller, "set_state", delayed)
    monkeypatch.setattr("camel.evaluation.flow_process.subprocess.Popen", unexpected)
    assert controller.run(lambda index, directory: cancelled[0])[0]["status"] == "NOT_RUN"
    assert controller.reserved == 1


def test_controller_has_no_retry_or_existing_output_reuse(regular):
    controller = regular[0]
    with pytest.raises(ValueError, match="retry"):
        controller.run()
    with pytest.raises(FileExistsError):
        FlowProcessController(controller.root, [job()], limits())


def test_duplicate_jobs_and_plan_limit_are_rejected_before_writing(tmp_path):
    for jobs, budget in [([job(), job()], limits()), ([job("one"), job("two")], limits(max_planned=1))]:
        with pytest.raises(ValueError, match="planned"):
            FlowProcessController(tmp_path / "run", jobs, budget)
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize(
    "changes",
    [
        dict(max_model_requests=1),
        dict(max_model_requests=False),
        dict(episode_seconds=float("inf")),
        dict(max_started=-1),
    ],
)
def test_limits_never_authorize_real_model_calls_or_invalid_resources(changes):
    with pytest.raises(ValidationError):
        limits(**changes)


def test_missing_or_malformed_result_cannot_complete(tmp_path):
    controller = FlowProcessController(tmp_path / "run", [job()], limits())
    directory = controller.root / "episode_000"
    directory.mkdir()
    assert controller.collect(0, directory, "FINISHED")["status"] == "INCOMPLETE"
    (directory / "result.json").write_text('{"case_id":1,"case_id":2}', encoding="utf-8")
    assert controller.collect(0, directory, "FINISHED")["status"] == "INVALID"
    (directory / "result.json").write_bytes(b" " * 2097153)
    row = controller.collect(0, directory, "FINISHED")
    assert row["status"] == "INVALID" and row["result_sha256"] is None


def test_record_identity_and_scope_are_checked_outside_worker_result(tmp_path):
    spec = job()
    recorder = JournalRecorder(tmp_path, spec)
    result = run_flow(spec.flow, tmp_path / "flow", recorder=recorder)
    assert len(observe_records(tmp_path, spec)["records"]) == 1
    record_path = tmp_path / "records/000.json"
    saved = bounded_json(record_path)
    saved["record"]["resources"] = ["file:///outside/secret"]
    write_json(record_path, saved)
    observed = observe_records(tmp_path, spec)
    assert observed["problems"] and not observed["records"]
    assert result["status"] == "RECORDED"


def test_disk_failure_between_in_memory_append_and_record_keeps_pending_intent(tmp_path, monkeypatch):
    spec = job()
    recorder = JournalRecorder(tmp_path, spec)

    def failed_record(path, value):
        if path.parent.name == "records":
            raise OSError("SYNTHETIC RECORD DISK FAILURE")
        write_json(path, value)

    monkeypatch.setattr("camel.evaluation.flow_worker.write_json", failed_record)
    with pytest.raises(OSError, match="DISK"):
        run_flow(spec.flow, tmp_path / "flow", recorder=recorder)
    assert len(recorder.ledger) == 1
    observed = observe_records(tmp_path, spec)
    assert not observed["records"] and observed["pending_intents"] == 1


def test_completed_policy_block_is_separate_from_task_success(regular):
    row = regular[1][1]
    assert row["status"] == "COMPLETED" and row["completed_flow_terminal"] == "RISK_BLOCKED"
    assert row["observation"]["records"] == [] and row["task_utility"] is None


@pytest.fixture
def evaluator():
    spec = importlib.util.spec_from_file_location(
        "flow_process_eval_tests", Path(__file__).resolve().parents[3] / "scripts/d_flow_process_eval.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_explicit_reference_allows_checkout_line_endings_but_rejects_code_change(tmp_path, evaluator):
    source, pin = tmp_path / "example.py", tmp_path / "pin.json"
    body = b"value = 1\n"
    write_json(pin, dict(format="sha256_lf_v1", sha256_lf={"example.py": hashlib.sha256(body).hexdigest()}))
    source.write_bytes(body.replace(b"\n", b"\r\n"))
    hashes = evaluator.source_reference(tmp_path, pin)
    assert hashes["example.py"] == hashlib.sha256(source.read_bytes()).hexdigest()
    source.write_bytes(b"value = 2\n")
    with pytest.raises(ValueError, match="mismatch"):
        evaluator.source_reference(tmp_path, pin)


def test_reference_cannot_read_outside_workspace_or_silently_omit_all_sources(tmp_path, evaluator):
    pin = tmp_path / "pin.json"
    write_json(pin, dict(format="sha256_lf_v1", sha256_lf={"../outside": "invalid"}))
    with pytest.raises(ValueError, match="outside_root"):
        evaluator.source_reference(tmp_path, pin)
    write_json(pin, dict(format="sha256_lf_v1", sha256_lf={}))
    with pytest.raises(ValueError, match="invalid_source_reference"):
        evaluator.source_reference(tmp_path, pin)
