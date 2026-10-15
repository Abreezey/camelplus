"""Run fixed D workflows under host process controls, with zero model requests."""

import argparse
import hashlib
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from camel.adapters.agentdojo.controller import bounded_json, file_digest, write_json
from camel.evaluation.connected import controls
from camel.evaluation.flow_process import FlowProcessController, ProcessJob, ProcessLimits

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D_flow_process_protocol.json"


def source_reference(root: Path, pin: Path):
    """Explicit reviewed baseline, portable across Git LF/CRLF checkout settings."""
    value = bounded_json(pin)
    if value.get("format") != "sha256_lf_v1" or not isinstance(value.get("sha256_lf"), dict) or not value["sha256_lf"]:
        raise ValueError("invalid_source_reference")
    hashes = {}
    for name, expected in value["sha256_lf"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError("source_reference_outside_root")
        body = path.read_bytes()
        if hashlib.sha256(body.replace(b"\r\n", b"\n")).hexdigest() != expected:
            raise ValueError("source_reference_mismatch:" + name)
        hashes[name] = hashlib.sha256(body).hexdigest()
    return hashes


def limits(**changes):
    values = dict(
        max_planned=128,
        max_started=128,
        total_seconds=90.0,
        episode_seconds=6.0,
        stop_grace_seconds=0.2,
        max_model_requests=0,
    )
    values.update(changes)
    return ProcessLimits.model_validate(values)


def job(name, mode="run"):
    return ProcessJob.model_validate(dict(job_id=name, flow=controls()[0][0].model_dump(), mode=mode))


def check_rows(rows, expected):
    if len(rows) != len(expected) or [row["status"] for row in rows] != expected:
        raise ValueError("process_flow_status_control_failed")
    for row in rows:
        if row["status"] != "COMPLETED" and row["completed_flow_terminal"] is not None:
            raise ValueError("incomplete_flow_was_scored")
        if row["observation"]["problems"]:
            raise ValueError("formal_record_observation_invalid")


def run_controls(output) -> dict[str, Any]:
    scenarios = [
        (
            "regular",
            [ProcessJob(job_id=case.case_id, flow=case) for case, _ in controls()],
            limits(max_planned=13, max_started=13),
        ),
        (
            "faults",
            [
                job("before", "hang_before"),
                job("after", "hang_after"),
                job("intent", "hang_at_intent"),
                job("crash", "crash_after"),
                job("error", "error_after"),
            ],
            limits(episode_seconds=2.0),
        ),
        ("cancel", [job("cancel", "hang_after"), job("after_cancel")], limits()),
        ("start_budget", [job("first"), job("no_budget")], limits(max_started=1)),
        ("total_deadline", [job("deadline", "hang_before"), job("after_deadline")], limits(total_seconds=2.0)),
    ]
    expected = dict(
        regular=["COMPLETED"] * 13,
        faults=["TIMEOUT", "TIMEOUT", "TIMEOUT", "ERROR", "ERROR"],
        cancel=["ABORTED", "NOT_RUN"],
        start_budget=["COMPLETED", "NOT_RUN"],
        total_deadline=["TIMEOUT", "NOT_RUN"],
    )
    by_group = {}
    launched = 0
    for name, jobs, budget in scenarios:
        controller = FlowProcessController(output / name, jobs, budget)
        cancelled = (lambda index, directory: (directory / "result_ready.json").exists()) if name == "cancel" else None
        rows = controller.run(cancelled)
        check_rows(rows, expected[name])
        for state in controller.states:
            if state["state"] != "NOT_RUN" and (not state.get("worker_stopped") or state.get("exit_code") is None):
                raise ValueError("process_exit_not_verified")
        launched += sum(state.get("worker_stopped", False) for state in controller.states)
        by_group[name] = rows
    if [row["flow_terminal"] for row in by_group["regular"]] != [expected for _, expected in controls()]:
        raise ValueError("regular_connected_flow_changed")
    faults = by_group["faults"]
    if [len(row["observation"]["records"]) for row in faults] != [0, 1, 0, 1, 1] or faults[2]["observation"][
        "pending_intents"
    ] != 1:
        raise ValueError("incomplete_flow_effect_evidence_lost")
    if (
        faults[4]["flow_terminal"] != "RECORDED"
        or faults[4]["worker_error_files"] != 1
        or faults[4]["completed_flow_terminal"] is not None
    ):
        raise ValueError("error_was_treated_as_recovered_success")
    if len(by_group["cancel"][0]["observation"]["records"]) != 1:
        raise ValueError("cancelled_flow_record_lost")
    write_json(output / "observations.json", by_group)
    rows = [row for values in by_group.values() for row in values]
    return dict(
        planned_workflows=len(rows),
        launched_workers=launched,
        statuses=dict(Counter(row["status"] for row in rows)),
        persisted_simulated_reads=sum(len(row["observation"]["records"]) for row in rows),
        pending_intents=sum(row["observation"]["pending_intents"] for row in rows),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--source-pin", type=Path, help="explicit current source reference after a reviewed upstream merge"
    )
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("fresh output under artifacts/d required")
    if args.source_pin is not None and (
        not args.source_pin.resolve().is_relative_to(ROOT / "docs/d/evidence") or not args.source_pin.is_file()
    ):
        parser.error("source pin must be an existing file under docs/d/evidence")

    def guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request"}:
            raise RuntimeError("process_flow_evaluation_is_offline")

    sys.addaudithook(guard)
    previous = ROOT / "docs/d/evidence/D_connected_acceptance.json"
    hashes = (
        source_reference(ROOT, args.source_pin)
        if args.source_pin is not None
        else bounded_json(previous)["source_sha256"]
    )
    if any(file_digest(ROOT / name) != digest for name, digest in hashes.items()):
        raise ValueError("connected_flow_sources_changed")
    paths = [
        Path(__file__),
        PROTOCOL,
        previous,
        ROOT / "src/camel/evaluation/flow_process.py",
        ROOT / "src/camel/evaluation/flow_worker.py",
        ROOT / "src/camel/adapters/agentdojo/controller.py",
        ROOT / "src/camel/adapters/agentdojo/results.py",
        ROOT / "src/camel/evaluation/ablation.py",
        ROOT / "tests/unit/evaluation/test_flow_process.py",
    ]
    if args.source_pin is not None:
        paths.append(args.source_pin.resolve())
    hashes.update({path.relative_to(ROOT).as_posix(): file_digest(path) for path in paths})
    output.mkdir(parents=True)
    write_json(output / "freeze.json", dict(protocol=bounded_json(PROTOCOL), source_sha256=hashes))
    counts = run_controls(output)
    if any(file_digest(ROOT / name) != digest for name, digest in hashes.items()):
        raise RuntimeError("flow_process_sources_changed")
    write_json(
        output / "summary.json",
        dict(
            status="PASS_D_OFFLINE_PROCESS_FLOW",
            **counts,
            real_model_requests=0,
            real_tool_calls=0,
            downloads=0,
            ASR=None,
            task_utility=None,
            full_D6_D7_D8_accepted=False,
            evidence_sha256={
                path.relative_to(output).as_posix(): file_digest(path)
                for path in sorted(output.rglob("*"))
                if path.is_file()
            },
        ),
    )
    print(f"PASS_D_OFFLINE_PROCESS_FLOW: {counts}; models=0, real tools=0; {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
