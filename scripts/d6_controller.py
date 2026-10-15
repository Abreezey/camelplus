"""Exercise fixed offline process and reservation controls, with zero model calls."""

import argparse
from pathlib import Path

from camel.adapters.agentdojo.controller import (
    Call,
    Controller,
    Job,
    Limits,
    bounded_json,
    file_digest,
    write_json,
)
from camel.adapters.agentdojo.results import Episode, aggregate

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D6_controller_protocol.json"


def call(role="planner"):
    return Call.model_validate(dict(role=role, input_tokens=3, max_output_tokens=2, max_cost_units=1))


def job(index, case="complete", *, group="normal", benign=False, calls=None):
    spec = Episode.model_validate(
        dict(
            episode_id=f"{group}_{index}",
            group=group,
            pipeline_name="synthetic-controller",
            kind="benign" if benign else "attack",
            user_task_id=f"user_task_{index}",
            injection_task_id=None if benign else "injection_task_0",
            attack_type=None if benign else "important_instructions",
        )
    )
    return Job.model_validate(
        dict(episode=spec.model_dump(), case=case, calls=[value.model_dump() for value in (calls or [call()])])
    )


def limits(**changes):
    quota = dict(requests=100, input_tokens=1000, output_tokens=1000, cost_units=1000)
    values = dict(
        total=quota,
        roles={role: quota.copy() for role in ["planner", "quarantined", "detector", "embedding"]},
        max_episodes=30,
        total_seconds=30.0,
        episode_seconds=3.0,
        stop_grace_seconds=0.2,
    )
    values.update(changes)
    return Limits.model_validate(values)


def run_controls(output):
    all_rows = []
    accounting = {}
    runs = [
        (
            "normal",
            [job(0, benign=True), job(1, "goal"), job(2, "native_error"), job(3, "tool_error"), job(4, "crash")],
            limits(),
        ),
        (
            "deadlines",
            [job(0, "hang", group="deadlines"), job(1, "effect_timeout", group="deadlines")],
            limits(episode_seconds=1.5),
        ),
        ("cancel", [job(0, "cancel", group="cancel"), job(1, group="cancel")], limits()),
        ("usage", [job(0, "bad_usage", group="usage"), job(1, group="usage")], limits()),
        ("missing_usage", [job(0, "missing_usage", group="missing_usage"), job(1, group="missing_usage")], limits()),
        (
            "global_budget",
            [
                job(
                    0,
                    group="global_budget",
                    calls=[call(role) for role in ["planner", "quarantined", "detector", "embedding"]],
                ),
                job(1, group="global_budget"),
            ],
            limits(total=dict(requests=4, input_tokens=12, output_tokens=8, cost_units=4)),
        ),
        (
            "role_budget",
            [
                job(0, group="role_budget", calls=[call("quarantined")]),
                job(1, group="role_budget"),
                job(2, group="role_budget", calls=[call("detector")]),
            ],
            limits(
                roles={
                    "planner": dict(requests=0, input_tokens=0, output_tokens=0, cost_units=0),
                    **{
                        role: dict(requests=10, input_tokens=100, output_tokens=100, cost_units=100)
                        for role in ["quarantined", "detector", "embedding"]
                    },
                }
            ),
        ),
        (
            "total_deadline",
            [job(0, "hang", group="total_deadline"), job(1, group="total_deadline")],
            limits(total_seconds=1.5),
        ),
    ]
    expected = {
        "normal": ["COMPLETED", "COMPLETED", "NATIVE_ERROR", "TOOL_ERROR", "ABORTED"],
        "deadlines": ["TIMEOUT", "TIMEOUT"],
        "cancel": ["ABORTED", "NOT_RUN"],
        "usage": ["ABORTED", "NOT_RUN"],
        "missing_usage": ["ABORTED", "NOT_RUN"],
        "global_budget": ["COMPLETED", "NOT_RUN"],
        "role_budget": ["COMPLETED", "NOT_RUN", "COMPLETED"],
        "total_deadline": ["TIMEOUT", "NOT_RUN"],
    }
    for name, jobs, budget in runs:
        controller = Controller(output / name, jobs, budget)
        cancelled = (lambda index, directory: (directory / "ready.json").exists()) if name == "cancel" else None
        rows = controller.run(cancelled)
        if [row["status"] for row in rows] != expected[name]:
            raise RuntimeError("offline_controller_control_failed:" + name)
        ledger = bounded_json(output / name / "ledger.json", 2097152)
        if any(
            state["state"] not in {"NOT_RUN", "RESERVED"} and not state.get("worker_stopped")
            for state in ledger["episodes"]
        ):
            raise RuntimeError("worker_stop_not_verified:" + name)
        if name == "deadlines" and not rows[1]["independent"]["extra_effect_observed"]:
            raise RuntimeError("timeout_effect_lost")
        if name == "global_budget" and (
            ledger["used"]["total"]["requests"] != 4
            or any(used["requests"] != 1 for used in ledger["used"]["roles"].values())
        ):
            raise RuntimeError("all_role_reservation_failed")
        accounting[name] = dict(
            reserved=ledger["used"],
            statuses=expected[name],
            launched_workers=sum(state.get("worker_stopped", False) for state in ledger["episodes"]),
        )
        all_rows.extend(rows)
    write_json(output / "normalized.json", all_rows)
    write_json(output / "metrics.json", aggregate(all_rows))
    write_json(output / "accounting.json", accounting)
    return dict(
        planned_synthetic_episodes=len(all_rows),
        launched_synthetic_workers=sum(row["launched_workers"] for row in accounting.values()),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("fresh output under artifacts/d required")
    paths = [
        Path(__file__),
        PROTOCOL,
        ROOT / "src/camel/adapters/agentdojo/controller.py",
        ROOT / "src/camel/adapters/agentdojo/control_worker.py",
        ROOT / "src/camel/adapters/agentdojo/results.py",
        ROOT / "src/camel/evaluation/ablation.py",
        ROOT / "tests/unit/evaluation/test_agentdojo_controller.py",
    ]
    sources = {path.relative_to(ROOT).as_posix(): file_digest(path) for path in paths}
    output.mkdir(parents=True)
    write_json(output / "freeze.json", dict(protocol=bounded_json(PROTOCOL), source_sha256=sources))
    counts = run_controls(output)
    if any(file_digest(ROOT / name) != digest for name, digest in sources.items()):
        raise RuntimeError("controller_source_changed")
    write_json(
        output / "summary.json",
        dict(
            status="PASS_SYNTHETIC_CONTROLLER_ONLY",
            **counts,
            real_model_requests=0,
            environment_loads=0,
            real_tool_calls=0,
            downloads=0,
            full_D6_accepted=False,
            evidence_sha256={
                path.relative_to(output).as_posix(): file_digest(path) for path in sorted(output.rglob("*.json"))
            },
        ),
    )
    print(f"PASS_SYNTHETIC_CONTROLLER_ONLY: {counts}; no model calls; {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
