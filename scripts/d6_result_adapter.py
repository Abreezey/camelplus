"""Offline result importer and synthetic TraceLogger controls; never run Agent models."""

import argparse
import json
import sys
from importlib.metadata import distribution
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field

from camel.adapters.agentdojo.catalog import sha256
from camel.adapters.agentdojo.results import (
    Episode,
    Observation,
    Record,
    aggregate,
    load_episode,
    normalize,
    strict_json,
    validate_population,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D6_result_adapter_protocol.json"


class InputEpisode(Record):
    episode: Episode
    controller: Literal["finished", "timeout", "not_run", "aborted"]
    trace: str | None
    observer: Observation | None = None


class Manifest(Record):
    purpose: Literal["SYNTHETIC_PARSER_CONTROLS", "EXISTING_LOG_IMPORT"]
    episodes: list[InputEpisode] = Field(min_length=1, max_length=128)


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def safe_trace(root: Path, value: str) -> Path:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or ":" in value
        or path.is_absolute()
        or path.as_posix() != value
        or ".." in path.parts
    ):
        raise ValueError("unsafe_trace_path")
    resolved = (root / value).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("unsafe_trace_path")
    return resolved


def synthetic_inputs(directory):
    from agentdojo.logging import NullLogger, TraceLogger

    directory.mkdir()
    scenarios = [
        "benign",
        "positive",
        "negative_extra",
        "native_error",
        "tool_error",
        "timeout",
        "not_run",
        "missing",
        "wrong_version",
        "pending",
        "empty_final",
        "goal_control",
        "oracle_disagreement",
        "invalid_json",
    ]
    records = []
    for index, scenario in enumerate(scenarios):
        kind = "benign" if scenario == "benign" else "goal_control" if scenario == "goal_control" else "attack"
        spec = Episode(
            episode_id=scenario,
            group="HARNESS_ONLY",
            pipeline_name="synthetic-no-model",
            kind=kind,
            user_task_id="injection_task_0" if kind == "goal_control" else f"user_task_{index}",
            injection_task_id="injection_task_0" if kind == "attack" else None,
            attack_type="important_instructions" if kind == "attack" else None,
        )
        trace = None
        if scenario not in {"not_run", "missing"}:
            delegate: Any = NullLogger()
            delegate.logdir = str(directory)
            delegate.messages = []
            logger: Any = TraceLogger(
                delegate,
                suite_name=spec.suite,
                pipeline_name=spec.pipeline_name,
                user_task_id=spec.user_task_id,
                injection_task_id=spec.injection_task_id,
                attack_type=spec.attack_type or "none",
                benchmark_version="v1.2",
                injections={"synthetic_vector": "INERT SYNTHETIC DATA"} if kind == "attack" else {},
            )
            messages: list[dict[str, Any]] = [
                dict(role="user", content=[dict(type="text", content="SYNTHETIC NO MODEL")]),
                dict(role="assistant", content=[dict(type="text", content="SYNTHETIC RESULT")], tool_calls=None),
            ]
            if scenario == "tool_error":
                messages.insert(1, dict(role="tool", content=[], error="SYNTHETIC TOOL FAILURE"))
            if scenario == "pending":
                messages[-1].update(content=None, tool_calls=[dict(function="synthetic_pending")])
            if scenario == "empty_final":
                messages[-1]["content"] = []
            logger.log(messages)
            logger.set_contextarg("duration", 0.01)
            logger.set_contextarg("utility", scenario in {"benign", "tool_error", "goal_control", "negative_extra"})
            logger.set_contextarg("security", scenario not in {"negative_extra", "empty_final", "oracle_disagreement"})
            if scenario == "native_error":
                logger.log_error("SYNTHETIC PROVIDER FAILURE")
            trace_path = (
                directory
                / spec.pipeline_name
                / spec.suite
                / spec.user_task_id
                / (spec.attack_type or "none")
                / f"{spec.injection_task_id or 'none'}.json"
            )
            if scenario == "wrong_version":
                content = json.loads(trace_path.read_text(encoding="utf-8"))
                content["benchmark_version"] = "v1.2.1"
                write(trace_path, content)
            if scenario == "invalid_json":
                trace_path.write_text('{"utility":true,"utility":false}', encoding="utf-8")
            trace = trace_path.relative_to(directory).as_posix()
        observer = None
        if scenario in {"positive", "negative_extra", "timeout", "oracle_disagreement", "empty_final"}:
            observer = Observation(
                source_id="SYNTHETIC_STATE_CONTROL",
                goal_achieved=scenario not in {"negative_extra", "empty_final"},
                extra_effect_observed=scenario != "empty_final",
                final=scenario != "timeout",
            )
        records.append(
            InputEpisode(
                episode=spec,
                controller="timeout" if scenario == "timeout" else "not_run" if scenario == "not_run" else "finished",
                trace=trace,
                observer=observer,
            )
        )
    manifest = Manifest(purpose="SYNTHETIC_PARSER_CONTROLS", episodes=records)
    write(directory / "manifest.json", manifest.model_dump())
    return manifest, directory


def import_manifest(manifest, directory, max_bytes):
    validate_population([record.episode for record in manifest.episodes])
    paths = [record.trace for record in manifest.episodes if record.trace is not None]
    if len(set(paths)) != len(paths):
        raise ValueError("trace_reused_for_multiple_episodes")
    rows = []
    for record in manifest.episodes:
        try:
            path = safe_trace(directory, record.trace) if record.trace is not None else None
        except ValueError:
            row = normalize(record.episode, [], controller=record.controller, observer=record.observer)
            row.update(reasons=["unsafe_trace_path"], trace_sha256=None)
        else:
            row = load_episode(
                record.episode, path, controller=record.controller, observer=record.observer, max_bytes=max_bytes
            )
        rows.append(row)
    return rows


def check_controls(rows):
    expected = dict(
        benign="COMPLETED",
        positive="COMPLETED",
        negative_extra="COMPLETED",
        native_error="NATIVE_ERROR",
        tool_error="TOOL_ERROR",
        timeout="TIMEOUT",
        not_run="NOT_RUN",
        missing="INCOMPLETE",
        wrong_version="INVALID",
        pending="INCOMPLETE",
        empty_final="COMPLETED",
        goal_control="COMPLETED",
        oracle_disagreement="ORACLE_DISAGREEMENT",
        invalid_json="INVALID",
    )
    if {row["episode_id"]: row["status"] for row in rows} != expected:
        raise RuntimeError("synthetic_status_control_failed")
    metrics = aggregate(rows)["HARNESS_ONLY"]
    attack = metrics["attack_goal"]
    observed = metrics["independent_goal"]
    if (attack["planned"], attack["true"], attack["false"], attack["unknown"], attack["rate"], attack["ci95"]) != (
        12,
        1,
        2,
        9,
        None,
        None,
    ) or (
        observed["true"],
        observed["false"],
        observed["unknown"],
        metrics["attack_extra_effect_positives"],
        metrics["goal_control_episodes"],
    ) != (3, 2, 7, 4, 1):
        raise RuntimeError("synthetic_denominator_control_failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--manifest", type=Path, help="import existing traces under artifacts/d; default builds synthetic controls"
    )
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("fresh output under artifacts/d required")
    if args.manifest is not None and (
        not args.manifest.resolve().is_relative_to(ROOT / "artifacts/d")
        or not args.manifest.is_file()
        or args.manifest.stat().st_size > 2097152
    ):
        parser.error("existing bounded manifest under artifacts/d required")

    def guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request", "subprocess.Popen"}:
            raise RuntimeError("offline result import prohibits networking and subprocesses")

    sys.addaudithook(guard)
    output.mkdir(parents=True)
    protocol = strict_json(PROTOCOL.read_bytes())
    source_paths = [
        Path(__file__),
        ROOT / "src/camel/adapters/agentdojo/results.py",
        ROOT / "src/camel/evaluation/ablation.py",
        PROTOCOL,
        ROOT / "tests/unit/evaluation/test_agentdojo_results.py",
        ROOT / "docs/d/evidence/D6_preparation_acceptance.json",
    ]
    sources = {p.relative_to(ROOT).as_posix(): sha256(p) for p in source_paths}
    write(output / "freeze.json", dict(protocol=protocol, source_sha256=sources))
    if args.manifest is None:
        installed = distribution("agentdojo")
        if installed.version != "0.1.34":
            raise ValueError("synthetic_logger_version_requires_review")
        preparation = strict_json((ROOT / "docs/d/evidence/D6_preparation_acceptance.json").read_bytes())
        logger_path = Path(str(installed.locate_file("agentdojo/logging.py")))
        if sha256(logger_path) != preparation["installed_package_file_sha256"]["logging.py"]:
            raise ValueError("installed_logger_changed_since_preparation")
        write(
            output / "dependency.json",
            dict(package="agentdojo", version=installed.version, logging_py_sha256=sha256(logger_path)),
        )
        manifest, directory = synthetic_inputs(output / "input")
        manifest_path = directory / "manifest.json"
    else:
        manifest_path = args.manifest.resolve()
        manifest = Manifest.model_validate(strict_json(manifest_path.read_bytes()))
        directory = manifest_path.parent
    inputs = {"manifest.json": sha256(manifest_path)}
    for record in manifest.episodes:
        if record.trace is not None:
            try:
                path = safe_trace(directory, record.trace)
            except ValueError:
                continue
            if path.is_file() and path.stat().st_size <= protocol["limits"]["max_trace_bytes"]:
                inputs[record.trace] = sha256(path)
    write(output / "input_freeze.json", inputs)
    rows = import_manifest(manifest, directory, protocol["limits"]["max_trace_bytes"])
    if args.manifest is None:
        check_controls(rows)
    if any(sha256(ROOT / name) != digest for name, digest in sources.items()):
        raise RuntimeError("result_adapter_source_changed")
    if sha256(manifest_path) != inputs["manifest.json"] or any(
        sha256(directory / name) != digest for name, digest in inputs.items() if name != "manifest.json"
    ):
        raise RuntimeError("result_input_changed")
    write(output / "normalized.json", rows)
    write(output / "metrics.json", aggregate(rows))
    write(
        output / "summary.json",
        dict(
            status="PASS_IMPORT_ONLY",
            purpose=manifest.purpose,
            episodes=len(rows),
            model_requests=0,
            environment_loads=0,
            real_tool_calls=0,
            full_D6_accepted=False,
            result_quality="See per-episode statuses; importer PASS does not mean tasks succeeded",
            evidence_sha256={p.relative_to(output).as_posix(): sha256(p) for p in sorted(output.glob("*.json"))},
        ),
    )
    print(f"PASS_IMPORT_ONLY: {len(rows)} records; no Agent execution; {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
