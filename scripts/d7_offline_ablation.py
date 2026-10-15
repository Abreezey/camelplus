"""D-only cached detector and Memory Gate ablations; not full D7 or Agent ASR."""

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from d4_eval import memory_case

from camel.detection.remote.scoring import similarity_score
from camel.detection.rules import detect
from camel.evaluation.ablation import ARMS, Choice, choose, join_sources, paired_bootstrap, replay_choice, summarize
from camel.evaluation.fixtures import load_dataset, sha256
from camel.evaluation.replay import replay, stable
from camel.policy import PolicyEngine, load_rules

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D7_offline_protocol.json"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(stable(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=ROOT / "artifacts/d/D3b_20261015_gateway_01/v2")
    parser.add_argument("--harness-validation", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    cache_dir = args.cache.resolve()
    if not args.harness_validation:
        parser.error("known Test access requires --harness-validation; no blind-Test claim")
    if (
        not output.is_relative_to(ROOT / "artifacts/d")
        or output.exists()
        or not cache_dir.is_relative_to(ROOT / "artifacts/d")
    ):
        parser.error("use an existing local cache and fresh output under artifacts/d")

    def offline_guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request"}:
            raise RuntimeError("D offline ablation prohibits network")

    sys.addaudithook(offline_guard)
    protocol = read(PROTOCOL)
    if protocol["detector_arms"] != list(ARMS):
        raise ValueError("protocol_arm_mismatch")
    output.mkdir(parents=True)
    cases, manifest = load_dataset(ROOT / "tests/fixtures/d/d1_v1")
    now = datetime.fromisoformat(manifest["clock"])
    sources = [
        ROOT / "scripts/d7_offline_ablation.py",
        ROOT / "scripts/d4_eval.py",
        ROOT / "scripts/d3b_replay.py",
        *[
            path
            for folder in ("core", "policy", "audit", "detection", "memory", "evaluation")
            for path in (ROOT / "src/camel" / folder).rglob("*.py")
        ],
    ]
    cache_files = [*cache_dir.glob("*.json"), cache_dir.parent / "request_budget.json"]
    source_hashes = {path.relative_to(ROOT).as_posix(): sha256(path) for path in sorted(sources)}
    cache_hashes = {path.relative_to(ROOT).as_posix(): sha256(path) for path in sorted(cache_files)}
    write(
        output / "freeze.json",
        dict(
            protocol=protocol,
            protocol_sha256=sha256(PROTOCOL),
            source_sha256=source_hashes,
            cache_sha256=cache_hashes,
            fixture_sha256=manifest["sha256"],
            created_utc=datetime.now(timezone.utc).isoformat(),
        ),
    )
    # Original raw-response and Dev-calibration verification, no network/client construction.
    preflight = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/d3b_replay.py"),
            "--run",
            str(cache_dir),
            "--output",
            str(output / "cache_verification"),
        ],
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    (output / "cache_verification.txt").write_text(preflight.stdout + preflight.stderr, encoding="utf-8")
    if preflight.returncode:
        raise RuntimeError("original_cache_preflight_failed")
    cache = read(cache_dir / "cache.json")
    calibration = read(cache_dir / "calibration_freeze.json")
    engine = PolicyEngine(load_rules((ROOT / "tests/fixtures/d/d1_v1/policy.yaml").read_text(encoding="utf-8")))
    rows = []
    for case in cases:
        _, views = join_sources(case)
        for arm in ARMS:
            choice = choose(
                arm,
                rules=lambda: detect(views),
                embedding=lambda: similarity_score(
                    cache[case.case_id]["embedding"],
                    calibration["positive_prototype"],
                    calibration["negative_prototype"],
                )
                >= calibration["threshold"],
                verifier=lambda: cache[case.case_id]["verifier"],
                source_ids=tuple(view.source_id for view in views),
            )
            row = replay_choice(case, engine, now, choice)
            row["arm"] = arm
            rows.append(row)
    reference = read(cache_dir / "observations.json")
    index = {(row["arm"], row["case_id"]): row for row in rows}
    for old in reference:
        current = index[old["arm"], old["case_id"]]
        for field in (
            "classification",
            "prediction",
            "incomplete",
            "decisions",
            "ledger",
            "benign_completed",
            "forbidden_observed",
        ):
            if stable(current[field]) != old[field]:
                raise RuntimeError("original_detector_arm_changed:" + old["case_id"] + ":" + field)
    detector_summary = {
        arm: dict(
            all=summarize([row for row in rows if row["arm"] == arm]),
            by_split={
                split: summarize([row for row in rows if row["arm"] == arm and row["split"] == split])
                for split in ("dev", "validation", "test")
            },
        )
        for arm in ARMS
    }
    memory = []
    stores = output / "memory_stores"
    stores.mkdir()
    for case in cases:
        if case.source_type != "memory":
            continue
        off = replay_choice(case, engine, now, Choice((), None, (), False, ()), lifecycle_disabled=True)
        off["arm"] = "memory_off"
        on = memory_case(case, engine, now, stores)
        if on["status"] != "PASS" or off["labels"] != on["labels"]:
            raise RuntimeError("memory_reference_or_label_comparability_failed")
        on_row = dict(
            case_id=case.case_id,
            family_id=case.family_id,
            split=case.split,
            variant=case.variant,
            source_type=case.source_type,
            arm="memory_on",
            classification="NA",
            prediction=None,
            incomplete=False,
            enabled_layers=(),
            invoked_layers=(),
            lifecycle_blocked=False,
            decisions={
                key: dict(
                    baseline=value["kernel"]["decision"],
                    actual=value["with_memory_gate"],
                    deny_retained=value["kernel_deny_retained"],
                )
                for key, value in on["decisions"].items()
            },
            labels=on["labels"],
            ledger=on["ledger"],
            forbidden_observed=on["forbidden_observed"],
            benign_completed=on["benign_completed"],
            memory_internal_write_quarantine=True,
        )
        memory.extend([off, on_row])
        write(stores / (case.case_id + "_gate_observation.json"), on)
    memory_summary = {
        arm: summarize([row for row in memory if row["arm"] == arm]) for arm in ("memory_off", "memory_on")
    }
    controls = [replay(case, engine, now) for case in cases if case.source_type != "memory"]
    if any(row["status"] != "PASS" for row in controls):
        raise RuntimeError("nonmemory_control_changed")
    paired = {}
    bootstrap_options = dict(replicates=protocol["bootstrap"]["replicates"], seed=protocol["bootstrap"]["seed"])
    full = [row for row in rows if row["arm"] == "rules_embedding_verifier"]
    for arm in ("rules_embedding", "rules_verifier", "embedding_verifier"):
        paired["full_minus_" + arm] = paired_bootstrap(
            full, [row for row in rows if row["arm"] == arm], **bootstrap_options
        )
    paired["memory_on_minus_off"] = paired_bootstrap(
        [row for row in memory if row["arm"] == "memory_on"],
        [row for row in memory if row["arm"] == "memory_off"],
        **bootstrap_options,
    )
    for path, digest in cache_hashes.items():
        if sha256(ROOT / path) != digest:
            raise RuntimeError("input_cache_changed")
    summary = dict(
        stage="D7_partial_D_only_offline",
        status="PASS",
        full_D7_accepted=False,
        detector_rows=len(rows),
        memory_rows=len(memory),
        nonmemory_controls=len(controls),
        detector=detector_summary,
        memory=memory_summary,
        original_144_detector_rows_reproduced=True,
        source_sha256=source_hashes,
        protocol_sha256=sha256(PROTOCOL),
        threshold=calibration["threshold"],
        model_requests=0,
        downloads=0,
        python=sys.version,
        platform=platform.platform(),
        cache_unchanged=True,
        fixture_sha256=manifest["sha256"],
        not_run=[
            "Planner/IR removal",
            "isolated parser removal",
            "IFC/contract/Gateway/sandbox removal",
            "real-agent replanning",
            "new heldout/adaptive attacks",
            "external benchmarks",
        ],
        limits="Known fixed canonical trajectories, cached model responses and recording-only effects. No online ASR, actual forbidden IO, new deployment choice or full D7 acceptance.",
    )
    for name, value in (
        ("detector_observations.json", rows),
        ("memory_observations.json", memory),
        ("nonmemory_controls.json", controls),
        ("paired_bootstrap.json", paired),
        ("summary.json", summary),
    ):
        write(output / name, value)
    print(
        json.dumps(
            dict(
                detector_rows=len(rows),
                memory_rows=len(memory),
                detector_counts={arm: result["all"]["counts"] for arm, result in detector_summary.items()},
                memory_forbidden={arm: result["attack_forbidden_recorded"] for arm, result in memory_summary.items()},
            ),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
