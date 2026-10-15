"""D1 fixed-candidate replay: real policy kernel, recording-only tools, no models."""

import argparse
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from camel.evaluation.fixtures import load_dataset, sha256
from camel.evaluation.replay import replay
from camel.policy import PolicyEngine, load_rules

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=ROOT / "tests/fixtures/d/d1_v1")
    parser.add_argument("--split", choices=["dev", "validation", "test", "all"], default="dev")
    parser.add_argument(
        "--harness-validation", action="store_true", help="Open frozen Test only to validate the replay harness"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.split in {"test", "all"} and not args.harness_validation:
        parser.error("Test access requires --harness-validation; no model evaluation is implemented")
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d"):
        parser.error("output must be a new directory under artifacts/d")

    # Prevent accidental model or tool networking in this process; this is not an OS sandbox.
    def offline_guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "urllib.Request"}:
            raise RuntimeError("D1 replay prohibits network access")

    sys.addaudithook(offline_guard)
    cases, manifest = load_dataset(args.fixtures.resolve())
    cases = [case for case in cases if args.split == "all" or case.split == args.split]
    if not cases:
        parser.error("no cases selected")
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc)
    engine = PolicyEngine(load_rules((args.fixtures / "policy.yaml").read_text(encoding="utf-8")))
    now = datetime.fromisoformat(manifest["clock"])
    observations = [replay(case, engine, now) for case in cases]
    # Determinism is checked before writing results; it is infrastructure validation, not another trial.
    repeated = [replay(case, engine, now) for case in cases]
    deterministic = observations == repeated
    counts = dict(Counter(row["status"] for row in observations))
    attacks = [row for row in observations if row["variant"] == "attack"]
    benign = [row for row in observations if row["variant"] == "benign"]
    metrics = {
        "attack_total": len(attacks),
        "attack_evaluable": sum(row["status"] != "BLOCKED" for row in attacks),
        "attack_forbidden_effect_observed": sum(bool(row["forbidden_observed"]) for row in attacks),
        "attack_blocked": sum(row["status"] == "BLOCKED" for row in attacks),
        "benign_total": len(benign),
        "benign_evaluable": sum(row["status"] != "BLOCKED" for row in benign),
        "benign_completed": sum(row["benign_completed"] is True for row in benign),
        "benign_blocked": sum(row["status"] == "BLOCKED" for row in benign),
        "detection_precision": None,
        "detection_recall": None,
        "model_asr": None,
    }
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    diff = subprocess.run(["git", "diff", "HEAD", "--no-ext-diff"], cwd=ROOT, capture_output=True, check=False)
    if git.returncode == 0:
        (output / "working_tree.patch").write_bytes(diff.stdout)
    sources = [
        ROOT / "scripts/d_eval.py",
        *sorted((ROOT / "src/camel/evaluation").glob("*.py")),
        *sorted((ROOT / "tests/unit/evaluation").glob("*.py")),
    ]
    source_hashes = {path.relative_to(ROOT).as_posix(): sha256(path) for path in sources}
    summary = {
        "stage": "D1",
        "run_id": output.name,
        "dataset_version": manifest["dataset_version"],
        "manifest_sha256": sha256(args.fixtures / "manifest.json"),
        "fixture_sha256": manifest["sha256"],
        "source_sha256": source_hashes,
        "lock_sha256": sha256(ROOT / "uv.lock"),
        "dependencies": {name: importlib.metadata.version(name) for name in ["pydantic", "PyYAML"]},
        "split": args.split,
        "purpose": "harness_validation" if args.harness_validation else "development_replay",
        "test_is_blind_model_evaluation": False,
        "clock": manifest["clock"],
        "random_seed": None,
        "model": None,
        "policy_version": engine.policy_version,
        "counts": counts,
        "counts_by_split": {
            split: dict(Counter(row["status"] for row in observations if row["split"] == split))
            for split in sorted({row["split"] for row in observations})
        },
        "counts_by_source": {
            source: dict(Counter(row["status"] for row in observations if row["source_type"] == source))
            for source in sorted({row["source_type"] for row in observations})
        },
        "metrics": metrics,
        "deterministic": deterministic,
        "base_commit": git.stdout.strip() if git.returncode == 0 else None,
        "git_checks_run": git.returncode == 0,
        "python": sys.version,
        "platform": platform.platform(),
        "hash_seed": os.environ.get("PYTHONHASHSEED"),
        "started_utc": started.isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "limitations": "E1/E2 fixed canonical candidates; no semantic planner/detector, model or real tool execution. Memory lifecycle unavailable. Test opened only for harness validation.",
    }
    (output / "observations.json").write_text(
        json.dumps(observations, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (output / "fixture_manifest.json").write_bytes((args.fixtures / "manifest.json").read_bytes())
    print(
        json.dumps({"counts": counts, "metrics": metrics, "deterministic": deterministic}, ensure_ascii=False, indent=2)
    )
    return int(counts.get("FAIL", 0) > 0 or not deterministic)


if __name__ == "__main__":
    raise SystemExit(main())
