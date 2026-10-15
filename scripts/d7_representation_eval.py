"""Offline known-seed representation robustness; no model or tool execution."""

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from camel.detection.rules import OPERATING_POINT, VERSION
from camel.evaluation.fixtures import load_dataset, sha256
from camel.evaluation.replay import stable
from camel.evaluation.representation import VARIANTS, observe, paired, summarize

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D7_representation_protocol.json"
FIXTURES = ROOT / "tests/fixtures/d/d1_v1"


def write(path, value):
    path.write_text(json.dumps(stable(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--harness-validation", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if not args.harness_validation or not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("known seeds require --harness-validation and fresh output under artifacts/d")

    def offline_guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request", "subprocess.Popen"}:
            raise RuntimeError("offline_representation_evaluation_prohibits_network_and_children")

    sys.addaudithook(offline_guard)
    started = time.monotonic()
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    if protocol["variants"] != list(VARIANTS) or protocol["user_selected_cases"] != 384:
        raise ValueError("representation_protocol_mismatch")
    original_freeze = json.loads((ROOT / "docs/d/evidence/D3a_rule_freeze.json").read_text(encoding="utf-8"))
    if (
        sha256(ROOT / "src/camel/detection/rules.py") != original_freeze["rules_sha256"]
        or VERSION != original_freeze["version"]
        or OPERATING_POINT != original_freeze["operating_point"]
    ):
        raise ValueError("fixed_detector_changed")
    cases, manifest = load_dataset(FIXTURES)
    paths = [
        PROTOCOL,
        Path(__file__),
        ROOT / "tests/unit/evaluation/test_representation.py",
        *[
            path
            for folder in ("core", "detection", "evaluation")
            for path in (ROOT / "src/camel" / folder).rglob("*.py")
        ],
    ]
    source_hashes = {path.relative_to(ROOT).as_posix(): sha256(path) for path in sorted(paths)}
    fixture_hashes = {name: sha256(FIXTURES / name) for name in ("cases.jsonl", "manifest.json", "policy.yaml")}
    budget = ROOT / "artifacts/d/D3b_20261015_gateway_01/request_budget.json"
    budget_hash = sha256(budget) if budget.exists() else None
    output.mkdir(parents=True)
    write(
        output / "freeze.json",
        dict(
            protocol=protocol,
            source_sha256=source_hashes,
            fixture_sha256=fixture_hashes,
            original_rule_freeze=original_freeze,
            request_budget_sha256=budget_hash,
            created_utc=datetime.now(timezone.utc).isoformat(),
        ),
    )
    rows = []
    reports = {}
    for variant in VARIANTS:
        current = [observe(case, variant) for case in cases]
        reports[variant] = dict(
            all=summarize(current),
            by_split={
                split: summarize([r for r in current if r["split"] == split]) for split in ("dev", "validation", "test")
            },
            by_source={
                source: summarize([r for r in current if r["source_type"] == source])
                for source in sorted({c.source_type for c in cases})
            },
            by_family={
                family: summarize([r for r in current if r["family_id"] == family])
                for family in sorted({c.family_id for c in cases})
            },
        )
        if variant == "identity" and reports[variant]["all"]["counts"] != dict(TP=21, FP=6, FN=3, TN=18, UNKNOWN=0):
            raise RuntimeError("original_rule_baseline_not_reproduced")
        rows.extend(current)
        if time.monotonic() - started > protocol["budget"]["max_seconds_per_run"]:
            raise RuntimeError("representation_time_budget_exceeded")
    if len(rows) != 384:
        raise RuntimeError("representation_population_changed")
    reference = [row for row in rows if row["representation"] == "identity"]
    baseline = {row["case_id"]: row for row in reference}
    for row in rows:
        before = baseline[row["case_id"]]
        if row["labels"] != before["labels"]:
            raise RuntimeError("representation_changed_authority_labels")
        row["identity_classification"] = before["classification"]
        row["classification_changed"] = row["classification"] != before["classification"]
        for source in row["sources"]:
            source["original_sha256"] = hashlib.sha256(source["original_text"].encode()).hexdigest()
            source["transformed_sha256"] = hashlib.sha256(source["transformed_text"].encode()).hexdigest()
    comparisons = {
        variant: paired(
            [row for row in rows if row["representation"] == variant],
            reference,
            replicates=protocol["paired"]["replicates"],
            seed=protocol["paired"]["seed"],
        )
        for variant in VARIANTS[1:]
    }
    if time.monotonic() - started > protocol["budget"]["max_seconds_per_run"]:
        raise RuntimeError("representation_time_budget_exceeded")
    if any(sha256(ROOT / name) != digest for name, digest in source_hashes.items()):
        raise RuntimeError("source_changed_during_evaluation")
    if any(sha256(FIXTURES / name) != digest for name, digest in fixture_hashes.items()):
        raise RuntimeError("seed_fixture_changed_during_evaluation")
    if budget_hash is not None and sha256(budget) != budget_hash:
        raise RuntimeError("shared_request_budget_changed")
    write(output / "observations.json", rows)
    write(output / "paired_bootstrap.json", comparisons)
    write(
        output / "summary.json",
        dict(
            stage=protocol["stage"],
            status="PASS",
            full_D7_accepted=False,
            baseline_reproduced=True,
            representations=reports,
            cases=384,
            independent_families=24,
            model_requests=0,
            real_tool_calls=0,
            downloads=0,
            source_sha256=source_hashes,
            fixture_sha256=fixture_hashes,
            request_budget_unchanged=True if budget_hash is not None else "NOT_PRESENT",
            platform=sys.platform,
            windows_version=str(sys.getwindowsversion()) if sys.platform == "win32" else None,
            python=sys.version,
            not_run=protocol["not_run"],
            limits=protocol["limits"],
        ),
    )
    write(output / "timing.json", dict(elapsed_seconds=time.monotonic() - started))
    print(f"PASS: 384 observations across 24 known seed families; evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
