"""Validate all new pairs; evaluate only Dev with the original frozen rules."""

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from camel.detection.rules import OPERATING_POINT, VERSION
from camel.evaluation.detection_followup import digest, load_pairs, metrics, nearest_neighbors, observe

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D_detection_followup_protocol.json"


def write(path: Path, value) -> None:
    path.write_bytes((json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("fresh output under artifacts/d required")

    def offline_guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request", "subprocess.Popen"}:
            raise RuntimeError("offline_followup_prohibits_network_and_children")

    sys.addaudithook(offline_guard)
    started = time.monotonic()
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    rule_path = ROOT / "src/camel/detection/rules.py"
    canonical_rule_hash = hashlib.sha256(rule_path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if (
        canonical_rule_hash != protocol["rule_sha256_lf"]
        or VERSION != protocol["detector_version"]
        or OPERATING_POINT != protocol["operating_point"]
        or protocol["allowed_evaluation_splits"] != ["dev"]
        or protocol["pairs"] != 36
        or protocol["cases"] != 72
        or protocol["max_case_characters"] != 4000
    ):
        raise ValueError("frozen_followup_protocol_mismatch")
    pairs, manifest, old_sources = load_pairs(ROOT)
    paths = [
        PROTOCOL,
        ROOT / "docs/d/D_detection_followup_protocol.md",
        Path(__file__),
        ROOT / "tests/unit/evaluation/test_detection_followup.py",
        *sorted((ROOT / "tests/fixtures/d/detection_v2").glob("*.json")),
        *sorted((ROOT / "tests/fixtures/d/d1_v1").iterdir()),
        *sorted((ROOT / "src/camel").rglob("*.py")),
    ]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path) for path in paths}
    output.mkdir(parents=True)
    write(
        output / "freeze.json",
        dict(
            created_utc=datetime.now(timezone.utc).isoformat(),
            manifest=manifest,
            protocol=protocol,
            sha256=hashes,
            before_first_detection=True,
            author_has_seen_all_text=True,
            validation_test_predictions_computed=False,
        ),
    )
    review = nearest_neighbors(pairs, old_sources)
    write(output / "overlap_review.json", review)
    if args.validate_only:
        rows = []
    else:
        rows = [observe(pair, case) for pair in pairs if pair.split == "dev" for case in pair.cases]
    if time.monotonic() - started > protocol["max_run_seconds"]:
        raise RuntimeError("followup_time_budget_exceeded")
    if any(digest(ROOT / name) != expected for name, expected in hashes.items()):
        raise RuntimeError("frozen_input_changed_during_run")
    write(output / "observations.json", rows)
    write(
        output / "summary.json",
        dict(
            status="PASS_DATA_VALIDATION" if args.validate_only else "PASS_BASELINE_RECORDED",
            quality_accepted=False,
            dataset_pairs=36,
            dataset_cases=72,
            evaluated_split=None if args.validate_only else "dev",
            evaluated_cases=len(rows),
            not_evaluated_splits=["dev", "validation", "test"] if args.validate_only else ["validation", "test"],
            metrics=metrics(rows) if rows else None,
            by_mechanism={
                name: metrics([row for row in rows if row["mechanism"] == name])
                for name in sorted({row["mechanism"] for row in rows})
            },
            by_source={
                name: metrics([row for row in rows if row["source_type"] == name])
                for name in sorted({row["source_type"] for row in rows})
            },
            model_requests=0,
            real_tool_calls=0,
            downloads=0,
            full_D7_accepted=False,
            blind_test=False,
            source_sha256=hashes,
            rule_sha256_lf=canonical_rule_hash,
        ),
    )
    write(
        output / "timing.json",
        dict(elapsed_seconds=time.monotonic() - started, platform=sys.platform, python=sys.version),
    )
    print(f"{len(pairs)} pairs validated; {len(rows)} Dev observations; Validation/Test not evaluated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
