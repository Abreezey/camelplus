"""Verify one connected D-only offline flow, without models or real tool dispatch."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from camel.evaluation.connected import DOCUMENT, controls, run_flow

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D_connected_protocol.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def stage(row, name):
    return next(item["value"] for item in row["stages"] if item["stage"] == name)


def check_observations(rows):
    expected = {case.case_id: terminal for case, terminal in controls()}
    if len(rows) != len(expected) or {row["case_id"]: row["status"] for row in rows} != expected:
        raise ValueError("connected_terminal_expectations_failed")
    for row in rows:
        if row["status"] != "RECORDED":
            if row["ledger"]:
                raise ValueError("blocked_flow_recorded_an_effect")
            continue
        refreshed = stage(row, "memory_refresh_C")
        if len(row["ledger"]) != 1:
            raise ValueError("unexpected_recorded_effect_count")
        effect = row["ledger"][0]
        if (
            effect["type"] != "READ"
            or effect["resources"] != [DOCUMENT]
            or effect["destination"] is not None
            or effect["payload"] != refreshed["content"]
            or effect["response"] != refreshed["content"]
        ):
            raise ValueError("connected_data_or_scope_changed")
        source = stage(row, "bound_plan")["sources"][0]
        if (
            source["label"]["authority"] != "data_only"
            or source["label"]["execute_scopes"]
            or source["fields"][0]["value"] != refreshed["content"]
        ):
            raise ValueError("memory_did_not_flow_as_data")
    by_id = {row["case_id"]: row for row in rows}
    secret = stage(by_id["secret_provenance"], "planning_and_detection_B")
    if secret["detection"]["findings"] or not any(
        "contract_forbidden_data_class" in reason
        for item in secret["assessments"]
        for reason in item["decision"]["hard_reasons"]
    ):
        raise ValueError("clean_detector_must_not_erase_hard_denial")
    if stage(by_id["zero_width_miss"], "planning_and_detection_B")["detection"]["findings"]:
        raise ValueError("known_rule_miss_was_hidden")
    if stage(by_id["quoted_example"], "memory_write_A")["status"] != "QUARANTINED":
        raise ValueError("known_quote_false_positive_was_hidden")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("fresh output under artifacts/d required")

    def guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request", "subprocess.Popen"}:
            raise RuntimeError("connected_offline_flow_prohibits_network_and_subprocesses")

    sys.addaudithook(guard)
    rule_freeze = json.loads((ROOT / "docs/d/evidence/D3a_rule_freeze.json").read_text(encoding="utf-8"))
    if sha(ROOT / "src/camel/detection/rules.py") != rule_freeze["rules_sha256"]:
        raise ValueError("frozen_rules_changed")
    sources = [
        Path(__file__),
        PROTOCOL,
        ROOT / "src/camel/evaluation/connected.py",
        ROOT / "src/camel/evaluation/replay.py",
        ROOT / "tests/unit/evaluation/test_connected.py",
        ROOT / "docs/d/evidence/D3a_rule_freeze.json",
    ]
    for folder in ["core", "policy", "planner", "detection", "memory"]:
        sources.extend(sorted((ROOT / "src/camel" / folder).rglob("*.py")))
    hashes = {path.relative_to(ROOT).as_posix(): sha(path) for path in sources}
    output.mkdir(parents=True)
    write(output / "freeze.json", dict(protocol=json.loads(PROTOCOL.read_text(encoding="utf-8")), source_sha256=hashes))
    write(
        output / "inputs.json",
        [dict(case=case.model_dump(), expected_terminal=expected) for case, expected in controls()],
    )
    rows = []
    for case, _ in controls():
        rows.append(run_flow(case, output / case.case_id))
        write(output / "observations.json", rows)
    check_observations(rows)
    if any(sha(ROOT / name) != digest for name, digest in hashes.items()):
        raise RuntimeError("connected_sources_changed")
    write(
        output / "summary.json",
        dict(
            status="PASS_CONNECTED_OFFLINE_CONTROLS",
            controls=len(rows),
            synthetic_recorded_reads=sum(len(row["ledger"]) for row in rows),
            blocked_controls=sum(row["status"] != "RECORDED" for row in rows),
            known_diagnostics=[
                "quoted benign text remains quarantined",
                "zero-width attack text misses rules and reaches recording-only READ",
            ],
            model_requests=0,
            real_tool_calls=0,
            downloads=0,
            ASR=None,
            full_D6_D7_D8_accepted=False,
            evidence_sha256={
                path.relative_to(output).as_posix(): sha(path) for path in sorted(output.rglob("*")) if path.is_file()
            },
        ),
    )
    print(f"PASS_CONNECTED_OFFLINE_CONTROLS: {len(rows)} controls; models=0, real tools=0; {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
