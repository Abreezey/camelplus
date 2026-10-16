"""Dev-only frozen baseline/candidate diagnostics and interleaved CPU cost."""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from camel.core import TrustLabel
from camel.core.labels import Authority, Confidentiality, Integrity
from camel.detection.candidate_v2 import VERSION, analyze, detect
from camel.detection.models import identity_view
from camel.detection.rules import detect as baseline_detect
from camel.detection.rules import predicted_attack
from camel.evaluation.detection_candidate import measure_cost, paired_diagnostics
from camel.evaluation.detection_followup import digest, load_pairs, observe
from camel.evaluation.replay import stable

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D_detection_v2_protocol.json"


def write(path: Path, value) -> None:
    path.write_bytes((json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode())


def append_event(path: Path, value) -> None:
    with path.open("ab") as stream:
        stream.write((json.dumps(value, sort_keys=True) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("fresh output under artifacts/d required; only Dev is supported")

    def guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request", "subprocess.Popen"}:
            raise RuntimeError("candidate_evaluation_prohibits_network_and_children")

    sys.addaudithook(guard)
    started = time.monotonic()
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    expected = dict(
        candidate_version=VERSION,
        allowed_split="dev",
        unique_cases_per_run=24,
        threshold=0.75,
        max_sources=1,
        max_source_characters=4000,
        max_findings=64,
        quote_context_characters_each_side=80,
        max_quote_nesting=4,
        rounds=100,
        warmup_rounds=10,
        max_run_seconds=60,
        model_requests=0,
        real_tool_calls=0,
        representation_normalization=False,
        deployment_enabled=False,
    )
    if any(protocol.get(key) != value for key, value in expected.items()):
        raise ValueError("candidate_protocol_mismatch")
    pairs, manifest, _ = load_pairs(ROOT)
    prior = json.loads((ROOT / "docs/d/evidence/D_detection_followup_acceptance.json").read_text(encoding="utf-8"))
    for name, expected_hash in {**prior["source_sha256"], **prior["published_evidence_sha256"]}.items():
        if digest(ROOT / name) != expected_hash:
            raise ValueError("prior_baseline_freeze_changed:" + name)
    files = [
        PROTOCOL,
        Path(__file__),
        ROOT / "tests/unit/detection/test_candidate_v2.py",
        ROOT / "tests/unit/evaluation/test_detection_candidate.py",
        ROOT / "docs/d/evidence/D_detection_followup_acceptance.json",
        *[ROOT / name for name in prior["source_sha256"]],
        *sorted((ROOT / "src/camel").rglob("*.py")),
    ]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path) for path in files}
    ledger = ROOT / "artifacts/d/D_v2_dev_runs.jsonl"
    lock_path = ROOT / "artifacts/d/D_v2_dev_runs.lock"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents two callers from racing the append-only run ledger.
    with lock_path.open("x", encoding="utf-8") as lock:
        lock.write(str(os.getpid()))
    reserved = False
    completed = False
    index = 0
    try:
        events = (
            [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()] if ledger.exists() else []
        )
        index = 1 + sum(event["event"] == "STARTED" for event in events)
        output.mkdir(parents=True)
        run_id = output.relative_to(ROOT).as_posix()
        append_event(
            ledger,
            dict(
                event="STARTED",
                run=index,
                run_id=run_id,
                candidate_version=VERSION,
                source_sha256=hashes,
                created_utc=datetime.now(timezone.utc).isoformat(),
            ),
        )
        reserved = True
        write(
            output / "freeze.json",
            dict(
                source_sha256=hashes,
                protocol=protocol,
                manifest=manifest,
                dev_run=index,
                before_dev_diagnostics=True,
                author_has_seen_all_text=True,
                validation_test_predictions_computed=False,
            ),
        )
        reference, candidate, population = [], [], []
        for pair in pairs:
            if pair.split != "dev":
                continue
            for case in pair.cases:
                source_id = "source:" + case.case_id
                label = TrustLabel(
                    schema_version=1,
                    provenance=frozenset({source_id}),
                    integrity=Integrity.UNTRUSTED,
                    confidentiality=Confidentiality.PUBLIC,
                    authority=Authority.DATA_ONLY,
                    execute_scopes=frozenset(),
                    readers=None,
                    data_classes=frozenset(),
                )
                views = (identity_view(source_id, pair.source_type, case.text, label),)
                baseline = observe(pair, case)
                result = analyze(views)
                if stable(result.baseline) != baseline["detection"]:
                    raise ValueError("candidate_baseline_input_mismatch")
                row = {
                    **baseline,
                    "prediction": predicted_attack(result.detection),
                    "detection": stable(result.detection),
                    "suppressed": stable(result.suppressed),
                }
                for finding in result.detection.findings:
                    evidence = finding.evidence
                    if (
                        evidence.source_id != source_id
                        or evidence.view != "raw"
                        or not 0 <= evidence.start < evidence.end <= len(case.text)
                        or evidence.raw_spans != ((evidence.start, evidence.end),)
                    ):
                        raise ValueError("ungrounded_candidate_evidence")
                reference.append(baseline)
                candidate.append(row)
                population.append(views)
        if len(candidate) != 24 or len({row["case_id"] for row in candidate}) != 24:
            raise ValueError("candidate_dev_population_mismatch")
        if paired_diagnostics(reference, reference)["baseline"] != prior["metrics"]:
            raise ValueError("prior_dev_baseline_not_reproduced")
        diagnostic = paired_diagnostics(reference, candidate)
        write(output / "baseline_observations.json", reference)
        write(output / "candidate_observations.json", candidate)
        cost = measure_cost(tuple(population), baseline_detect, detect, deadline=started + protocol["max_run_seconds"])
        write(output / "cost.json", cost)
        if time.monotonic() > started + protocol["max_run_seconds"]:
            raise TimeoutError("candidate_total_deadline_exceeded")
        for name, expected_hash in hashes.items():
            if digest(ROOT / name) != expected_hash:
                raise ValueError("candidate_source_changed_during_run:" + name)
        write(
            output / "summary.json",
            dict(
                status="PASS_DEV_DIAGNOSTICS",
                candidate_version=VERSION,
                evaluated_split="dev",
                cases=24,
                diagnostic=diagnostic,
                dev_cost_eligible=cost["dev_cost_eligible"],
                dev_candidate_ready_for_validation=diagnostic["dev_quality_conditions_met"]
                and cost["dev_cost_eligible"],
                validation_selection_performed=False,
                test_evaluation_performed=False,
                deployment_enabled=False,
                model_requests=0,
                real_tool_calls=0,
                downloads=0,
                agent_asr=None,
                unique_pairs=12,
                source_sha256=hashes,
                known_limitations=protocol["known_limitations"],
            ),
        )
        write(
            output / "timing.json",
            dict(elapsed_seconds=time.monotonic() - started, platform=sys.platform, python=sys.version, dev_run=index),
        )
        completed = True
        print(
            json.dumps(
                dict(
                    candidate=diagnostic["candidate"]["counts"],
                    dev_cost_eligible=cost["dev_cost_eligible"],
                    validation_test_evaluated=False,
                )
            )
        )
        return 0
    except Exception as error:
        if output.exists():
            write(output / "failure.json", dict(status="FAILED", error_type=type(error).__name__, error=str(error)))
        raise
    finally:
        try:
            if reserved:
                append_event(
                    ledger,
                    dict(
                        event="COMPLETED" if completed else "FAILED",
                        run=index,
                        run_id=output.relative_to(ROOT).as_posix(),
                    ),
                )
        finally:
            lock_path.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
