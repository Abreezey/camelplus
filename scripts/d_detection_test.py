"""One reserved Test report for the Validation-selected frozen candidate."""

import argparse
import json
import runpy
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from camel.core import TrustLabel
from camel.core.labels import Authority, Confidentiality, Integrity
from camel.detection.candidate_v2 import VERSION, analyze
from camel.detection.models import identity_view
from camel.detection.rules import predicted_attack
from camel.evaluation.detection_followup import digest, load_pairs, metrics, observe
from camel.evaluation.replay import stable

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/d/evidence/D_detection_v2_test_protocol.json"
SELECTION = ROOT / "docs/d/evidence/D_detection_v2_validation_selection.json"
VALIDATION = ROOT / "docs/d/evidence/D_detection_v2_validation_acceptance.json"
HELPERS = runpy.run_path(str(ROOT / "scripts/d_detection_validation.py"))
read, write, check_evidence = HELPERS["read"], HELPERS["write"], HELPERS["check_evidence"]


def verify_selection(root: Path, selection: dict, acceptance: dict) -> None:
    if (
        selection.get("validation_selection_performed") is not True
        or selection.get("frozen_before_test") is not True
        or selection.get("test_evaluation_performed") is not False
        or selection.get("candidate_retained") is not True
        or selection.get("selected_detector") != VERSION
        or selection.get("decision") != "RETAIN_CANDIDATE_FOR_TEST"
        or selection.get("deployment_enabled") is not False
        or acceptance.get("test_evaluation_performed") is not False
        or selection.get("source_sha256") != acceptance.get("source_sha256")
        or not selection.get("validation_conditions")
        or not all(value is True for value in selection["validation_conditions"].values())
    ):
        raise ValueError("invalid_pretest_validation_selection")
    if (
        digest(root / "docs/d/evidence/D_detection_v2_validation_selection.json")
        != acceptance["selection_record_sha256"]
    ):
        raise ValueError("validation_selection_digest_changed")
    pin_path = root / "docs/d/evidence/D_detection_v2_candidate_freeze.json"
    if digest(pin_path) != selection["candidate_pin_sha256"]:
        raise ValueError("candidate_pin_digest_changed")
    HELPERS["verify_pin"](root, read(pin_path))
    for name, expected in {**selection["source_sha256"], **acceptance["published_evidence_sha256"]}.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file() or digest(path) != expected:
            raise ValueError("selected_runtime_or_evidence_changed:" + name)


def report_test(baseline: list[dict], candidate: list[dict], selected_detector: str) -> dict:
    if selected_detector != VERSION:
        raise ValueError("selected_detector_must_match_frozen_validation_choice")
    left, right = ({row["case_id"]: row for row in rows} for rows in (baseline, candidate))
    if not baseline or left.keys() != right.keys() or len(left) != len(baseline) or len(right) != len(candidate):
        raise ValueError("test_population_mismatch")
    for key, row in right.items():
        if (
            row["split"] != "test"
            or left[key]["split"] != "test"
            or any(row[field] != left[key][field] for field in ("group_id", "variant", "source_type", "mechanism"))
        ):
            raise ValueError("test_population_metadata_mismatch")
    return dict(
        baseline=metrics(baseline),
        candidate=metrics(candidate),
        selected_detector=selected_detector,
        changes=[
            dict(case_id=key, before=left[key]["prediction"], after=right[key]["prediction"])
            for key in sorted(right)
            if left[key]["prediction"] != right[key]["prediction"]
        ],
        test_used_for_selection=False,
        parameters_changed_after_test=False,
        deployment_enabled=False,
        agent_asr=None,
        benign_task_completion=None,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("fresh output under artifacts/d required")

    def guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request", "subprocess.Popen"}:
            raise RuntimeError("test_evaluation_prohibits_network_and_children")

    sys.addaudithook(guard)
    started = time.monotonic()
    protocol, selection, acceptance = read(PROTOCOL), read(SELECTION), read(VALIDATION)
    expected = dict(
        stage="FROZEN_SELECTED_CANDIDATE_TEST",
        candidate_version=VERSION,
        split="test",
        pairs=12,
        cases=24,
        max_run_seconds=60,
        one_local_reservation_per_candidate=True,
        selection_from_validation_only=True,
        test_driven_selection_or_tuning=False,
        model_requests=0,
        real_tool_calls=0,
        downloads=0,
        deployment_enabled=False,
    )
    if any(protocol.get(key) != value for key, value in expected.items()):
        raise ValueError("test_protocol_mismatch")
    verify_selection(ROOT, selection, acceptance)
    pairs, manifest, _ = load_pairs(ROOT)
    files = [PROTOCOL, SELECTION, VALIDATION, Path(__file__), ROOT / "tests/unit/evaluation/test_detection_test.py"]
    hashes = {**selection["source_sha256"], **{p.relative_to(ROOT).as_posix(): digest(p) for p in files}}
    reservation = ROOT / "artifacts/d/D_v2_test_reservation.json"
    reservation.parent.mkdir(parents=True, exist_ok=True)
    write(
        reservation,
        dict(
            status="RESERVED",
            stage="TEST",
            candidate_version=VERSION,
            output=output.relative_to(ROOT).as_posix(),
            source_sha256=hashes,
            selection_sha256=digest(SELECTION),
            created_utc=datetime.now(timezone.utc).isoformat(),
        ),
        exclusive=True,
    )
    output.mkdir(parents=True)
    write(
        output / "freeze.json",
        dict(
            protocol=protocol,
            source_sha256=hashes,
            selection=selection,
            dataset_manifest=manifest,
            before_first_test_prediction=True,
            author_has_seen_all_text=True,
            blind_test=False,
            deployment_enabled=False,
        ),
    )
    baseline_rows, candidate_rows = [], []
    try:
        for pair in pairs:
            if pair.split != "test":
                continue
            for case in pair.cases:
                if time.monotonic() - started > protocol["max_run_seconds"]:
                    raise TimeoutError("test_deadline_exceeded")
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
                view = identity_view(source_id, pair.source_type, case.text, label)
                baseline = observe(pair, case)
                result = analyze((view,))
                if stable(result.baseline) != baseline["detection"]:
                    raise ValueError("test_baseline_input_mismatch")
                check_evidence(view, result.baseline)
                check_evidence(view, result.detection)
                for item in result.suppressed:
                    check_evidence(view, result.detection.model_copy(update={"findings": (item.finding,)}))
                    e = item.finding.evidence
                    if not (
                        0
                        <= item.context_start
                        <= item.quote_start
                        < e.start
                        < e.end
                        < item.quote_end
                        <= item.context_end
                        <= len(case.text)
                    ):
                        raise ValueError("ungrounded_test_suppression")
                baseline_rows.append(baseline)
                candidate_rows.append(
                    {
                        **baseline,
                        "prediction": predicted_attack(result.detection),
                        "detection": stable(result.detection),
                        "suppressed": stable(result.suppressed),
                    }
                )
                write(output / "baseline_observations.json", baseline_rows)
                write(output / "candidate_observations.json", candidate_rows)
        if len(candidate_rows) != 24 or len({row["group_id"] for row in candidate_rows}) != 12:
            raise ValueError("incomplete_test_population")
        result_report = report_test(baseline_rows, candidate_rows, selection["selected_detector"])
        if any(digest(ROOT / name) != expected_hash for name, expected_hash in hashes.items()):
            raise ValueError("test_inputs_changed_during_run")
        if time.monotonic() - started > protocol["max_run_seconds"]:
            raise TimeoutError("test_total_deadline_exceeded")
        write(
            output / "summary.json",
            dict(
                status="COMPLETED_TEST_REPORT_ONLY",
                cases=24,
                pairs=12,
                evaluated_split="test",
                result=result_report,
                source_sha256=hashes,
                selection_sha256=digest(SELECTION),
                model_requests=0,
                real_tool_calls=0,
                downloads=0,
                blind_test=False,
                deployment_enabled=False,
            ),
        )
        write(
            output / "receipt.json",
            dict(
                status="COMPLETED",
                reservation_sha256=digest(reservation),
                summary_sha256=digest(output / "summary.json"),
                test_used_for_selection=False,
                elapsed_seconds=time.monotonic() - started,
            ),
        )
        print(
            json.dumps(
                dict(
                    baseline=result_report["baseline"]["counts"],
                    candidate=result_report["candidate"]["counts"],
                    selected_detector=VERSION,
                    test_used_for_selection=False,
                )
            )
        )
        return 0
    except Exception as error:
        write(
            output / "failure.json",
            dict(
                status="FAILED_RESERVED_NO_AUTOMATIC_RETRY",
                error_type=type(error).__name__,
                error=str(error),
                observed_cases=len(candidate_rows),
            ),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
