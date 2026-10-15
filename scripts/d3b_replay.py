"""Rebuild D3b judgments/prototypes/tool observations from saved responses, with networking denied."""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from camel.detection.remote.client import write_json
from camel.detection.remote.scoring import (
    calibrate,
    embedding_response,
    evaluate_case,
    model_sources,
    similarity_score,
    verify_response,
)
from camel.evaluation.fixtures import load_dataset, sha256
from camel.policy import PolicyEngine, load_rules

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = args.run.resolve()
    output = args.output.resolve()
    if not directory.is_relative_to(ROOT / "artifacts/d") or not output.is_relative_to(ROOT / "artifacts/d"):
        parser.error("run/output must remain under artifacts/d")

    def offline_guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "urllib.Request"}:
            raise RuntimeError("cached replay prohibits networking")

    sys.addaudithook(offline_guard)

    def read(name):
        return json.loads((directory / name).read_text(encoding="utf-8"))

    freeze = read("protocol_freeze.json")
    assert all(sha256(ROOT / name) == digest for name, digest in freeze["source_sha256"].items())
    cases, manifest = load_dataset(ROOT / "tests/fixtures/d/d1_v1")
    assert manifest["sha256"] == freeze["fixture_sha256"]
    smoke_families = freeze["smoke_families"]
    groups = [
        [case for case in cases if case.split == "dev" and case.family_id in smoke_families],
        [case for case in cases if case.split == "dev" and case.family_id not in smoke_families],
        [case for case in cases if case.split == "validation"],
        [case for case in cases if case.split == "test"],
    ]
    vectors = {}
    for group in groups:
        response = read("embedding_" + group[0].case_id + ".json")
        vectors.update(
            {case.case_id: vector for case, vector in zip(group, embedding_response(response, len(group)), strict=True)}
        )
    cache = read("cache.json")
    assert all(cache[case.case_id]["embedding"] == vectors[case.case_id] for case in cases)
    calibration = calibrate([case for case in cases if case.split == "dev"], vectors)
    frozen_calibration = read("calibration_freeze.json")
    assert all(value == frozen_calibration[name] for name, value in calibration.items())
    engine = PolicyEngine(load_rules((ROOT / "tests/fixtures/d/d1_v1/policy.yaml").read_text(encoding="utf-8")))
    rows = []
    for case in cases:
        aliases = model_sources(case)
        try:
            verdict = verify_response(read(case.case_id + "_response.json"), aliases)
            actual = {alias.source_id: event.source_id for alias, event in zip(aliases, case.input_events, strict=True)}
            verdict["model_source_id"] = verdict["source_id"]
            verdict["source_id"] = actual[verdict["source_id"]]
        except (ValueError, KeyError, TypeError, IndexError, OverflowError):
            verdict = {"status": "INVALID_OR_FAILED_RESPONSE"}
        assert verdict == cache[case.case_id]["verifier"]
        score = similarity_score(
            vectors[case.case_id], calibration["positive_prototype"], calibration["negative_prototype"]
        )
        rows.extend(
            evaluate_case(
                case,
                engine,
                datetime.fromisoformat(manifest["clock"]),
                embedding_prediction=score >= calibration["threshold"],
                verifier=verdict,
            )
        )
    assert rows == read("observations.json")
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "observations.json", rows)
    write_json(output / "calibration.json", calibration)
    counts = {
        arm: dict(Counter(row["classification"] for row in rows if row["arm"] == arm))
        for arm in sorted({row["arm"] for row in rows})
    }
    write_json(
        output / "verification.json",
        {
            "raw_responses_revalidated": True,
            "cache_labels_and_vectors_match": True,
            "dev_calibration_rebuilt": True,
            "all_observations_identical": True,
            "counts": counts,
            "networking_denied": True,
            "protocol_sha256": sha256(directory / "protocol_freeze.json"),
            "replay_source_sha256": sha256(Path(__file__)),
        },
    )
    print(
        json.dumps({"raw_responses_revalidated": True, "all_observations_identical": True, "counts": counts}, indent=2)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
