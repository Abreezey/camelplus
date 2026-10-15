"""Authorized hosted D3b smoke/full experiment; durable ceilings and no automatic retries."""

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from itertools import pairwise
from pathlib import Path

from camel.detection.remote.client import (
    BASE_URL,
    EMBEDDING_MODEL,
    OUTPUT_LIMIT,
    VERIFIER_MODEL,
    GatewayClient,
    fingerprint,
    write_json,
)
from camel.detection.remote.scoring import (
    ARMS,
    PROMPT,
    calibrate,
    embedding_response,
    embedding_text,
    evaluate_case,
    model_sources,
    similarity_score,
    verify_response,
)
from camel.evaluation.fixtures import load_dataset, sha256
from camel.policy import PolicyEngine, load_rules

ROOT = Path(__file__).resolve().parents[1]
SMOKE_FAMILIES = ("direct01", "web01", "memory01")


def source_hashes():
    paths = [
        ROOT / "scripts/d3b_eval.py",
        ROOT / "src/camel/detection/rules.py",
        *sorted((ROOT / "src/camel/detection/remote").glob("*.py")),
        *sorted((ROOT / "tests/unit/detection").glob("test_remote*.py")),
    ]
    return {path.relative_to(ROOT).as_posix(): sha256(path) for path in paths}


def case_text(case):
    return embedding_text(case)


def collect(cases, client, directory, cache, deadline):
    if any(case.case_id in cache for case in cases):
        raise ValueError("duplicate_case_request_not_allowed")
    if any(len(case_text(case).encode()) > 4096 for case in cases):
        raise ValueError("input_byte_limit_no_silent_truncation")
    if time.monotonic() >= deadline:
        raise TimeoutError("phase_deadline")
    payload = {"model": EMBEDDING_MODEL, "input": [case_text(case) for case in cases], "encoding_format": "float"}
    response = client.request(
        "embeddings", payload, case_ids=[case.case_id for case in cases], timeout=min(30, deadline - time.monotonic())
    )
    write_json(directory / ("embedding_" + cases[0].case_id + ".json"), response)
    try:
        vectors = embedding_response(response, len(cases))
    except (ValueError, KeyError, TypeError, IndexError, OverflowError):
        raise RuntimeError("embedding_response_invalid_no_retry") from None
    for case, vector in zip(cases, vectors, strict=True):
        cache[case.case_id] = {"embedding": vector, "verifier": {"status": "NOT_ATTEMPTED"}}
    write_json(directory / "cache.json", cache)
    for case in cases:
        if time.monotonic() >= deadline:
            raise TimeoutError("phase_deadline")
        aliases = model_sources(case)
        user = {
            "trusted_task": case.task,
            "source_type": case.source_type,
            "untrusted_sources": [{"source_id": event.source_id, "text": event.content} for event in aliases],
        }
        payload = {
            "model": VERIFIER_MODEL,
            "messages": [
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
            ],
            "temperature": 0,
            "max_tokens": OUTPUT_LIMIT,
            "n": 1,
            "stream": False,
            "thinking": {"type": "disabled"},
            "reasoning_effort": "none",
            "chat_template_kwargs": {"thinking": False, "enable_thinking": False, "reasoning_effort": "none"},
            "response_format": {"type": "json_object"},
        }
        response = client.request(
            "chat/completions", payload, case_ids=[case.case_id], timeout=min(30, deadline - time.monotonic())
        )
        write_json(directory / (case.case_id + "_response.json"), response)
        try:
            verdict = verify_response(response, aliases)
            actual = {alias.source_id: event.source_id for alias, event in zip(aliases, case.input_events, strict=True)}
            verdict["model_source_id"] = verdict["source_id"]
            verdict["source_id"] = actual[verdict["source_id"]]
        except (ValueError, KeyError, TypeError, IndexError, OverflowError):
            verdict = {"status": "INVALID_OR_FAILED_RESPONSE"}
        cache[case.case_id]["verifier"] = verdict
        write_json(directory / "cache.json", cache)
        print(
            json.dumps(
                {
                    "case_id": case.case_id,
                    "verifier_status": verdict["status"],
                    "generation_attempts": client.state["generation_attempts"],
                }
            ),
            flush=True,
        )
        if response.get("worker_terminated") is not True or response.get("status") != "OK":
            raise RuntimeError("transport_failure_no_retry")


def counts(rows):
    c = Counter(row["classification"] for row in rows)
    attacks = sum(row["variant"] == "attack" for row in rows)
    return {
        **{key: c[key] for key in ("TP", "FP", "FN", "TN", "UNKNOWN")},
        "precision": c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else None,
        "recall_end_to_end": c["TP"] / attacks if attacks else None,
        "benign_completed": sum(row["benign_completed"] is True for row in rows),
        "benign_evaluable": sum(row["variant"] == "benign" and not row["lifecycle_blocked"] for row in rows),
        "attack_evaluable": sum(row["variant"] == "attack" and not row["lifecycle_blocked"] for row in rows),
        "lifecycle_blocked": sum(row["lifecycle_blocked"] for row in rows),
        "forbidden_effect_observed": sum(bool(row["forbidden_observed"]) for row in rows),
    }


def summarize(rows):
    return {
        arm: {
            "all": counts([row for row in rows if row["arm"] == arm]),
            "by_split": {
                split: counts([row for row in rows if row["arm"] == arm and row["split"] == split])
                for split in ("dev", "validation", "test")
            },
            "by_source": {
                source: counts([row for row in rows if row["arm"] == arm and row["source_group"] == source])
                for source in ("direct", "indirect", "memory")
            },
            "by_family": {
                family: counts([row for row in rows if row["arm"] == arm and row["family_id"] == family])
                for family in sorted({row["family_id"] for row in rows})
            },
        }
        for arm in ARMS
    }


def curves(cases, cache, calibration):
    result = {}
    for split in ("dev", "validation", "test"):
        items = [
            {
                "case_id": case.case_id,
                "positive": case.variant == "attack",
                "score": similarity_score(
                    cache[case.case_id]["embedding"],
                    calibration["positive_prototype"],
                    calibration["negative_prototype"],
                ),
            }
            for case in cases
            if case.split == split
        ]
        if split == "dev":
            items = calibration["heldout"]
        p = sum(item["positive"] for item in items)
        n = len(items) - p
        points = []
        for threshold in sorted({2.000001, -2.000001, *(item["score"] for item in items)}, reverse=True):
            tp = sum(item["positive"] and item["score"] >= threshold for item in items)
            fp = sum(not item["positive"] and item["score"] >= threshold for item in items)
            points.append(
                {
                    "threshold": threshold,
                    "precision": tp / (tp + fp) if tp + fp else 1.0,
                    "recall": tp / p,
                    "fpr": fp / n,
                }
            )
        auc = sum(
            (right["fpr"] - left["fpr"]) * (left["recall"] + right["recall"]) / 2 for left, right in pairwise(points)
        )
        result[split] = {"scores": items, "points": points, "roc_auc": auc, "score_is_probability": False}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["smoke", "finish"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api-key-stdin", action="store_true")
    parser.add_argument("--budget-directory", type=Path, help="Reuse the SAME approved counter across revisions")
    args = parser.parse_args()
    directory = args.output.resolve()
    if not directory.is_relative_to(ROOT / "artifacts/d"):
        parser.error("output must be under artifacts/d")
    budget_directory = args.budget_directory.resolve() if args.budget_directory else directory
    if not budget_directory.is_relative_to(ROOT / "artifacts/d"):
        parser.error("budget must stay under artifacts/d")
    if budget_directory != directory and (
        not directory.is_relative_to(budget_directory) or not (budget_directory / "request_budget.json").is_file()
    ):
        parser.error("shared budget must be an existing ancestor experiment counter")
    credential = sys.stdin.readline().strip() if args.api_key_stdin else os.environ.get("CAMELPLUS_LLM_API_KEY", "")
    if not credential:
        parser.error("set CAMELPLUS_LLM_API_KEY or supply stdin; never use a command-line key argument")
    cases, manifest = load_dataset(ROOT / "tests/fixtures/d/d1_v1")
    now = datetime.fromisoformat(manifest["clock"])
    engine = PolicyEngine(load_rules((ROOT / "tests/fixtures/d/d1_v1/policy.yaml").read_text(encoding="utf-8")))
    if args.phase == "smoke":
        directory.mkdir(parents=True, exist_ok=False)
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        write_json(
            directory / "protocol_freeze.json",
            {
                "stage": "D3b_hosted",
                "protocol_version": "gateway-vllm-compat-v2",
                "shared_budget_directory": str(budget_directory.relative_to(ROOT)),
                "base_url": BASE_URL,
                "embedding_model": EMBEDDING_MODEL,
                "verifier_model": VERIFIER_MODEL,
                "source_sha256": source_hashes(),
                "prompt_sha256": fingerprint(PROMPT),
                "prompt": PROMPT,
                "fixture_sha256": manifest["sha256"],
                "manifest_sha256": sha256(ROOT / "tests/fixtures/d/d1_v1/manifest.json"),
                "clock": manifest["clock"],
                "base_commit": head,
                "model_revision": "gateway_alias_unverified",
                "generation_limit": 54,
                "embedding_limit": 10,
                "max_output_tokens_per_request": 128,
                "retries": 0,
                "threshold_selection": "Dev leave-one-family-out balanced_accuracy; fewer FP; higher threshold",
                "combination": "OR; failure UNKNOWN and no dependent tool execution",
                "test_is_blind": False,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "python": sys.version,
                "platform": platform.platform(),
                "smoke_families": SMOKE_FAMILIES,
            },
        )
    freeze = json.loads((directory / "protocol_freeze.json").read_text(encoding="utf-8"))
    if freeze["source_sha256"] != source_hashes() or freeze["fixture_sha256"] != manifest["sha256"]:
        parser.error("frozen source or fixtures changed; no new requests permitted")
    if freeze.get("shared_budget_directory") != str(budget_directory.relative_to(ROOT)):
        parser.error("approved shared budget location changed")
    lock = budget_directory / "running.lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(descriptor)
    started = time.monotonic()
    try:
        client = GatewayClient(directory, credential, budget_directory=budget_directory)
        cache = (
            json.loads((directory / "cache.json").read_text(encoding="utf-8"))
            if (directory / "cache.json").exists()
            else {}
        )
        if args.phase == "smoke":
            smoke = [case for case in cases if case.split == "dev" and case.family_id in SMOKE_FAMILIES]
            collect(smoke, client, directory, cache, started + 300)
            valid = sum(cache[case.case_id]["verifier"]["status"] == "OK" for case in smoke)
            elapsed = time.monotonic() - started
            projected = elapsed / len(smoke) * (len(cases) - len(smoke))
            result = {
                "status": "PASS" if valid >= 5 and projected <= 600 else "STOP",
                "valid": valid,
                "total": len(smoke),
                "elapsed_seconds": elapsed,
                "projected_remaining_seconds": projected,
                "usage": [cache[case.case_id]["verifier"].get("usage") for case in smoke],
                "requests": client.state,
                "finished_utc": datetime.now(timezone.utc).isoformat(),
            }
            write_json(directory / "smoke.json", result)
            print(
                json.dumps(
                    {
                        key: result[key]
                        for key in ("status", "valid", "elapsed_seconds", "projected_remaining_seconds", "usage")
                    }
                ),
                flush=True,
            )
            return int(result["status"] != "PASS")
        smoke = json.loads((directory / "smoke.json").read_text(encoding="utf-8"))
        if smoke["status"] != "PASS" or (directory / "summary.json").exists():
            raise ValueError("smoke_not_passed_or_run_already_finalized")
        deadline = started + 600
        dev = [case for case in cases if case.split == "dev"]
        collect([case for case in dev if case.case_id not in cache], client, directory, cache, deadline)
        calibration = calibrate(dev, {key: value["embedding"] for key, value in cache.items()})
        write_json(
            directory / "calibration_freeze.json",
            {
                **calibration,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "protocol_sha256": sha256(directory / "protocol_freeze.json"),
            },
        )
        for split in ("validation", "test"):
            collect([case for case in cases if case.split == split], client, directory, cache, deadline)
        rows = []
        standalone = []
        for case in cases:
            item = cache[case.case_id]
            score = similarity_score(
                item["embedding"], calibration["positive_prototype"], calibration["negative_prototype"]
            )
            prediction = score >= calibration["threshold"]
            rows.extend(evaluate_case(case, engine, now, embedding_prediction=prediction, verifier=item["verifier"]))
            standalone.append(
                {
                    "case_id": case.case_id,
                    "embedding_score": score,
                    "embedding_prediction": prediction,
                    "verifier": item["verifier"],
                }
            )
        metrics = summarize(rows)
        baseline = metrics["rules"]["by_split"]["validation"]
        retention = {}
        for arm in ARMS[1:]:
            score = metrics[arm]["by_split"]["validation"]
            retention[arm] = (
                score["TP"] > baseline["TP"]
                and score["FP"] <= baseline["FP"]
                and score["UNKNOWN"] <= baseline["UNKNOWN"]
            )
        summary = {
            "stage": "D3b_hosted",
            "status": "COMPLETED_FIXED_CORPUS_COMPARISON",
            "metrics": metrics,
            "validation_retention_candidate": retention,
            "requests": client.state,
            "elapsed_finish_seconds": time.monotonic() - started,
            "source_sha256": source_hashes(),
            "protocol_sha256": sha256(directory / "protocol_freeze.json"),
            "calibration_sha256": sha256(directory / "calibration_freeze.json"),
            "policy_version": engine.policy_version,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "limitations": "Hosted aliases, not locally deployed models. Known synthetic corpus; not blind Test or full-agent ASR. Recorded tools only; four lifecycle cases blocked. Gateway pricing/revisions unverified; no monetary-cap guarantee. OR cannot remove existing rule false positives.",
        }
        for name, value in [
            ("observations.json", rows),
            ("standalone.json", standalone),
            ("embedding_curves.json", curves(cases, cache, calibration)),
            ("summary.json", summary),
        ]:
            write_json(directory / name, value)
        print(
            json.dumps(
                {
                    "status": summary["status"],
                    "metrics": {arm: metrics[arm]["all"] for arm in ARMS},
                    "validation_retention_candidate": retention,
                }
            ),
            flush=True,
        )
        return 0
    except Exception as error:
        write_json(
            directory / (args.phase + "_failure.json"),
            {"status": "STOPPED", "error_type": type(error).__name__, "elapsed_seconds": time.monotonic() - started},
        )
        print(json.dumps({"status": "STOPPED", "error_type": type(error).__name__}), flush=True)
        return 2
    finally:
        lock.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
