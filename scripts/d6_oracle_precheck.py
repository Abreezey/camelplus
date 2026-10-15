"""Run only pinned in-memory AgentDojo reference/oracle controls; no Agent models."""

import argparse
import json
import sys
import time
from importlib.metadata import distribution
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("use fresh output under artifacts/d")

    def guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request", "subprocess.Popen"}:
            raise RuntimeError("model-free precheck prohibits network and subprocesses")

    sys.addaudithook(guard)
    from camel.adapters.agentdojo.catalog import sha256

    protocol_path = ROOT / "docs/d/evidence/D6_oracle_precheck_protocol.json"
    protocol = read(protocol_path)
    pin = read(ROOT / "docs/d/evidence/D6_preparation_acceptance.json")
    installed = distribution("agentdojo")
    package_root = Path(str(installed.locate_file("agentdojo")))
    if installed.version != protocol["agentdojo_package"]:
        raise ValueError("agentdojo_version_changed")
    hashes = pin["installed_package_file_sha256"]
    if any(sha256(package_root / name) != digest for name, digest in hashes.items()):
        raise ValueError("installed_code_or_fixture_changed_from_preparation")
    from camel.adapters.agentdojo.precheck import run_checks

    source_paths = [
        Path(__file__),
        ROOT / "tests/unit/evaluation/test_agentdojo_precheck.py",
        protocol_path,
        ROOT / "docs/d/evidence/D6_preparation_acceptance.json",
        *sorted((ROOT / "src/camel/adapters").rglob("*.py")),
    ]
    source_hashes = {p.relative_to(ROOT).as_posix(): sha256(p) for p in source_paths}
    output.mkdir(parents=True)
    raw_dir = output / "raw"
    raw_dir.mkdir()
    write(output / "freeze.json", dict(protocol=protocol, source_sha256=source_hashes, package_sha256=hashes))
    started = time.monotonic()
    result = run_checks(protocol, lambda name, value: write(raw_dir / (name + ".json"), value))
    counts = result["counts"]
    limits = protocol["budget"]
    if (
        counts["environment_loads"] > limits["max_environment_loads"]
        or counts["ground_truth_pipeline_queries"] > limits["max_ground_truth_pipeline_queries"]
        or counts["ground_truth_method_calls"] > limits["max_ground_truth_method_calls"]
        or counts["tool_calls"] > limits["max_tool_calls"]
        or time.monotonic() - started > limits["max_seconds"]
    ):
        raise RuntimeError("model_free_budget_exceeded")
    if any(sha256(ROOT / name) != digest for name, digest in source_hashes.items()) or any(
        sha256(package_root / name) != digest for name, digest in hashes.items()
    ):
        raise RuntimeError("frozen_inputs_changed")
    write(output / "observations.json", result)
    write(
        output / "summary.json",
        dict(
            status=result["status"],
            counts=counts,
            full_D6_accepted=False,
            ASR=None,
            evidence_sha256={p.relative_to(output).as_posix(): sha256(p) for p in sorted(output.rglob("*.json"))},
        ),
    )
    print(f"{result['status']}; ground-truth simulator only; {output}")
    return int(result["status"] != "PASS_MODEL_FREE_PRECHECK")


if __name__ == "__main__":
    raise SystemExit(main())
