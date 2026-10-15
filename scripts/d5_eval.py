"""Run local D5 prerequisite/subchain acceptance; FAIL is not full-system PASS."""

import argparse
import hashlib
import importlib.metadata
import platform
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from camel.evaluation.integration import SCENARIOS, run_probe, write_json

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    output = options.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("choose a new output directory under artifacts/d")
    output.mkdir(parents=True)
    started = datetime.now(timezone.utc).isoformat()
    network_attempts = []

    def deny_network(event, args):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto"}:
            network_attempts.append(event)
            raise OSError("D5 Python socket network access disabled")

    # Process-local guard only; this does not provide C's OS containment.
    sys.addaudithook(deny_network)
    observations = []
    for name in SCENARIOS:
        try:
            observation, trace = run_probe(name, output / name)
            write_json(output / name / "trace.json", trace)
        except Exception as error:
            observation = dict(scenario=name, status="ERROR", error_type=type(error).__name__)
        observations.append(observation)
        print(f"{name}: {observation['status']}", flush=True)
    missing = [name for name in ("normalization", "gateway") if not (ROOT / "src/camel" / name).is_dir()]
    status = Counter(item["status"] for item in observations)
    hashes = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for folder in ("src/camel", "scripts", "tests/integration", "tests/unit/broker", "tests/unit/audit")
        for path in sorted((ROOT / folder).rglob("*.py"))
    }
    report = dict(
        stage="D5",
        status="PARTIAL_FAIL" if status["FAIL"] or status["ERROR"] else "PARTIAL_BLOCKED",
        full_chain_accepted=False,
        python=sys.version,
        platform=platform.platform(),
        missing_components=missing,
        counts=dict(status),
        observations=observations,
        source_sha256=hashes,
        model_requests=0,
        network_attempts=network_attempts,
        started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(),
        dependencies={name: importlib.metadata.version(name) for name in ("pydantic", "PyYAML")},
        frozen_fixture_sha256={
            name: hashlib.sha256((ROOT / "tests/fixtures/d/d1_v1" / name).read_bytes()).hexdigest()
            for name in ("cases.jsonl", "manifest.json", "policy.yaml")
        },
        lock_sha256=hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest(),
        limits=[
            "B canonical effects are fixtures/host inputs, not production normalization",
            "host identity is synthetic; no authentication or OS containment proven",
            "no live egress, MCP drift/reconnect, shell reduction, adaptive attacks or D6 benchmark",
            "memory refresh and D detection wiring are test-host adapters, not C production wiring",
            "READ-only successful execution; POSIX WRITE acceptance still requires Linux",
            "terminal audit failure may follow IO; unresolved durable intent is not proof of rollback",
        ],
    )
    write_json(output / "report.json", report)
    print(f"D5 {report['status']}: {dict(status)}; full_chain_accepted=false", flush=True)
    return 1 if status["FAIL"] or status["ERROR"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
