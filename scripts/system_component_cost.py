"""Measure A policy, B gateway and C broker latency against arch.md gates."""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from camel.audit import AuditStore
from camel.broker import ConfirmationAuthority, ExecutionBroker, SandboxProfile, SecureExecutionPipeline
from camel.core.effect import CanonicalEffect, EffectType
from camel.evaluation.component_cost import Workload, measure
from camel.gateway import CallContext, MCPSecurityGateway, ServerManifest, ToolManifest
from camel.normalization import EffectNormalizer, EffectSpec, NetworkPolicy, NormalizationContext, ToolBinding
from camel.policy import PolicyEngine, load_rules
from camel.policy.ticket import InMemoryTicketStore

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)
KEY = b"SYSTEM-COST-PUBLIC-SYNTHETIC-KEY"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class StubTransport:
    def __init__(self) -> None:
        self.manifest = ServerManifest(
            identity="system-cost:stub:v1",
            tools=(ToolManifest(name="lookup", input_schema={"type": "object", "additionalProperties": False}),),
        )

    async def snapshot(self) -> ServerManifest:
        return self.manifest

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"value": "fixed-result"}


def _effect(effect_type: EffectType, operation: str, **changes: Any) -> CanonicalEffect:
    return CanonicalEffect(effect_id="system-cost-" + operation, type=effect_type, operation=operation, **changes)


def policy_workload() -> Workload:
    engine = PolicyEngine(
        load_rules(
            "id: allow-read\nwhen:\n  effect.type: READ\nthen: ALLOW\n---\n"
            "id: allow-egress\nwhen:\n  effect.type: EGRESS\nthen: ALLOW\n"
        )
    )
    effects = (_effect(EffectType.READ, "lookup"), _effect(EffectType.EXEC, "shell"))
    return Workload(
        "policy_decision",
        ("allow-read", "default-deny-exec"),
        lambda index: engine.evaluate(effects[index], now=NOW).decision.value,
        lambda result, index: result == ("ALLOW" if index == 0 else "DENY"),
        "A PolicyEngine pure decision; one explicit allow and one default deny; model calls excluded",
        False,
    )


def broker_workloads(root: Path) -> tuple[list[Workload], AuditStore]:
    workspace = root / "workspace"
    scratch = root / "scratch"
    workspace.mkdir(parents=True)
    scratch.mkdir()
    note = workspace / "note.txt"
    note.write_text("fixed broker payload", encoding="utf-8")
    audit = AuditStore(":memory:")
    resolver = lambda host, port: ("93.184.216.34",)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"fixed egress payload"))
    engine = PolicyEngine(
        load_rules(
            "id: allow-read\nwhen:\n  effect.type: READ\nthen: ALLOW\n---\n"
            "id: allow-egress\nwhen:\n  effect.type: EGRESS\nthen: ALLOW\n"
        )
    )
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(workspace, scratch),
        ticket_store=InMemoryTicketStore(),
        audit=audit,
        now_fn=lambda: NOW,
        network=NetworkPolicy(allowed_hosts=frozenset({"example.com"}), allowed_ports=frozenset({443})),
        resolver=resolver,
        transport=transport,
    )
    pipeline = SecureExecutionPipeline(
        engine=engine,
        broker=broker,
        confirmations=ConfirmationAuthority(signing_key=KEY, audit=audit, now_fn=lambda: NOW),
        audit=audit,
        signing_key=KEY,
        now_fn=lambda: NOW,
    )
    effects = (
        _effect(EffectType.READ, "file_read", resources=(str(note),)),
        _effect(EffectType.EXEC, "shell"),
        _effect(EffectType.EGRESS, "http_get", destination="https://example.com/data"),
    )

    def invoke(index: int) -> tuple[str, str | None]:
        result = pipeline.run(
            effects[index],
            subject="system-cost",
            trace_id="system-cost",
            session_id="system-cost",
        )
        output = result.execution.output.decode() if result.execution is not None and result.execution.output else None
        return result.decision.decision.value, output

    expected = (("ALLOW", "fixed broker payload"), ("DENY", None), ("ALLOW", "fixed egress payload"))
    return (
        [
            Workload(
                "broker_pipeline",
                ("allow-read", "default-deny-exec", "allow-egress"),
                invoke,
                lambda result, index: result == expected[index],
                "A+C SecureExecutionPipeline including SQLite audit, tickets and READ/EGRESS IO; no external network",
                True,
            )
        ],
        audit,
    )


def gateway_workloads(root: Path) -> tuple[list[Workload], AuditStore, asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    transport = StubTransport()
    audit = AuditStore(":memory:")
    context = CallContext(
        subject="system-cost",
        trace_id="system-cost",
        session_id="system-cost",
        normalization=NormalizationContext(workspace=root, cwd=root),
        model_version="none",
        code_commit="system-cost",
    )
    gateway = MCPSecurityGateway(
        engine=PolicyEngine(load_rules("id: allow-read\nwhen:\n  effect.type: READ\nthen: ALLOW")),
        normalizer=EffectNormalizer(),
        audit=audit,
        signing_key=KEY,
        ticket_store=InMemoryTicketStore(),
        now_fn=lambda: NOW,
    )
    loop.run_until_complete(
        gateway.register(
            "stub",
            transport,
            expected_identity=transport.manifest.identity,
            expected_digest=transport.manifest.digest,
            bindings={
                "lookup": ToolBinding(
                    adapter="mcp",
                    effects=(EffectSpec(type=EffectType.READ, operation="lookup"),),
                )
            },
            context=context,
        )
    )

    def raw(_: int) -> dict[str, Any]:
        return loop.run_until_complete(transport.call_tool("lookup", {}))

    def secured(_: int) -> dict[str, Any] | None:
        result = loop.run_until_complete(gateway.call_tool("stub", "lookup", {}, context=context))
        return result.output.payload if result.output is not None else None

    check = lambda result, index: result == {"value": "fixed-result"}
    return (
        [
            Workload("gateway_raw_stub", ("lookup",), raw, check, "raw in-process upstream RPC baseline", False),
            Workload(
                "gateway_secured_stub",
                ("lookup",),
                secured,
                check,
                "B gateway normalize + A decision + C audit/ticket + result envelope over same stub RPC",
                True,
            ),
        ],
        audit,
        loop,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("choose a fresh output directory under artifacts/d")

    def offline_guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request"}:
            raise RuntimeError("system cost experiment prohibits external networking")

    sys.addaudithook(offline_guard)
    output.mkdir(parents=True)
    broker, broker_audit = broker_workloads(output / "broker")
    gateway, gateway_audit, loop = gateway_workloads(output / "gateway")
    workloads = [policy_workload(), *broker, *gateway]
    started = time.perf_counter()
    results = []
    try:
        for workload in workloads:
            measured = measure(workload)
            samples = measured.pop("raw_samples")
            (output / f"{workload.name}_samples.json").write_text(
                json.dumps(samples, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            results.append(measured)
            print(f"{workload.name}: P50={measured['p50_ms']:.3f} ms; P95={measured['p95_ms']:.3f} ms")
        broker_audit.verify_chain()
        gateway_audit.verify_chain()
    finally:
        broker_audit.close()
        gateway_audit.close()
        loop.close()
    by_name = {row["name"]: row for row in results}
    gateway_increment = max(0.0, by_name["gateway_secured_stub"]["p95_ms"] - by_name["gateway_raw_stub"]["p95_ms"])
    gates = {
        "policy_decision_p95_lt_20ms": by_name["policy_decision"]["p95_ms"] < 20,
        "gateway_increment_p95_lt_150ms": gateway_increment < 150,
    }
    summary = {
        "experiment": "ABC system component cost",
        "status": "PASS" if all(gates.values()) else "FAIL",
        "model_requests": 0,
        "duration_seconds": time.perf_counter() - started,
        "protocol": {
            "warmup": 100,
            "iterations": 1000,
            "clock": "perf_counter_ns",
            "percentile": "nearest_rank",
            "outliers_removed": 0,
        },
        "results": results,
        "gateway_p95_increment_ms": gateway_increment,
        "gates": gates,
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "dependencies": {name: importlib.metadata.version(name) for name in ("httpx", "pydantic")},
        "source_sha256": {
            path: sha256(ROOT / path)
            for path in (
                "scripts/system_component_cost.py",
                "src/camel/evaluation/component_cost.py",
                "src/camel/policy/engine.py",
                "src/camel/gateway/gateway.py",
                "src/camel/broker/pipeline.py",
                "src/camel/broker/executor.py",
            )
        },
        "limitations": "In-process microbenchmark with a deterministic stub upstream; excludes model and external network latency. Repeated observations are correlated, not independent security trials.",
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
