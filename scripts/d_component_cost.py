"""D component microbenchmark only; no models, tools, Gateway or C recovery changes."""

import argparse
import importlib.metadata
import json
import os
import platform
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from camel.core import Authority, Confidentiality, TrustLabel
from camel.detection.models import identity_view
from camel.detection.rules import VERSION, detect
from camel.evaluation.component_cost import Workload, measure
from camel.evaluation.fixtures import load_dataset, sha256
from camel.memory.models import Context, MemoryPolicy, Reader, Source, Write, WriteBinding
from camel.memory.store import MemoryGate, digest
from camel.planner.compiler import compile_task
from camel.planner.fixture_adapter import TOOLS, normalize_fixture
from camel.planner.models import CandidatePlan, DataField, Organization, Resource, ToolNode, TrustedTask
from camel.planner.models import Source as PlannerSource
from camel.planner.validation import validate_plan
from camel.policy import PolicyEngine, load_rules

ROOT = Path(__file__).resolve().parents[1]
KEY = b"D-COST-PUBLIC-SYNTHETIC-KEY-32-BYTES"
OWNER = "host:d-component-cost"


def planner_workloads(now):
    organization = Organization(
        policy_id="d-cost-v1",
        forbidden_data_classes=frozenset({"credentials"}),
        resources=(
            Resource(resource_id="file:///workspace/README.md", kind="document"),
            Resource(resource_id="file:///workspace/src/module.py", kind="code"),
        ),
    )
    tasks = tuple(
        TrustedTask(
            task_id="cost-" + tool.template,
            principal=OWNER,
            template=tool.template,
            resource_ids=(organization.resources[index].resource_id,),
            expires_at=now + timedelta(minutes=30),
        )
        for index, tool in enumerate(TOOLS)
    )
    compiled = []
    for task in tasks:
        item = compile_task(task, organization, now=now).compiled
        if item is None:
            raise ValueError("planner_setup_failed")
        compiled.append(item)
    source = PlannerSource(
        source_id="cost-source",
        label=TrustLabel(provenance=frozenset({"cost-source"})),
        fields=(DataField(name="content", value="Facts about project documentation."),),
    )
    sources = (source,)
    plans = tuple(
        CandidatePlan(
            task_id=task.task_id,
            nodes=(
                ToolNode(
                    node_id="read",
                    tool_id=TOOLS[index].tool_id,
                    tool_version=TOOLS[index].version,
                    resource_id=task.resource_ids[0],
                    effect_refs=("read-effect",),
                    source_ids=(source.source_id,),
                    depends_on=(),
                    data_slots=(),
                ),
            ),
        )
        for index, task in enumerate(tasks)
    )
    normalized = tuple(normalize_fixture(item, plan, sources) for item, plan in zip(compiled, plans, strict=True))
    engine = PolicyEngine(load_rules("id: cost-read\nwhen:\n  effect.type: READ\nthen: ALLOW"))
    ids = tuple(task.template for task in tasks)
    return [
        Workload(
            "contract_compile",
            ids,
            lambda index: compile_task(tasks[index], organization, now=now),
            lambda result, index: result.status == "READY" and result.compiled == compiled[index],
            "D2 compile only; two existing one-resource read-only templates; no model",
            False,
        ),
        Workload(
            "tdg_validate",
            ids,
            lambda index: validate_plan(
                compiled[index],
                plans[index],
                sources=sources,
                tools=TOOLS,
                normalized=normalized[index],
                engine=engine,
                now=now,
            ),
            lambda result, index: result.status == "READY" and len(result.effects) == 1,
            "D2 validation includes contract recheck and A evaluation; B fixture effects prepared before timing; one node/source/effect",
            False,
        ),
    ]


def detection_workload(cases):
    views = []
    for case in cases:
        labels = {}
        case_views = []
        for event in case.input_events:
            label = event.label
            for parent in event.parent_ids:
                label = label.join(labels[parent])
            labels[event.event_id] = label
            case_views.append(identity_view(event.source_id, case.source_type, event.content, label))
        views.append(tuple(case_views))
    return Workload(
        "fixed_rules",
        tuple(case.case_id for case in cases),
        lambda index: detect(views[index]),
        lambda result, index: result.status == "OK",
        "D3a frozen rules over known 48-case source views; view construction excluded; no tuning or model inference",
        False,
    )


def memory_workload(storage: Path, now):
    policy = MemoryPolicy(
        version="d-cost-v1",
        writers=frozenset({OWNER}),
        operators=frozenset({OWNER}),
        readers=(Reader(principal=OWNER, clearance=Confidentiality.PUBLIC),),
    )
    gate = MemoryGate(storage / "memory.sqlite", key=KEY, policy=policy, store_id="d-component-cost")
    context = Context(principal=OWNER, session_id="cost-session", trace_id="cost-trace")
    gate.register_source(
        Source(source_id="s", event_id="cost-ingress", label=TrustLabel(provenance=frozenset({"s"}))),
        context=context,
        now=now,
    )
    for index in range(3):
        entry_id = "entry-" + str(index)
        parents = ("entry-" + str(index - 1),) if index else ()
        text = f"Ordinary module facts {index}."
        result = gate.put(
            Write(
                entry_id=entry_id,
                content=text,
                source_ids=("s",),
                parent_ids=parents,
                expires_at=now + timedelta(minutes=30),
            ),
            binding=WriteBinding(OWNER, entry_id, ("s",), parents, digest(text)),
            context=context,
            now=now,
        )
        if result.status != "STORED":
            gate.close()
            raise ValueError("memory_setup_failed")
    ids = ("entry-0", "entry-2")
    workload = Workload(
        "memory_get",
        ids,
        lambda index: gate.get(ids[index], context=context, now=now),
        lambda result, index: result.status == "RETURNED"
        and result.entry is not None
        and result.entry.labels.authority == Authority.DATA_ONLY
        and result.content == ("Ordinary module facts 0." if index == 0 else "Ordinary module facts 2."),
        "D4 actual SQLite/HMAC/TTL/ACL/lineage validation and read-event commit; root vs two-parent chain; seed setup excluded",
        True,
    )
    return gate, workload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--storage-root", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    storage = args.storage_root.resolve() if args.storage_root is not None else output / "memory"
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("choose a new output directory under artifacts/d")
    if storage.exists() or not (
        storage.is_relative_to(output) or (sys.platform == "linux" and storage.is_relative_to(Path.home()))
    ):
        parser.error("choose fresh storage inside output or Linux home")

    def offline_guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request"}:
            raise RuntimeError("D component cost experiment prohibits networking")

    sys.addaudithook(offline_guard)
    output.mkdir(parents=True)
    storage.mkdir(parents=True)
    cases, manifest = load_dataset(ROOT / "tests/fixtures/d/d1_v1")
    now = datetime.fromisoformat(manifest["clock"])
    started = time.perf_counter()
    gate, memory = memory_workload(storage, now)
    try:
        workloads = [*planner_workloads(now), detection_workload(cases), memory]
        setup_seconds = time.perf_counter() - started
        results = []
        for workload in workloads:
            measured = measure(workload)
            samples = measured.pop("raw_samples")
            (output / (workload.name + "_samples.json")).write_text(
                json.dumps(samples, indent=2) + "\n", encoding="utf-8"
            )
            results.append(measured)
            print(f"{workload.name}: P50={measured['p50_ms']:.3f} ms; P95={measured['p95_ms']:.3f} ms", flush=True)
        memory_events = len(gate.events())
    finally:
        gate.close()
    summary = dict(
        experiment="D component offline cost",
        status="PASS",
        model_requests=0,
        setup_seconds=setup_seconds,
        protocol=dict(
            warmup=100,
            iterations=1000,
            clock="perf_counter_ns",
            percentile="nearest_rank",
            outliers_removed=0,
            result_validation_and_hashing_timed=False,
            order=[workload.name for workload in workloads],
        ),
        results=results,
        python=sys.version,
        platform=platform.platform(),
        processor=platform.processor(),
        logical_cpus=os.cpu_count(),
        hardware=(
            dict(
                cpu_model=next(
                    (
                        line.split(":", 1)[1].strip()
                        for line in Path("/proc/cpuinfo").read_text().splitlines()
                        if line.startswith("model name")
                    ),
                    "unknown",
                ),
                memory_total_kb=next(
                    (
                        int(line.split()[1])
                        for line in Path("/proc/meminfo").read_text().splitlines()
                        if line.startswith("MemTotal:")
                    ),
                    None,
                ),
            )
            if sys.platform == "linux"
            else dict(cpu_model=platform.processor(), memory_total_kb=None)
        ),
        dependencies={name: importlib.metadata.version(name) for name in ("pydantic", "PyYAML")},
        memory_storage=str(storage),
        memory_events=memory_events,
        fixed_rule_version=VERSION,
        fixture_sha256={
            name: sha256(ROOT / "tests/fixtures/d/d1_v1" / name)
            for name in ("cases.jsonl", "manifest.json", "policy.yaml")
        },
        source_sha256={
            path.relative_to(ROOT).as_posix(): sha256(path)
            for folder in ("src/camel/planner", "src/camel/detection", "src/camel/memory", "src/camel/evaluation")
            for path in sorted((ROOT / folder).glob("*.py"))
        }
        | {"scripts/d_component_cost.py": sha256(Path(__file__))},
        limitations="Microbenchmark only; repeated observations are correlated, not independent attack trials. No Gateway/OS sandbox/model latency or full D6/D7 acceptance; no correctness or security improvement inferred from speed.",
    )
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
