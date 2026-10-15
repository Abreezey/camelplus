"""D4 real SQLite lifecycle replay, recording-only effects, actual C audit/DAG, no models."""

import argparse
import importlib.metadata
import json
import platform
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from camel.audit.provenance import ProvenanceService
from camel.audit.store import AuditStore
from camel.core import Confidentiality, Decision, DecisionOutcome, EffectType, TrustLabel
from camel.evaluation.fixtures import canonical_effect, load_dataset, sha256
from camel.evaluation.replay import RecordingTool, observes, replay, stable
from camel.memory.models import Context, MemoryPolicy, Reader, Source, Write, WriteBinding
from camel.memory.store import MemoryGate, digest
from camel.policy import PolicyEngine, load_rules

ROOT = Path(__file__).resolve().parents[1]
# Deliberately public synthetic fixture key. Production must inject a separate protected key.
TEST_KEY = b"D4-ONLY-SYNTHETIC-TEST-KEY-32-BYTES"
OWNER = "user:synthetic"
OPERATOR = "host:memory-operator"


def policy():
    return MemoryPolicy(
        version="d4-offline-memory-v1",
        writers=frozenset({OWNER}),
        operators=frozenset({OPERATOR}),
        readers=(
            Reader(principal=OWNER, clearance=Confidentiality.SECRET),
            Reader(principal="agent:reviewer", clearance=Confidentiality.PUBLIC),
        ),
    )


def actor(case, session, principal=OWNER):
    return Context(principal=principal, session_id=session, trace_id=case.case_id)


def memory_case(case, engine, now, directory):
    path = directory / (case.case_id + ".sqlite")
    gate = MemoryGate(path, key=TEST_KEY, policy=policy(), store_id=case.case_id)
    write_case = any(call.type == EffectType.MEMORY_WRITE for call in case.candidate_calls)
    seeded = {}
    for event in case.input_events:
        clock = now - timedelta(hours=2) if event.memory_state == "expired" else now - timedelta(minutes=1)
        label = TrustLabel.model_validate(event.label.model_dump())
        gate.register_source(
            Source(source_id=event.source_id, event_id=event.event_id, label=label), context=actor(case, "A"), now=clock
        )
        if write_case:
            continue
        request = Write(
            entry_id=event.event_id,
            content=event.content,
            source_ids=(event.source_id,),
            parent_ids=event.parent_ids,
            expires_at=clock + timedelta(minutes=30),
        )
        binding = WriteBinding(OWNER, event.event_id, (event.source_id,), event.parent_ids, digest(event.content))
        stored = gate.put(request, binding=binding, context=actor(case, "A"), now=clock)
        if stored.entry is None:
            raise RuntimeError("fixture_memory_setup_failed")
        if event.memory_state == "quarantined" and stored.entry.state != "quarantined":
            stored = gate.quarantine(event.event_id, context=actor(case, "A", OPERATOR), now=clock)
        seeded[event.event_id] = stable(stored)
    gate.close()
    gate = MemoryGate(path, key=TEST_KEY, policy=policy(), store_id=case.case_id)
    labels = {}
    for event in case.input_events:
        if write_case:
            labels[event.event_id] = TrustLabel.model_validate(event.label.model_dump())
        else:
            description = gate.describe(event.event_id, context=actor(case, "B", OPERATOR), now=now)
            if description.entry is None:
                raise RuntimeError("verified_fixture_metadata_unavailable")
            labels[event.event_id] = description.entry.labels
    label_errors = [
        event_id for event_id, value in labels.items() if stable(value) != stable(case.expected_labels[event_id])
    ]
    tool = RecordingTool()
    by_id = {event.event_id: event for event in case.input_events}
    decisions = {}
    reads = {}
    used = 0
    for call in case.candidate_calls:
        effect = canonical_effect(call, labels)
        kernel = engine.evaluate(effect, now=now, contract=case.authorized_scope, side_effects_used=used)
        final = kernel
        content = {}
        failures = []
        if call.type != EffectType.MEMORY_WRITE:
            for event_id in call.data_event_ids:
                got = gate.get(event_id, context=actor(case, "B"), now=now)
                reads[event_id] = stable(got)
                if got.status != "RETURNED":
                    failures.extend(got.reasons)
                else:
                    content[event_id] = got.content
        if failures:
            final = Decision(
                decision=DecisionOutcome.DENY,
                hard_reasons=tuple("memory_gate:" + code for code in failures),
                policy_version=engine.policy_version,
                contract_id=case.authorized_scope.contract_id,
                evidence=("memory_policy:" + policy().version,),
            )
        if final.decision == DecisionOutcome.ALLOW:
            if call.type == EffectType.MEMORY_WRITE:
                event = by_id[call.data_event_ids[0]]
                stored = gate.put(
                    Write(
                        entry_id=event.event_id,
                        content=event.content,
                        source_ids=(event.source_id,),
                        parent_ids=event.parent_ids,
                        expires_at=now + timedelta(minutes=30),
                    ),
                    binding=WriteBinding(
                        OWNER, event.event_id, (event.source_id,), event.parent_ids, digest(event.content)
                    ),
                    context=actor(case, "B"),
                    now=now,
                )
                seeded[event.event_id] = stable(stored)
                if stored.status != "STORED" or stored.entry is None:
                    raise RuntimeError("benign_memory_write_did_not_store")
                labels[event.event_id] = stored.entry.labels
                content[event.event_id] = event.content
            tool.invoke(
                effect, "\n".join(content[event_id] for event_id in call.data_event_ids), call.recorded_response
            )
            used += int(effect.is_side_effecting)
        decisions[call.call_id] = {
            "kernel": stable(kernel),
            "with_memory_gate": stable(final),
            "kernel_deny_retained": kernel.decision != DecisionOutcome.DENY or final.decision == DecisionOutcome.DENY,
        }
    gate.close()
    gate = MemoryGate(path, key=TEST_KEY, policy=policy(), store_id=case.case_id)
    persisted = None
    if write_case:
        event = case.input_events[-1]
        persisted = gate.get(event.event_id, context=actor(case, "C"), now=now + timedelta(seconds=1))
        if (
            persisted.status != "RETURNED"
            or persisted.entry is None
            or persisted.content != event.content
            or stable(persisted.entry.labels) != stable(case.expected_labels[event.event_id])
        ):
            raise RuntimeError("written_memory_failed_reopen_verification")
    audit = AuditStore(directory / (case.case_id + "-audit.sqlite"))
    exported = gate.export_events(audit)
    if gate.export_events(audit) != 0:
        raise RuntimeError("outbox_export_not_idempotent")
    audit.verify_chain()
    dag = ProvenanceService(audit).dag(case.case_id)
    ids = {event.event_id for event, _ in gate.events()}
    expected_edges = sorted(
        {(parent, event.event_id) for event, _ in gate.events() for parent in event.parent_ids if parent in ids}
    )
    if list(dag.edges) != expected_edges:
        raise RuntimeError("audit_dag_edges_differ")
    events = [{"event": stable(event), "payload": payload} for event, payload in gate.events()]
    if "CANARY::" in json.dumps(events):
        raise RuntimeError("raw_content_in_memory_audit")
    gate.close()
    audit.close()
    forbidden = [i for i, oracle in enumerate(case.forbidden_observables) if observes(tool.ledger, oracle)]
    completed = None
    if case.benign_success_oracle is not None:
        oracle = case.benign_success_oracle
        actual = {entry["effect_id"]: entry["response"] for entry in tool.ledger}
        completed = all(actual.get(key) == oracle.expected_responses[key] for key in oracle.required_effect_ids)
    effect_errors = [entry["effect_id"] for entry in tool.ledger] != list(case.expected_effects)
    decision_errors = []
    stricter = []
    for call_id, expected in case.expected_decision.items():
        row = decisions[call_id]
        if case.required_components:
            if row["with_memory_gate"]["decision"] != expected:
                decision_errors.append(call_id)
        elif row["kernel"]["decision"] != expected:
            decision_errors.append(call_id)
        if row["kernel"]["decision"] != row["with_memory_gate"]["decision"]:
            stricter.append(call_id)
    passed = not (label_errors or effect_errors or forbidden or completed is False or decision_errors) and all(
        row["kernel_deny_retained"] for row in decisions.values()
    )
    return {
        "case_id": case.case_id,
        "family_id": case.family_id,
        "split": case.split,
        "variant": case.variant,
        "source_type": case.source_type,
        "status": "PASS" if passed else "FAIL",
        "memory_exercised": True,
        "lifecycle_was_blocked_in_D1": bool(case.required_components),
        "seeded": seeded,
        "reads": reads,
        "labels": {key: stable(value) for key, value in labels.items()},
        "label_errors": label_errors,
        "decisions": decisions,
        "decision_errors": decision_errors,
        "stricter_due_to_memory_gate": stricter,
        "ledger": tool.ledger,
        "effect_errors": effect_errors,
        "forbidden_observed": forbidden,
        "benign_completed": completed,
        "post_write_reopen_verified": persisted.status == "RETURNED" if persisted else None,
        "audit": {
            "exported": exported,
            "events": events,
            "dag_edges": expected_edges,
            "no_raw_content": True,
            "chain_verified": True,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=["dev", "validation", "test", "all"], default="dev")
    parser.add_argument("--harness-validation", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.split in {"test", "all"} and not args.harness_validation:
        parser.error("Test access requires --harness-validation; known fixture engineering replay only")
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d"):
        parser.error("output must be a new directory under artifacts/d")

    def offline_guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "urllib.Request"}:
            raise RuntimeError("D4 evaluation prohibits networking")

    sys.addaudithook(offline_guard)
    cases, manifest = load_dataset(ROOT / "tests/fixtures/d/d1_v1")
    cases = [case for case in cases if args.split == "all" or case.split == args.split]
    now = datetime.fromisoformat(manifest["clock"])
    engine = PolicyEngine(load_rules((ROOT / "tests/fixtures/d/d1_v1/policy.yaml").read_text(encoding="utf-8")))
    output.mkdir(parents=True, exist_ok=False)
    stores = output / "stores"
    stores.mkdir()
    started = datetime.now(timezone.utc)
    rows = [
        memory_case(case, engine, now, stores)
        if case.source_type == "memory"
        else {**replay(case, engine, now), "memory_exercised": False}
        for case in cases
    ]
    sources = [
        ROOT / "scripts/d4_eval.py",
        ROOT / "src/camel/detection/rules.py",
        ROOT / "src/camel/detection/models.py",
        ROOT / "src/camel/planner/models.py",
        *sorted((ROOT / "src/camel/memory").glob("*.py")),
        *sorted((ROOT / "tests/unit/memory").glob("*.py")),
    ]
    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    summary = {
        "stage": "D4",
        "run_id": output.name,
        "split": args.split,
        "base_commit": head,
        "model": None,
        "evidence_levels": ["E1", "E2"],
        "source_sha256": {path.relative_to(ROOT).as_posix(): sha256(path) for path in sources},
        "fixture_sha256": manifest["sha256"],
        "manifest_sha256": sha256(ROOT / "tests/fixtures/d/d1_v1/manifest.json"),
        "lock_sha256": sha256(ROOT / "uv.lock"),
        "clock": manifest["clock"],
        "policy_version": engine.policy_version,
        "memory_policy": stable(policy()),
        "counts": dict(Counter(row["status"] for row in rows)),
        "memory_case_count": sum(row["memory_exercised"] for row in rows),
        "previous_lifecycle_blocked_now_evaluable": sum(row.get("lifecycle_was_blocked_in_D1", False) for row in rows),
        "memory_benign_completed": sum(row["memory_exercised"] and row["benign_completed"] is True for row in rows),
        "memory_forbidden_effect_observed": sum(
            row["memory_exercised"] and bool(row["forbidden_observed"]) for row in rows
        ),
        "stricter_case_ids": [row["case_id"] for row in rows if row.get("stricter_due_to_memory_gate")],
        "python": sys.version,
        "platform": platform.platform(),
        "sqlite": sqlite3.sqlite_version,
        "dependencies": {name: importlib.metadata.version(name) for name in ["pydantic", "PyYAML"]},
        "started_utc": started.isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "limitations": "Synthetic setup, host-authenticated identity/labels assumed, public fixture HMAC key; plaintext payload DB, no OS sandbox/anti-rollback. Existing C audit adapter tested locally, not production pipeline/real tool execution. D1 truths unchanged; kernel and stricter lifecycle decisions reported separately.",
    }
    for name, value in [("observations.json", rows), ("summary.json", summary)]:
        (output / name).write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    print(
        json.dumps(
            {
                key: summary[key]
                for key in [
                    "counts",
                    "memory_case_count",
                    "previous_lifecycle_blocked_now_evaluable",
                    "memory_benign_completed",
                    "memory_forbidden_effect_observed",
                    "stricter_case_ids",
                ]
            },
            indent=2,
        )
    )
    return int(summary["counts"].get("FAIL", 0) > 0)


if __name__ == "__main__":
    raise SystemExit(main())
