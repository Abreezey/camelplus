"""End-to-end full-system demo: B boundary + A decision + C execution + audit.

Covers the arch.md §10.1 MVP items now reachable on the integrated chain:

1. ordinary repository file read  → ALLOW, really executed in the sandbox;
2. secret egress to any domain    → IFC hard DENY, zero execution;
3. allowlisted egress             → ALLOW, pinned-IP request with the
   vault-derived credential (stub transport — no real network).

Prints every decision, verifies the audit hash chain and renders the
provenance report. Exit 0 only if all expectations hold.
"""

import argparse
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from camel.audit import AuditContext, AuditStore, ProvenanceService
from camel.broker import (
    ConfirmationAuthority,
    ExecutionBroker,
    KeyVault,
    SandboxProfile,
    SecureExecutionPipeline,
)
from camel.core.effect import CanonicalEffect, DataReference, EffectType
from camel.core.labels import Confidentiality, TrustLabel
from camel.normalization import NetworkPolicy
from camel.policy import PolicyEngine, load_rules

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(minutes=5)
KEY = b"demo-signing-key"
MASTER = b"demo-master-key"
PUBLIC_IP = "93.184.216.34"


class StubEgressTransport(httpx.BaseTransport):
    """Records the pinned request; answers with a canned 200 (no real network)."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, content=b'{"status": "accepted"}', request=request)


class MemoryTickets:
    def __init__(self) -> None:
        self._uses: dict[str, int] = {}
        self._lock = threading.Lock()

    def uses(self, ticket_id: str) -> int:
        return self._uses.get(ticket_id, 0)

    def try_consume(self, ticket_id: str, max_uses: int) -> bool:
        with self._lock:
            current = self._uses.get(ticket_id, 0)
            if current >= max_uses:
                return False
            self._uses[ticket_id] = current + 1
            return True


def read_effect(document: Path) -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_demo_read",
        type=EffectType.READ,
        operation="file_read",
        resources=(str(document),),
    )


def secret_egress_effect() -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_demo_secret_egress",
        type=EffectType.EGRESS,
        operation="http_post",
        destination="https://example.com/upload",
        data_refs=(DataReference(ref="value://api_key", label=TrustLabel(confidentiality=Confidentiality.SECRET)),),
    )


def public_egress_effect() -> CanonicalEffect:
    return CanonicalEffect(
        effect_id="fx_demo_public_egress",
        type=EffectType.EGRESS,
        operation="http_post",
        destination="https://example.com/upload",
        data_refs=(DataReference(ref="value://summary", label=TrustLabel(confidentiality=Confidentiality.PUBLIC)),),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=None, help="demo workspace (default: a fresh temp dir)")
    options = parser.parse_args()

    root = options.workspace or Path(tempfile.mkdtemp(prefix="camel-full-system-demo-"))
    workspace = root / "workspace"
    scratch = root / "scratch"
    workspace.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    document = workspace / "README.md"
    document.write_text("Project documentation describes the public module layout.", encoding="utf-8")

    audit = AuditStore(str(root / "audit.sqlite"))
    transport = StubEgressTransport()
    broker = ExecutionBroker(
        signing_key=KEY,
        profile=SandboxProfile.workspace(workspace, scratch),
        ticket_store=MemoryTickets(),
        audit=audit,
        now_fn=lambda: NOW,
        vault=KeyVault(MASTER),
        network=NetworkPolicy(allowed_hosts=frozenset({"example.com"})),
        resolver=lambda host, port: (PUBLIC_IP,),
        transport=transport,
    )
    pipeline = SecureExecutionPipeline(
        engine=PolicyEngine(
            load_rules(
                """id: allow-workspace-read
when:
  effect.type: READ
then: ALLOW
---
id: allow-listed-egress
when:
  effect.type: EGRESS
then: ALLOW
"""
            )
        ),
        broker=broker,
        confirmations=ConfirmationAuthority(signing_key=KEY, audit=audit, now_fn=lambda: NOW),
        audit=audit,
        signing_key=KEY,
        now_fn=lambda: NOW,
    )
    context = AuditContext(
        model_version="demo:offline",
        tool_manifest_digest="sha256:demo-manifest",
        code_commit="demo-commit",
    )
    results = []

    # 1. ordinary repository read — allowed and really executed
    read = pipeline.run(
        read_effect(document), subject="user:demo", trace_id="demo-read", session_id="demo", audit_context=context
    )
    executed = read.execution is not None and read.execution.output == document.read_bytes()
    results.append(("repository read allowed + executed", read.decision.decision.value == "ALLOW" and executed))
    print(f"[1] repository read      -> {read.decision.decision.value:8s} executed={executed}")

    # 2. secret egress — IFC hard deny, zero execution
    secret = pipeline.run(
        secret_egress_effect(), subject="user:demo", trace_id="demo-secret", session_id="demo", audit_context=context
    )
    blocked = secret.decision.decision.value == "DENY" and secret.execution is None
    results.append(("secret egress IFC-denied with zero execution", blocked))
    print(
        f"[2] secret egress        -> {secret.decision.decision.value:8s} hard_reasons={secret.decision.hard_reasons}"
    )

    # 3. allowlisted egress — pinned IP + vault credential, stub transport
    egress = pipeline.run(
        public_egress_effect(), subject="user:demo", trace_id="demo-egress", session_id="demo", audit_context=context
    )
    sent = bool(transport.requests) and transport.requests[0].url.host == PUBLIC_IP
    credential = egress.execution.credential_handle if egress.execution is not None else None
    ok = egress.decision.decision.value == "ALLOW" and sent and credential is not None
    results.append(("allowlisted egress executed via pinned IP with credential", ok))
    print(
        f"[3] allowlisted egress   -> {egress.decision.decision.value:8s} "
        f"pinned_ip={transport.requests[0].url.host if transport.requests else None} credential={credential}"
    )

    # 4. audit chain + provenance
    audit.verify_chain()
    report = ProvenanceService(audit).report("demo-read")
    print("[4] audit chain verified; provenance report (demo-read) excerpt:")
    for line in report.splitlines()[:8]:
        print("    " + line)
    payloads = [
        audit.payload_of(e.event_id)
        for trace in ("demo-read", "demo-secret", "demo-egress")
        for e in audit.events(trace)
    ]
    context_ok = all((payload or {}).get("context", {}).get("code_commit") == "demo-commit" for payload in payloads)
    results.append(("audit context fields recorded on every payload", context_ok))

    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed" + (f"; FAILED: {failed}" if failed else ""))
    audit.close()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
