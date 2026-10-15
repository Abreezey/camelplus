"""Regressions for RPC dataflow, audit confidentiality and process approval."""

import json
import sys
from contextlib import asynccontextmanager

import pytest

from camel.audit import AuditStore, ProvenanceService
from camel.core.decision import DecisionOutcome
from camel.core.effect import CanonicalEffect, EffectType
from camel.core.labels import Confidentiality, TrustLabel
from camel.gateway import GatewayError, ToolManifest, connect_stdio
from camel.gateway.transports import stdio_identity
from camel.normalization import EffectSpec, ToolBinding
from camel.policy import PolicyEngine, load_rules
from tests.unit.gateway.conftest import register

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("confidentiality", [Confidentiality.SECRET, Confidentiality.PUBLIC])
async def test_composite_rpc_propagates_file_labels_before_dispatch(env, reverse, confidentiality):
    specs = (
        EffectSpec(type=EffectType.READ, operation="read", resource_fields=("path",)),
        EffectSpec(type=EffectType.EGRESS, operation="send", destination_field="to"),
    )
    env.transport.manifest = env.transport.manifest.model_copy(
        update={"tools": (ToolManifest(name="read", input_schema={"type": "object"}),)}
    )
    context = env.context.model_copy(
        update={
            "normalization": env.context.normalization.model_copy(
                update={"resource_labels": {str(env.root / "note"): TrustLabel(confidentiality=confidentiality)}}
            )
        }
    )
    await register(env, bindings={"read": ToolBinding(adapter="mcp", effects=specs[::-1] if reverse else specs)})
    result = await env.gateway.call_tool("files", "read", {"path": "note", "to": "external"}, context=context)
    denied = confidentiality is Confidentiality.SECRET
    assert any(d.decision is DecisionOutcome.DENY for d in result.decisions) == denied
    assert len(env.transport.calls) == (0 if denied else 1)


@pytest.mark.parametrize("outcome", ["ALLOW", "CONFIRM", "DENY"])
async def test_secret_url_is_absent_from_sqlite_report_and_replay_is_exact(env, outcome):
    from camel.gateway.audit import recover_decision_payload

    marker = "SYNTHETIC_QUERY_TOKEN"
    url = "https://example.com/private/" + marker + "?token=" + marker
    env.audit = AuditStore(env.root / "audit.db")
    env.gateway._audit = env.audit
    if outcome == "CONFIRM":
        env.gateway._engine = PolicyEngine(load_rules("id: confirm\nwhen: {}\nthen: CONFIRM"))
    env.transport.returned = {"content": []}
    env.transport.manifest = env.transport.manifest.model_copy(
        update={"tools": (ToolManifest(name="read", input_schema={"type": "object"}),)}
    )
    await register(env, bindings={"read": ToolBinding(adapter="net", operation="GET")})
    context = env.context.model_copy(
        update={
            "parameter_labels": {
                "url": TrustLabel(
                    confidentiality=Confidentiality.SECRET if outcome == "DENY" else Confidentiality.PUBLIC
                )
            }
        }
    )
    result = await env.gateway.call_tool("files", "read", {"url": url}, context=context)
    assert result.decisions[0].decision.value == outcome
    if outcome == "CONFIRM":
        await env.gateway.resolve(result.confirmation_id, approved=True, context=context)
    assert len(env.transport.calls) == (0 if outcome == "DENY" else 1)
    events = env.audit.events()
    assert marker not in json.dumps([env.audit.payload_of(e.event_id) for e in events])
    assert marker not in ProvenanceService(env.audit).report(context.trace_id)
    assert marker.encode() not in (env.root / "audit.db").read_bytes()
    event = next(e for e in events if e.source == "decision")
    payload = env.audit.payload_of(event.event_id)
    assert payload is not None
    restored = recover_decision_payload(payload, signing_key=b"gateway-test-key", event_id=event.event_id)
    assert restored["effect"]["destination"] == url
    assert restored["decision"] == result.decisions[0].model_dump(mode="json")
    replayed = env.gateway._engine.evaluate(CanonicalEffect.model_validate(restored["effect"]), now=env.now[0])
    assert replayed.model_dump(mode="json") == restored["decision"]
    env.audit.verify_chain()
    with pytest.raises(GatewayError, match="audit_payload_invalid"):
        recover_decision_payload(payload, signing_key=b"wrong-key", event_id=event.event_id)
    with pytest.raises(GatewayError, match="audit_payload_invalid"):
        recover_decision_payload(payload, signing_key=b"gateway-test-key", event_id="another-event")
    with pytest.raises(GatewayError, match="audit_payload_invalid"):
        recover_decision_payload(
            {**payload, "payload_digest": "tampered"}, signing_key=b"gateway-test-key", event_id=event.event_id
        )
    with pytest.raises(GatewayError, match="audit_payload_invalid"):
        recover_decision_payload(
            {**payload, "payload_format": "unknown"}, signing_key=b"gateway-test-key", event_id=event.event_id
        )


async def test_ifc_reason_does_not_leak_secret_filename(env):
    marker = "SYNTHETIC_SECRET_FILENAME"
    env.transport.manifest = env.transport.manifest.model_copy(
        update={"tools": (ToolManifest(name="read", input_schema={"type": "object"}),)}
    )
    await register(
        env,
        bindings={
            "read": ToolBinding(
                adapter="mcp",
                effects=(
                    EffectSpec(
                        type=EffectType.EGRESS, operation="send", resource_fields=("path",), destination_field="to"
                    ),
                ),
            )
        },
    )
    result = await env.gateway.call_tool("files", "read", {"path": marker, "to": "external"}, context=env.context)
    assert result.decisions[0].decision is DecisionOutcome.DENY
    assert marker not in json.dumps([env.audit.payload_of(e.event_id) for e in env.audit.events()])
    assert marker not in ProvenanceService(env.audit).report(env.context.trace_id)


async def test_stdio_rejects_changed_script_before_startup(tmp_path, monkeypatch):
    script = tmp_path / "server.py"
    marker = tmp_path / "started"
    script.write_text("# approved")
    args = (str(script),)
    approved = stdio_identity(sys.executable, args, {})
    script.write_text("# replaced")
    starts = []

    @asynccontextmanager
    async def start(parameters):
        starts.append(parameters)
        marker.write_text("started")
        raise AssertionError("unapproved process started")
        yield

    monkeypatch.setattr("camel.gateway.transports.stdio_client", start)
    with pytest.raises(GatewayError, match="stdio_identity_mismatch"):
        async with connect_stdio(sys.executable, args, expected_identity=approved):
            pytest.fail("unapproved process connected")
    assert not starts and not marker.exists()
