"""Pinned MCP security gateway (module B, arch.md §6.7).

All effects are evaluated before dispatch; one hard DENY blocks the whole call.
Pending confirmations bind arguments, labels, caller and manifest. Upstream
sessions are private deployment objects, never handed to the Agent. C must
enforce the process/network boundary that makes this ownership non-bypassable.
"""

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from mcp.shared.exceptions import McpError

from camel.audit import AuditContext, AuditStore
from camel.audit.store import decision_event
from camel.core.decision import Decision, DecisionOutcome
from camel.core.effect import CanonicalEffect, DataReference
from camel.core.events import CanonicalEvent
from camel.core.labels import Authority, Integrity, TrustLabel
from camel.gateway.audit import protected_decision_payload
from camel.gateway.models import (
    CallContext,
    GatewayError,
    GatewayResult,
    MCPTransport,
    ServerManifest,
    ToolResultEnvelope,
)
from camel.gateway.schema import bounded_json, validate_arguments, validate_schema
from camel.normalization import EffectNormalizer, IngressNormalizer, NormalizationError, TextView, ToolBinding
from camel.normalization.models import digest
from camel.policy import PolicyEngine
from camel.policy.ticket import TicketStore, issue_ticket, verify_ticket


@dataclass
class _Server:
    transport: MCPTransport
    manifest: ServerManifest
    bindings: dict[str, ToolBinding]
    lock: asyncio.Lock
    registration_context: CallContext
    suspended: bool = False


@dataclass(frozen=True)
class _Pending:
    server_id: str
    tool: str
    arguments_json: bytes
    context: CallContext
    effects: tuple[CanonicalEffect, ...]
    decisions: tuple[Decision, ...]
    manifest_digest: str
    policy_version: str
    event_id: str
    expires_at: datetime


class MCPSecurityGateway:
    def __init__(
        self,
        *,
        engine: PolicyEngine,
        normalizer: EffectNormalizer,
        audit: AuditStore,
        signing_key: bytes,
        ticket_store: TicketStore,
        result_sink: Callable[[ToolResultEnvelope], Awaitable[None]] | None = None,
        now_fn: Callable[[], datetime] | None = None,
        timeout: float = 30,
        confirmation_ttl: timedelta = timedelta(minutes=5),
        max_pending: int = 256,
    ) -> None:
        if not signing_key or timeout <= 0 or confirmation_ttl.total_seconds() <= 0 or max_pending < 1:
            raise ValueError("invalid_gateway_configuration")
        self._engine, self._normalizer, self._audit = engine, normalizer, audit
        self._key, self._tickets = signing_key, ticket_store
        self._sink = result_sink
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self._timeout, self._ttl, self._max_pending = timeout, confirmation_ttl, max_pending
        self._servers: dict[str, _Server] = {}
        self._pending: dict[str, _Pending] = {}
        self._budgets: dict[str, int] = {}
        # Contracts share a budget across servers; hold through dispatch to avoid races.
        self._dispatch_lock = asyncio.Lock()

    async def register(
        self,
        server_id: str,
        transport: MCPTransport,
        *,
        expected_identity: str,
        expected_digest: str | None,
        bindings: dict[str, ToolBinding],
        context: CallContext,
        allow_development_tofu: bool = False,
    ) -> str:
        if not server_id or "__" in server_id or server_id in self._servers:
            raise GatewayError("duplicate_or_invalid_server_id")
        manifest = await self._snapshot(transport)
        if server_id in self._servers:
            raise GatewayError("duplicate_or_invalid_server_id")
        if manifest.identity != expected_identity:
            raise GatewayError("server_identity_mismatch")
        if expected_digest is None and not allow_development_tofu:
            raise GatewayError("manifest_pin_required")
        if expected_digest is not None and manifest.digest != expected_digest:
            raise GatewayError("manifest_pin_mismatch")
        names = [t.name for t in manifest.tools]
        if len(set(names)) != len(names) or any(not n or "__" in n for n in names):
            raise GatewayError("duplicate_or_invalid_tool_name")
        if not set(bindings) <= set(names):
            raise GatewayError("binding_for_unknown_tool")
        for tool in manifest.tools:
            validate_schema(tool.input_schema)
        # Deep copies: frozen Pydantic models do not freeze nested dictionaries.
        manifest = ServerManifest.model_validate_json(manifest.model_dump_json())
        bindings = {k: ToolBinding.model_validate_json(v.model_dump_json()) for k, v in bindings.items()}
        self._event("tool_manifest_registered", context, {"server_id": server_id, "manifest_digest": manifest.digest})
        self._servers[server_id] = _Server(transport, manifest, bindings, asyncio.Lock(), context)
        return manifest.digest

    async def list_tools(self, *, context: CallContext | None = None) -> list[dict[str, Any]]:
        tools = []
        for server_id, server in list(self._servers.items()):
            if server.suspended:
                continue
            async with server.lock:
                try:
                    await self._check_manifest(server_id, server, context or server.registration_context)
                except GatewayError:
                    continue  # Already audited and suspended; never advertise stale tools.
            for tool in server.manifest.tools:
                if tool.name in server.bindings:
                    tools.append(
                        {
                            "name": f"{server_id}__{tool.name}",
                            "description": tool.description,
                            "inputSchema": json.loads(json.dumps(tool.input_schema)),
                        }
                    )
        return tools

    async def call_tool(
        self,
        server_id: str,
        tool: str,
        arguments: dict[str, Any],
        *,
        context: CallContext,
    ) -> GatewayResult:
        server = self._server(server_id)
        async with self._dispatch_lock, server.lock:
            await self._check_manifest(server_id, server, context)
            definition = next((t for t in server.manifest.tools if t.name == tool), None)
            if definition is None or tool not in server.bindings:
                raise GatewayError("tool_not_allowlisted")
            # Freeze arguments before awaiting upstream IO or retaining a confirmation.
            encoded = bounded_json(arguments)
            arguments = json.loads(encoded)
            validate_arguments(arguments, definition.input_schema)
            if context.contract is not None and context.contract.principal != context.subject:
                raise GatewayError("contract_principal_mismatch")
            call_event = self._event(
                "tool_call",
                context,
                {
                    "server_id": server_id,
                    "tool": tool,
                    "manifest_digest": server.manifest.digest,
                    "arguments_digest": digest(arguments),
                },
            )
            references = tuple(
                DataReference(
                    ref=f"argument:{key}:{digest(value)}", label=context.parameter_labels.get(key, TrustLabel())
                )
                for key, value in arguments.items()
            )
            # Bind every ticket to exact bytes, server identity, manifest and tool.
            call_label = TrustLabel(integrity=Integrity.TRUSTED_SYSTEM, authority=Authority.EXECUTE)
            for reference in (*context.normalization.data_refs, *references):
                call_label = call_label.join(reference.label)
            call_ref = DataReference(
                ref="mcp-call:"
                + digest(
                    {
                        "manifest": server.manifest.digest,
                        "identity": server.manifest.identity,
                        "tool": tool,
                        "arguments": arguments,
                    }
                ),
                label=call_label,
            )
            norm_context = context.normalization.model_copy(
                update={
                    "parent_ids": (*context.normalization.parent_ids, call_event.event_id),
                    "data_refs": (*context.normalization.data_refs, *references, call_ref),
                }
            )
            normalized = self._normalizer.normalize(server.bindings[tool], arguments, norm_context)
            if normalized.arguments is not None:
                arguments = normalized.arguments
                encoded = bounded_json(arguments)
                validate_arguments(arguments, definition.input_schema)
            now = self._now()
            budget_key = context.contract.contract_id if context.contract is not None else ""
            used = self._budgets.get(budget_key, 0)
            decisions = []
            for effect in normalized.effects:
                decision = self._engine.evaluate(effect, now=now, contract=context.contract, side_effects_used=used)
                used += int(effect.is_side_effecting)
                decisions.append(decision)
                event = decision_event(
                    decision,
                    effect,
                    trace_id=context.trace_id,
                    session_id=context.session_id,
                    principal=context.subject,
                    now=now,
                    parent_ids=(call_event.event_id,),
                )
                self._audit.append(
                    event,
                    payload=protected_decision_payload(
                        decision,
                        effect,
                        self._audit_context(context, server),
                        signing_key=self._key,
                        event_id=event.event_id,
                    ),
                )
            final = tuple(decisions)
            if normalized.blocked or not final or any(d.decision is DecisionOutcome.DENY for d in final):
                return GatewayResult(decisions=final)
            if any(d.decision is DecisionOutcome.CONFIRM for d in final):
                self._expire_pending()
                if len(self._pending) >= self._max_pending:
                    raise GatewayError("confirmation_capacity_exceeded")
                request_id = "gcfm_" + uuid.uuid4().hex
                self._event(
                    "confirmation_requested",
                    context,
                    {"request_id": request_id, "server_id": server_id},
                    parents=(call_event.event_id,),
                )
                self._pending[request_id] = _Pending(
                    server_id,
                    tool,
                    encoded,
                    CallContext.model_validate_json(context.model_dump_json()),
                    normalized.effects,
                    final,
                    server.manifest.digest,
                    self._engine.policy_version,
                    call_event.event_id,
                    now + self._ttl,
                )
                text = "\n".join(
                    f"{e.type.value} {e.operation}: resources={list(e.resources)}, destination={e.destination}, "
                    f"consequence={e.reversibility.value}"
                    for e in normalized.effects
                )
                text += "\nreasons=" + ", ".join(reason for d in final for reason in d.confirm_reasons)
                text += "\npolicy_version=" + self._engine.policy_version
                return GatewayResult(decisions=final, confirmation_id=request_id, confirmation_text=text)
            return await self._dispatch(
                server_id, server, tool, arguments, context, normalized.effects, final, call_event.event_id
            )

    async def resolve(self, request_id: str, *, approved: bool, context: CallContext) -> GatewayResult:
        """Trusted UI/API only. This method is deliberately absent from MCP tools."""
        async with self._dispatch_lock:
            pending = self._pending.get(request_id)
            if pending is None:
                raise GatewayError("unknown_or_consumed_confirmation")
            if (context.subject, context.session_id) != (pending.context.subject, pending.context.session_id):
                raise GatewayError("confirmation_subject_mismatch")
            del self._pending[request_id]  # Atomic consume before the first await.
            if self._now() >= pending.expires_at:
                raise GatewayError("confirmation_expired")
            server = self._server(pending.server_id)
            async with server.lock:
                await self._check_manifest(pending.server_id, server, pending.context)
                if (
                    server.manifest.digest != pending.manifest_digest
                    or self._engine.policy_version != pending.policy_version
                ):
                    raise GatewayError("confirmation_authorization_changed")
                if pending.context.contract is not None and pending.context.contract.is_expired(self._now()):
                    raise GatewayError("confirmation_contract_expired")
                self._event(
                    "confirmation_approved" if approved else "confirmation_denied",
                    pending.context,
                    {"request_id": request_id, "server_id": pending.server_id},
                    parents=(pending.event_id,),
                )
                if not approved:
                    return GatewayResult(decisions=pending.decisions)
                # Other calls may have spent this contract's budget while the
                # user was considering the request. Approval cannot override DENY.
                contract = pending.context.contract
                used = self._budgets.get(contract.contract_id, 0) if contract else 0
                decisions = []
                for effect in pending.effects:
                    decision = self._engine.evaluate(effect, now=self._now(), contract=contract, side_effects_used=used)
                    used += int(effect.is_side_effecting)
                    decisions.append(decision)
                    event = decision_event(
                        decision,
                        effect,
                        trace_id=pending.context.trace_id,
                        session_id=pending.context.session_id,
                        principal=pending.context.subject,
                        now=self._now(),
                        parent_ids=(pending.event_id,),
                    )
                    self._audit.append(
                        event,
                        payload=protected_decision_payload(
                            decision,
                            effect,
                            self._audit_context(pending.context, server),
                            signing_key=self._key,
                            event_id=event.event_id,
                        ),
                    )
                if any(
                    current.decision is DecisionOutcome.DENY
                    or set(current.confirm_reasons) - set(previous.confirm_reasons)
                    for current, previous in zip(decisions, pending.decisions)
                ):
                    raise GatewayError("confirmation_authorization_changed")
                return await self._dispatch(
                    pending.server_id,
                    server,
                    pending.tool,
                    json.loads(pending.arguments_json),
                    pending.context,
                    pending.effects,
                    tuple(decisions),
                    pending.event_id,
                )

    async def _dispatch(
        self,
        server_id: str,
        server: _Server,
        tool: str,
        arguments: dict[str, Any],
        context: CallContext,
        effects: tuple[CanonicalEffect, ...],
        decisions: tuple[Decision, ...],
        parent_id: str,
    ) -> GatewayResult:
        now = self._now()
        ticket_ids = []
        for effect in effects:
            ticket = issue_ticket(self._key, subject=context.subject, effect=effect, expires_at=now + self._ttl)
            verify_ticket(self._key, ticket, effect, subject=context.subject, store=self._tickets, now=now)
            ticket_ids.append(ticket.ticket_id)
        # Persist execution intent before dispatch; a crash has an explicit uncertain outcome.
        intent = self._event(
            "execution_prepared",
            context,
            {
                "tool": tool,
                "server_id": server_id,
                "manifest_digest": server.manifest.digest,
                "effect_ids": [e.effect_id for e in effects],
                "ticket_ids": ticket_ids,
                "arguments_digest": digest(arguments),
            },
            parents=(parent_id,),
        )
        if context.contract is not None:
            key = context.contract.contract_id
            self._budgets[key] = self._budgets.get(key, 0) + sum(e.is_side_effecting for e in effects)
        try:
            returned = await asyncio.wait_for(server.transport.call_tool(tool, arguments), self._timeout)
            bounded_json(returned, max_bytes=1048576)
        except (asyncio.TimeoutError, OSError, ValueError, RuntimeError, McpError, httpx.HTTPError) as err:
            self._event(
                "execution_failed",
                context,
                {"tool": tool, "server_id": server_id, "outcome": "uncertain"},
                parents=(intent.event_id,),
            )
            raise GatewayError("upstream_execution_failed") from err
        result_event_id = "evt_" + uuid.uuid4().hex
        label = server.bindings[tool].result_label.join(
            TrustLabel(
                integrity=Integrity.UNTRUSTED,
                authority=Authority.DATA_ONLY,
                provenance=frozenset({result_event_id, intent.event_id}),
            )
        )
        for effect in effects:
            for ref in effect.data_refs:
                label = label.join(ref.label)
        ingress = IngressNormalizer(max_input=1048576, max_output=2097152)
        views: dict[str, TextView] = {}

        def collect(value: Any, pointer: str) -> None:
            if isinstance(value, str):
                views[pointer] = ingress.normalize(value)
            elif isinstance(value, dict):
                for key, child in value.items():
                    collect(child, pointer + "/" + key.replace("~", "~0").replace("/", "~1"))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    collect(child, pointer + "/" + str(index))

        try:
            collect(returned, "")
        except NormalizationError as err:
            self._event(
                "tool_result_rejected",
                context,
                {"server_id": server_id, "tool": tool, "reason": "invalid_text_view"},
                parents=(intent.event_id,),
            )
            raise GatewayError("invalid_upstream_text") from err
        suspicious = any(
            (pointer.endswith("/role") and view.normalized.lower() in {"system", "user", "developer"})
            or view.suspicious_positions
            or any(
                marker in text.lower()
                for text in (view.normalized, *view.decoded_views)
                for marker in ('"role": "system"', '"role": "user"', "<|system|>", "<system>")
            )
            for pointer, view in views.items()
        )
        envelope = ToolResultEnvelope(
            event_id=result_event_id,
            server_id=server_id,
            server_identity=server.manifest.identity,
            tool=tool,
            manifest_digest=server.manifest.digest,
            labels=label,
            payload=returned,
            suspicious_content=suspicious,
            text_views=views,
        )
        self._event(
            "tool_result",
            context,
            {
                "server_id": server_id,
                "tool": tool,
                "manifest_digest": server.manifest.digest,
                "payload_digest": digest(returned),
                "suspicious_content": suspicious,
            },
            parents=(intent.event_id,),
            labels=label,
            event_id=result_event_id,
        )
        if self._sink is not None:
            await asyncio.wait_for(self._sink(envelope), self._timeout)
        return GatewayResult(decisions=decisions, output=envelope)

    async def _snapshot(self, transport: MCPTransport) -> ServerManifest:
        try:
            snapshot = await asyncio.wait_for(transport.snapshot(), self._timeout)
            bounded_json(snapshot.model_dump(mode="json"), max_bytes=1048576)
            return snapshot
        except (asyncio.TimeoutError, OSError, ValueError, RuntimeError, McpError, httpx.HTTPError) as err:
            raise GatewayError("manifest_unavailable") from err

    async def _check_manifest(self, server_id: str, server: _Server, context: CallContext) -> None:
        if server.suspended:
            raise GatewayError("tool_server_suspended")
        try:
            current = await self._snapshot(server.transport)
        except GatewayError:
            server.suspended = True
            self._event("tool_manifest_unavailable", context, {"server_id": server_id})
            raise
        if current.digest != server.manifest.digest:
            server.suspended = True
            self._event(
                "tool_manifest_changed",
                context,
                {"server_id": server_id, "expected_digest": server.manifest.digest, "observed_digest": current.digest},
            )
            raise GatewayError("tool_manifest_changed")

    def _server(self, server_id: str) -> _Server:
        if server_id not in self._servers:
            raise GatewayError("server_not_registered")
        return self._servers[server_id]

    def _expire_pending(self) -> None:
        now = self._now()
        for key in [key for key, value in self._pending.items() if value.expires_at <= now]:
            del self._pending[key]

    @staticmethod
    def _audit_context(context: CallContext, server: _Server) -> AuditContext:
        return AuditContext(
            model_version=context.model_version,
            tool_manifest_digest=server.manifest.digest,
            code_commit=context.code_commit,
        )

    def _event(
        self,
        source: str,
        context: CallContext,
        payload: dict[str, Any],
        *,
        parents: tuple[str, ...] = (),
        labels: TrustLabel | None = None,
        event_id: str | None = None,
    ) -> CanonicalEvent:
        server_id = payload.get("server_id")
        manifest = payload.get("manifest_digest")
        if manifest is None and server_id in self._servers:
            manifest = self._servers[server_id].manifest.digest
        payload = {
            **payload,
            "context": AuditContext(
                model_version=context.model_version, tool_manifest_digest=manifest, code_commit=context.code_commit
            ).model_dump(),
        }
        event = CanonicalEvent(
            event_id=event_id or "evt_" + uuid.uuid4().hex,
            trace_id=context.trace_id,
            session_id=context.session_id,
            parent_ids=parents or context.normalization.parent_ids,
            principal=context.subject,
            source=source,
            payload_ref="gateway:" + digest(payload),
            labels=labels or TrustLabel(),
            timestamp=self._now(),
        )
        self._audit.append(event, payload=payload)
        return event
