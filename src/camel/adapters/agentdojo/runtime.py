"""AgentDojo suite runtime behind the real A/B/C/D gateway chain.

AgentDojo tools mutate an in-memory benchmark environment, so they remain one
composite upstream RPC owned by the B gateway.  C contributes the durable
ticket and hash-chained audit stores; routing these virtual calls through the
local filesystem/HTTP broker would execute a different system.
"""

import asyncio
import copy
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from agentdojo.functions_runtime import Function, FunctionReturnType, FunctionsRuntime, TaskEnvironment
from pydantic import BaseModel

from camel.audit import AuditStore, SQLiteTicketStore
from camel.core import Authority, Integrity, TrustLabel
from camel.core.decision import DecisionOutcome
from camel.core.effect import EffectType
from camel.detection.gateway_bridge import DetectionSink
from camel.gateway import CallContext, GatewayError, MCPSecurityGateway, ServerManifest, ToolManifest
from camel.normalization import EffectNormalizer, EffectSpec, NormalizationContext, ToolBinding
from camel.policy import PolicyEngine, load_rules

WORKSPACE_READ_TOOLS = frozenset(
    {
        "get_unread_emails",
        "get_sent_emails",
        "get_received_emails",
        "get_draft_emails",
        "search_emails",
        "search_contacts_by_name",
        "search_contacts_by_email",
        "get_current_day",
        "search_calendar_events",
        "get_day_calendar_events",
        "search_files_by_filename",
        "get_file_by_id",
        "list_files",
        "search_files",
    }
)
WORKSPACE_WRITE_TOOLS = frozenset(
    {
        "send_email",
        "delete_email",
        "create_calendar_event",
        "cancel_calendar_event",
        "reschedule_calendar_event",
        "add_calendar_event_participants",
        "append_to_file",
        "create_file",
        "delete_file",
        "share_file",
    }
)
# Per-suite frozen tool review.  Source of truth: the existing reviewed sets in
# pipeline_elements/security_policies/{workspace,travel,banking,slack}.py —
# no_side_effect_tools (READ) and the registered policies (WRITE).  Slack's
# get_webpage carries an is_public policy but is a read of untrusted web
# content, so it is classified READ here (result labels are UNTRUSTED anyway).
SUITE_TOOL_REVIEWS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "workspace": (WORKSPACE_READ_TOOLS, WORKSPACE_WRITE_TOOLS),
    "travel": (
        frozenset(
            {
                "get_user_information",
                "get_all_hotels_in_city",
                "get_hotels_prices",
                "get_rating_reviews_for_hotels",
                "get_hotels_address",
                "get_all_restaurants_in_city",
                "get_cuisine_type_for_restaurants",
                "get_restaurants_address",
                "get_rating_reviews_for_restaurants",
                "get_dietary_restrictions_for_all_restaurants",
                "get_contact_information_for_restaurants",
                "get_price_for_restaurants",
                "check_restaurant_opening_hours",
                "get_all_car_rental_companies_in_city",
                "get_car_types_available",
                "get_rating_reviews_for_car_rental",
                "get_car_fuel_options",
                "get_car_rental_address",
                "get_car_price_per_day",
                "search_calendar_events",
                "get_day_calendar_events",
                "get_flight_information",
            }
        ),
        frozenset(
            {
                "send_email",
                "create_calendar_event",
                "cancel_calendar_event",
                "reserve_hotel",
                "reserve_car_rental",
                "reserve_restaurant",
            }
        ),
    ),
    "banking": (
        frozenset(
            {
                "get_iban",
                "get_balance",
                "get_most_recent_transactions",
                "get_scheduled_transactions",
                "read_file",
                "get_user_info",
            }
        ),
        frozenset(
            {
                "send_money",
                "schedule_transaction",
                "update_scheduled_transaction",
                "update_password",
                "update_user_info",
            }
        ),
    ),
    "slack": (
        frozenset(
            {
                "get_channels",
                "read_channel_messages",
                "read_inbox",
                "get_users_in_channel",
                "get_webpage",
            }
        ),
        frozenset(
            {
                "add_user_to_channel",
                "send_direct_message",
                "send_channel_message",
                "invite_user_to_slack",
                "remove_user_from_slack",
                "post_webpage",
            }
        ),
    ),
}

_POLICY = """\
id: agentdojo-read
when:
  effect.type: READ
then: ALLOW
---
id: agentdojo-side-effect
when:
  effect.type: WRITE
then: CONFIRM
"""


def _json_value(value: FunctionReturnType) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list | tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


class AgentDojoTransport:
    """Trusted gateway transport for one benchmark episode."""

    def __init__(self, functions: Sequence[Function], suite: str = "workspace") -> None:
        self._runtime = FunctionsRuntime(functions)
        self.environment: TaskEnvironment | None = None
        self.last_value: FunctionReturnType = None
        self.manifest = ServerManifest(
            identity=f"agentdojo:{suite}:0.1.34:v1.2",
            tools=tuple(
                ToolManifest(
                    name=function.name,
                    description=function.description,
                    input_schema=function.parameters.model_json_schema(),
                )
                for function in functions
            ),
        )

    async def snapshot(self) -> ServerManifest:
        return self.manifest

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value, error = self._runtime.run_function(self.environment, name, arguments)
        if error is not None:
            raise ValueError("agentdojo_upstream_tool_error")
        self.last_value = value
        # The gateway walks every string leaf into a separate detection view.
        # AgentDojo list results can contain hundreds of fields, so serialize
        # the complete value into one deterministic view without truncation.
        # The benchmark still receives ``last_value`` in its native type.
        return {
            "value_json": json.dumps(
                _json_value(value),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        }


def suite_bindings(suite: str, functions: Sequence[Function]) -> dict[str, ToolBinding]:
    """Freeze every suite tool as read-only or confirmation-required (fail closed on new tools)."""
    if suite not in SUITE_TOOL_REVIEWS:
        raise ValueError("unreviewed_agentdojo_suite:" + suite)
    read_tools, write_tools = SUITE_TOOL_REVIEWS[suite]
    names = {function.name for function in functions}
    unknown = names - read_tools - write_tools
    if unknown:
        raise ValueError("unreviewed_agentdojo_tools:" + ",".join(sorted(unknown)))
    result_label = TrustLabel(integrity=Integrity.UNTRUSTED, authority=Authority.DATA_ONLY)
    return {
        name: ToolBinding(
            adapter="mcp",
            effects=(
                EffectSpec(
                    type=EffectType.READ if name in read_tools else EffectType.WRITE,
                    operation="agentdojo_" + name,
                ),
            ),
            result_label=result_label,
        )
        for name in names
    }


class AgentDojoGatewayRuntime(FunctionsRuntime):
    """Synchronous AgentDojo runtime interposed by the production gateway."""

    def __init__(
        self,
        functions: Sequence[Function],
        *,
        root: Path,
        model_version: str,
        session_id: str,
        auto_approve_writes: bool = False,
        suite: str = "workspace",
    ) -> None:
        super().__init__(functions)
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.audit = AuditStore(self.root / "audit.sqlite")
        self.tickets = SQLiteTicketStore(self.root / "tickets.sqlite")
        self.detection = DetectionSink()
        self.suite = suite
        self.transport = AgentDojoTransport(functions, suite)
        self._sequence = 0
        self._session_id = session_id
        self._model_version = model_version
        self._auto_approve_writes = auto_approve_writes
        self._context = CallContext(
            subject="agentdojo:benchmark",
            trace_id=session_id + ":registration",
            session_id=session_id,
            normalization=NormalizationContext(workspace=self.root, cwd=self.root),
            model_version=model_version,
        )
        self.gateway = MCPSecurityGateway(
            engine=PolicyEngine(load_rules(_POLICY)),
            normalizer=EffectNormalizer(),
            audit=self.audit,
            signing_key=(session_id + ":agentdojo-gateway").encode(),
            ticket_store=self.tickets,
            result_sink=self.detection,
        )
        self.manifest_digest = asyncio.run(
            self.gateway.register(
                suite,
                self.transport,
                expected_identity=self.transport.manifest.identity,
                expected_digest=self.transport.manifest.digest,
                bindings=suite_bindings(suite, functions),
                context=self._context,
            )
        )

    def run_function(
        self,
        env: TaskEnvironment | None,
        function: str,
        kwargs: Mapping[str, Any],
        raise_on_error: bool = False,
    ) -> tuple[FunctionReturnType, str | None]:
        self.transport.environment = env
        self._sequence += 1
        context = self._context.model_copy(
            update={
                "trace_id": f"{self._session_id}:tool:{self._sequence}",
                "normalization": self._context.normalization.model_copy(
                    update={"parent_ids": (f"agentdojo-call:{self._sequence}",)}
                ),
            }
        )
        try:

            async def dispatch():
                result = await self.gateway.call_tool(
                    self.suite, function, copy.deepcopy(dict(kwargs)), context=context
                )
                if result.confirmation_id is not None and self._auto_approve_writes:
                    result = await self.gateway.resolve(result.confirmation_id, approved=True, context=context)
                return result

            result = asyncio.run(dispatch())
            if result.output is None:
                outcome = result.decisions[-1].decision if result.decisions else DecisionOutcome.DENY
                return f"Tool call blocked by security policy ({outcome.value}).", None
            return self.transport.last_value, None
        except (GatewayError, ValueError, OSError, RuntimeError) as error:
            if raise_on_error:
                raise
            return "", f"{type(error).__name__}: {error}"

    def summary(self) -> dict[str, Any]:
        self.audit.verify_chain()
        events = self.audit.events()
        decisions = []
        for event in events:
            payload = self.audit.payload_of(event.event_id)
            if event.source == "decision" and payload is not None:
                decisions.append(payload["decision"])
        return {
            "manifest_digest": self.manifest_digest,
            "audit_events": len(events),
            "audit_sources": sorted({event.source for event in events}),
            "detection_results": len(self.detection.results),
            "detection_findings": sum(len(result.findings) for result in self.detection.results.values()),
            "decisions": {
                outcome: sum(decision["decision"] == outcome for decision in decisions)
                for outcome in ("ALLOW", "CONFIRM", "DENY")
            },
            "confirmations": {
                outcome: sum(event.source == "confirmation_" + outcome for event in events)
                for outcome in ("requested", "approved", "denied")
            },
        }

    def close(self) -> None:
        self.tickets.close()
        self.audit.close()
