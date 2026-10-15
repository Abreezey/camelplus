"""Explicit B interface stub for D2 tests; no path/shell interpretation or real IO."""

from datetime import datetime

from camel.core import CanonicalEffect, DataReference, EffectType
from camel.planner.models import CandidatePlan, CompiledTask, NormalizedCall, Source, ToolSpec
from camel.planner.validation import context, request_fingerprint, validate_plan
from camel.policy import PolicyEngine

TOOLS = (
    ToolSpec(
        tool_id="read_repository_document",
        version="fixture-v1",
        template="read_document",
        data_slots=frozenset({"focus"}),
    ),
    ToolSpec(
        tool_id="inspect_repository_code", version="fixture-v1", template="review_code", data_slots=frozenset({"focus"})
    ),
)


def normalize_fixture(
    compiled: CompiledTask, plan: CandidatePlan, sources: tuple[Source, ...], tools: tuple[ToolSpec, ...] = TOOLS
) -> tuple[NormalizedCall, ...]:
    source_map, tool_map, labels, _, _ = context(compiled, plan, sources, tools)
    return tuple(
        NormalizedCall(
            node_id=node.node_id,
            tool_id=node.tool_id,
            tool_version=node.tool_version,
            request_fingerprint=request_fingerprint(compiled, node, source_map, labels, tool_map[node.tool_id]),
            backend="fixture_stub",
            effects=tuple(
                CanonicalEffect(
                    effect_id=key,
                    type=EffectType.READ,
                    operation="read_file",
                    resources=(node.resource_id,),
                    data_refs=tuple(DataReference(ref=source, label=labels[source]) for source in node.source_ids),
                    derived_from=node.source_ids,
                )
                for key in node.effect_refs
            ),
        )
        for node in plan.nodes
    )


def replay_fixture(
    compiled: CompiledTask,
    plan: CandidatePlan,
    sources: tuple[Source, ...],
    engine: PolicyEngine,
    *,
    now: datetime,
    normalized: tuple[NormalizedCall, ...] | None = None,
):
    """Revalidate before recording. This ledger is synthetic; no real tool is invoked."""
    bundles = normalized if normalized is not None else normalize_fixture(compiled, plan, sources)
    result = validate_plan(compiled, plan, sources=sources, tools=TOOLS, normalized=bundles, engine=engine, now=now)
    ledger = (
        tuple(
            {
                "effect_id": effect.effect_id,
                "type": effect.type.value,
                "operation": effect.operation,
                "resources": list(effect.resources),
                "destination": effect.destination,
            }
            for effect in result.effects
        )
        if result.status == "READY"
        else ()
    )
    return result, ledger
