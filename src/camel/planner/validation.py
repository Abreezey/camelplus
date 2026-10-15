"""Bounded TDG construction and policy validation, without executing any tool."""

from datetime import datetime

from camel.core import EffectType, IntentContract, TrustLabel, validate_child_contract
from camel.core.effect import NormalizationConfidence
from camel.planner.compiler import compile_task, fingerprint, require_clock
from camel.planner.models import (
    Binding,
    CandidatePlan,
    CompiledTask,
    Explanation,
    GraphEdge,
    NormalizedCall,
    PlanValidation,
    Source,
    ToolNode,
    ToolSpec,
)
from camel.policy import PolicyEngine


class PlanError(ValueError):
    """Invalid structure, unregistered identity, source graph or adapter binding."""


def parse_candidate(raw: str, *, max_bytes: int = 65536) -> CandidatePlan:
    if not raw.strip() or len(raw.encode("utf-8")) > max_bytes:
        raise PlanError("candidate_empty_or_over_budget")
    return CandidatePlan.model_validate_json(raw)


def topological(nodes: set[str], edges: tuple[GraphEdge, ...]) -> tuple[str, ...]:
    incoming = {node: set() for node in nodes}
    outgoing = {node: set() for node in nodes}
    for edge in edges:
        if edge.source not in nodes or edge.target not in nodes:
            raise PlanError("missing_graph_reference")
        incoming[edge.target].add(edge.source)
        outgoing[edge.source].add(edge.target)
    ready = sorted(node for node in nodes if not incoming[node])
    result = []
    while ready:
        node = ready.pop(0)
        result.append(node)
        for child in sorted(outgoing[node]):
            incoming[child].remove(node)
            if not incoming[child]:
                ready.append(child)
                ready.sort()
    if len(result) != len(nodes):
        raise PlanError("dependency_cycle")
    return tuple(result)


def context(compiled: CompiledTask, plan: CandidatePlan, sources: tuple[Source, ...], tools: tuple[ToolSpec, ...]):
    limits = compiled.organization
    if plan.task_id != compiled.task.task_id:
        raise PlanError("task_identity_mismatch")
    if len(plan.nodes) > limits.max_nodes or len(sources) > limits.max_sources:
        raise PlanError("graph_budget_exceeded")
    if sum(len(node.effect_refs) for node in plan.nodes) > limits.max_effects:
        raise PlanError("effect_budget_exceeded")
    if sum(len(field.value) for source in sources for field in source.fields) > limits.max_source_characters:
        raise PlanError("source_text_budget_exceeded")
    source_map = {source.source_id: source for source in sources}
    tool_map = {tool.tool_id: tool for tool in tools}
    node_map = {node.node_id: node for node in plan.nodes}
    if len(source_map) != len(sources) or len(tool_map) != len(tools) or len(node_map) != len(plan.nodes):
        raise PlanError("duplicate_source_tool_or_node_identity")
    labels: dict[str, TrustLabel] = {}
    visiting = set()

    def label_of(key: str) -> TrustLabel:
        if key not in source_map:
            raise PlanError("missing_source_reference")
        if key in visiting:
            raise PlanError("source_cycle")
        if key in labels:
            return labels[key]
        visiting.add(key)
        source = source_map[key]
        if source.source_id not in source.label.provenance:
            raise PlanError("source_provenance_missing")
        names = [field.name for field in source.fields]
        if len(set(names)) != len(names):
            raise PlanError("duplicate_source_field")
        label = source.label
        for parent in source.parent_ids:
            label = label.join(label_of(parent))
        visiting.remove(key)
        labels[key] = label
        return label

    for key in sorted(source_map):
        label_of(key)
    edges = []
    task_vertex = "task:" + compiled.task.task_id
    vertices = {task_vertex, *("source:" + key for key in source_map), *("tool:" + key for key in node_map)}
    for source in sources:
        for parent in source.parent_ids:
            edges.append(GraphEdge(source="source:" + parent, target="source:" + source.source_id, kind="derived"))
        if source.producer_node_id is not None:
            if source.producer_node_id not in node_map:
                raise PlanError("missing_source_producer")
            edges.append(
                GraphEdge(
                    source="tool:" + source.producer_node_id, target="source:" + source.source_id, kind="tool_result"
                )
            )
    effects_seen = set()
    for node in plan.nodes:
        spec = tool_map.get(node.tool_id)
        if spec is None:
            raise PlanError("unregistered_tool")
        if node.tool_version != spec.version:
            raise PlanError("tool_manifest_changed")
        if spec.template != compiled.task.template:
            raise PlanError("tool_not_in_task_template")
        slot_names = [slot.name for slot in node.data_slots]
        if len(set(slot_names)) != len(slot_names) or not set(slot_names) <= spec.data_slots:
            raise PlanError("unknown_or_duplicate_data_slot")
        if len(set(node.source_ids)) != len(node.source_ids) or not set(node.source_ids) <= set(source_map):
            raise PlanError("missing_or_duplicate_node_source")
        if len(set(node.effect_refs)) != len(node.effect_refs) or effects_seen.intersection(node.effect_refs):
            raise PlanError("duplicate_effect_reference")
        effects_seen.update(node.effect_refs)
        edges.append(GraphEdge(source=task_vertex, target="tool:" + node.node_id, kind="authorization"))
        for key in node.source_ids:
            edges.append(GraphEdge(source="source:" + key, target="tool:" + node.node_id, kind="data"))
        for slot in node.data_slots:
            if slot.binding is not None:
                binding = slot.binding
                if binding.source_id not in node.source_ids:
                    raise PlanError("slot_source_not_declared")
                if binding.field not in {field.name for field in source_map[binding.source_id].fields}:
                    raise PlanError("missing_data_field")
        if len(set(node.depends_on)) != len(node.depends_on):
            raise PlanError("duplicate_dependency")
        for parent in node.depends_on:
            if parent not in node_map:
                raise PlanError("missing_tool_dependency")
            edges.append(GraphEdge(source="tool:" + parent, target="tool:" + node.node_id, kind="dependency"))
    frozen_edges = tuple(sorted(edges, key=lambda edge: (edge.source, edge.target, edge.kind)))
    order = topological(vertices, frozen_edges)
    ordered_nodes = tuple(vertex[5:] for vertex in order if vertex.startswith("tool:"))
    return source_map, tool_map, labels, frozen_edges, ordered_nodes


def request_fingerprint(
    compiled: CompiledTask, node: ToolNode, sources: dict[str, Source], labels: dict[str, TrustLabel], spec: ToolSpec
) -> str:
    resolved = {
        slot.name: next(
            field.value for field in sources[slot.binding.source_id].fields if field.name == slot.binding.field
        )
        for slot in node.data_slots
        if slot.binding is not None
    }
    return fingerprint(
        {
            "contract": compiled.fingerprint,
            "node": node,
            "manifest": spec,
            "resolved_data": resolved,
            "labels": {key: labels[key] for key in node.source_ids},
        }
    )


def validate_plan(
    compiled: CompiledTask,
    plan: CandidatePlan,
    *,
    sources: tuple[Source, ...],
    tools: tuple[ToolSpec, ...],
    normalized: tuple[NormalizedCall, ...],
    engine: PolicyEngine,
    now: datetime,
) -> PlanValidation:
    require_clock(now)
    original = compile_task(compiled.task, compiled.organization, now=compiled.issued_at).compiled
    if (
        original is None
        or original.contract != compiled.contract
        or fingerprint(compiled.contract) != compiled.fingerprint
    ):
        raise PlanError("compiled_authorization_changed")
    if now < compiled.issued_at:
        raise PlanError("clock_precedes_compilation")
    source_map, tool_map, labels, edges, order = context(compiled, plan, sources, tools)
    bundles = {item.node_id: item for item in normalized}
    if len(bundles) != len(normalized) or set(bundles) != {node.node_id for node in plan.nodes}:
        raise PlanError("missing_or_extra_normalized_call")
    by_id = {node.node_id: node for node in plan.nodes}
    effects = []
    explanations = []
    reasons = []
    authorization_reasons = []
    needs_authorization = False
    for node_id in order:
        node = by_id[node_id]
        bundle = bundles[node_id]
        spec = tool_map[node.tool_id]
        if bundle.tool_id != node.tool_id or bundle.tool_version != spec.version:
            raise PlanError("normalized_tool_identity_mismatch")
        if bundle.request_fingerprint != request_fingerprint(compiled, node, source_map, labels, spec):
            raise PlanError("stale_normalized_request")
        if tuple(effect.effect_id for effect in bundle.effects) != node.effect_refs:
            raise PlanError("normalized_effect_reference_mismatch")
        if node.resource_id not in compiled.task.resource_ids:
            needs_authorization = True
            authorization_reasons.append("resource_scope_change_requires_authorization")
        for effect in bundle.effects:
            if (
                effect.type != EffectType.READ
                or effect.operation != "read_file"
                or effect.resources != (node.resource_id,)
                or effect.destination is not None
                or bool(effect.required_capabilities)
            ):
                reasons.append("normalized_effect_exceeds_read_tool_manifest")
            if effect.normalization_confidence != NormalizationConfidence.EXACT:
                needs_authorization = True
                authorization_reasons.append("normalization_not_exact")
            expected_refs = {key: fingerprint(labels[key]) for key in node.source_ids}
            actual_refs = {ref.ref: fingerprint(ref.label) for ref in effect.data_refs}
            if (
                actual_refs != expected_refs
                or len(effect.data_refs) != len(expected_refs)
                or effect.derived_from != node.source_ids
            ):
                reasons.append("normalized_data_provenance_mismatch")
            decision = engine.evaluate(effect, contract=compiled.contract, now=now)
            effects.append(effect)
            explanations.append(
                Explanation(
                    task_id=plan.task_id,
                    node_id=node_id,
                    effect_id=effect.effect_id,
                    source_ids=node.source_ids,
                    decision=decision,
                )
            )
            if decision.decision.value == "DENY":
                reasons.append("policy_denied:" + effect.effect_id)
                reasons.extend(decision.hard_reasons)
            elif decision.decision.value == "CONFIRM":
                needs_authorization = True
                authorization_reasons.extend(decision.confirm_reasons)
    status = "DENIED" if reasons else ("REQUIRES_AUTHORIZATION" if needs_authorization else "READY")
    return PlanValidation(
        status=status,
        contract_fingerprint=compiled.fingerprint,
        candidate_fingerprint=fingerprint(plan),
        ordered_nodes=order,
        edges=edges,
        effects=tuple(effects),
        explanations=tuple(explanations),
        executable_node_ids=order if status == "READY" else (),
        reasons=tuple(dict.fromkeys([*reasons, *authorization_reasons])),
        normalization_backends=tuple(sorted({item.backend for item in normalized})),
    )


def fill_data_slot(plan: CandidatePlan, *, node_id: str, slot_name: str, binding: Binding) -> CandidatePlan:
    """Only fill an existing empty data slot; callers must obtain fresh adapter results and revalidate."""
    nodes = []
    found = False
    for node in plan.nodes:
        if node.node_id != node_id:
            nodes.append(node)
            continue
        slots = []
        for slot in node.data_slots:
            if slot.name == slot_name:
                if slot.binding is not None:
                    raise PlanError("data_slot_already_filled")
                slots.append(slot.model_copy(update={"binding": binding}))
                found = True
            else:
                slots.append(slot)
        nodes.append(node.model_copy(update={"data_slots": tuple(slots)}))
    if not found:
        raise PlanError("unknown_data_slot_or_node")
    return plan.model_copy(update={"nodes": tuple(nodes)})


def check_child(compiled: CompiledTask, child: IntentContract, *, depth: int) -> tuple[str, ...]:
    """Reuse A's actual validator; both current templates prohibit delegation."""
    return tuple(validate_child_contract(compiled.contract, child, depth))
