"""Production adapter: D plan normalization through B's real EffectNormalizer.

Each node is normalized with the real fs read binding (path resolution,
workspace containment, symlink checks); the verified B effect is then
projected into D's frozen TDG effect shape required by ``validate_plan``
(``effect_id=node.effect_refs[0]``, operation ``read_file``, data_refs exactly
the source labels). Any deviation fails closed with :class:`PlanError`.
"""

from pathlib import Path

from camel.core import CanonicalEffect, DataReference, EffectType
from camel.core.effect import NormalizationConfidence
from camel.normalization import EffectNormalizer, NormalizationContext, ToolBinding
from camel.planner.models import CandidatePlan, CompiledTask, NormalizedCall, Source, ToolSpec
from camel.planner.validation import PlanError, context, request_fingerprint

FS_READ_BINDING = ToolBinding(adapter="fs", operation="read")

PRODUCTION_TOOLS = (
    ToolSpec(
        tool_id="read_repository_document",
        version="prod-fs-v1",
        template="read_document",
        data_slots=frozenset({"focus"}),
    ),
    ToolSpec(
        tool_id="inspect_repository_code", version="prod-fs-v1", template="review_code", data_slots=frozenset({"focus"})
    ),
)


def _verify_normalized(result, node) -> CanonicalEffect:
    """Fail closed unless B's real normalization yields exactly one exact READ."""
    if result.blocked:
        reason = ",".join(result.failures) or "normalization_failed"
        raise PlanError(f"production_normalization_failed:{reason}")
    if len(result.effects) != 1:
        raise PlanError("production_expected_single_read_effect")
    effect = result.effects[0]
    if effect.type is not EffectType.READ:
        raise PlanError("production_effect_not_read")
    if effect.normalization_confidence is not NormalizationConfidence.EXACT:
        raise PlanError("production_normalization_not_exact")
    if effect.resources != (node.resource_id,):
        raise PlanError("production_resource_not_canonical")
    return effect


def normalize_production(
    compiled: CompiledTask,
    plan: CandidatePlan,
    sources: tuple[Source, ...],
    *,
    workspace: Path,
    tools: tuple[ToolSpec, ...] = PRODUCTION_TOOLS,
    normalizer: EffectNormalizer | None = None,
) -> tuple[NormalizedCall, ...]:
    """Real-effect validation per node, projected into the frozen D effect shape."""
    normalizer = normalizer if normalizer is not None else EffectNormalizer()
    source_map, tool_map, labels, _, _ = context(compiled, plan, sources, tools)
    bundles: list[NormalizedCall] = []
    for node in plan.nodes:
        spec = tool_map[node.tool_id]
        data_refs = tuple(DataReference(ref=source, label=labels[source]) for source in node.source_ids)
        result = normalizer.normalize(
            FS_READ_BINDING,
            {"path": node.resource_id},
            NormalizationContext(
                workspace=workspace,
                cwd=workspace,
                parent_ids=node.source_ids,
                data_refs=data_refs,
            ),
        )
        effect = _verify_normalized(result, node)
        projected = effect.model_copy(
            update={
                "effect_id": node.effect_refs[0],
                "operation": "read_file",
                "data_refs": data_refs,
                "derived_from": node.source_ids,
            }
        )
        bundles.append(
            NormalizedCall(
                node_id=node.node_id,
                tool_id=node.tool_id,
                tool_version=spec.version,
                request_fingerprint=request_fingerprint(compiled, node, source_map, labels, spec),
                backend="production_adapter",
                effects=(projected,),
            )
        )
    return tuple(bundles)
