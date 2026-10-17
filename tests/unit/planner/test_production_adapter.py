"""D production adapter: real B normalization projected into the frozen TDG shape."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from camel.core import TrustLabel
from camel.planner.compiler import compile_task
from camel.planner.fixture_adapter import TOOLS, normalize_fixture
from camel.planner.models import (
    Binding,
    CandidatePlan,
    DataField,
    DataSlot,
    Organization,
    Resource,
    Source,
    ToolNode,
    TrustedTask,
)
from camel.planner.production_adapter import PRODUCTION_TOOLS, normalize_production
from camel.planner.validation import PlanError, validate_plan
from camel.policy import PolicyEngine, load_rules

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


def environment(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    document = workspace / "README.md"
    document.write_text("Project documentation describes the public module layout.", encoding="utf-8")
    organization = Organization(
        policy_id="prod-org-v1",
        resources=(Resource(resource_id=str(document), kind="document"),),
        forbidden_data_classes=frozenset({"credentials"}),
        max_ttl_seconds=600,
    )
    request = TrustedTask(
        task_id="task-prod",
        principal="user:prod",
        template="read_document",
        resource_ids=(str(document),),
        expires_at=NOW + timedelta(hours=1),
    )
    compiled = compile_task(request, organization, now=NOW).compiled
    assert compiled is not None
    source = Source(
        source_id="synthetic-source",
        label=TrustLabel(provenance=frozenset({"synthetic-source"})),
        fields=(DataField(name="focus", value="文档介绍项目结构。"),),
    )
    node = ToolNode(
        node_id="read",
        tool_id=PRODUCTION_TOOLS[0].tool_id,
        tool_version=PRODUCTION_TOOLS[0].version,
        resource_id=str(document),
        effect_refs=("effect-read",),
        source_ids=(source.source_id,),
        depends_on=(),
        data_slots=(DataSlot(name="focus", binding=Binding(source_id=source.source_id, field="focus")),),
    )
    plan = CandidatePlan(task_id=request.task_id, nodes=(node,))
    engine = PolicyEngine(
        load_rules(f"""id: allow-workspace-read
when:
  effect.type: READ
  effect.operation: read_file
  effect.resource_matches: {workspace}/**
then: ALLOW
""")
    )
    return compiled, plan, (source,), engine, workspace, document


def test_production_bundle_passes_validate_plan(tmp_path: Path) -> None:
    compiled, plan, sources, engine, workspace, _ = environment(tmp_path)
    bundles = normalize_production(compiled, plan, sources, workspace=workspace)
    assert len(bundles) == 1
    bundle = bundles[0]
    assert bundle.backend == "production_adapter"
    assert bundle.tool_version == PRODUCTION_TOOLS[0].version
    validated = validate_plan(
        compiled, plan, sources=sources, tools=PRODUCTION_TOOLS, normalized=bundles, engine=engine, now=NOW
    )
    assert validated.status == "READY"
    assert validated.normalization_backends == ("production_adapter",)
    effect = validated.effects[0]
    assert effect.operation == "read_file"
    assert effect.resources == (str(tmp_path / "workspace" / "README.md"),)


def test_outside_workspace_fails_closed(tmp_path: Path) -> None:
    compiled, plan, sources, engine, workspace, document = environment(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    plan = plan.model_copy(update={"nodes": (plan.nodes[0].model_copy(update={"resource_id": str(outside)}),)})
    with pytest.raises(PlanError, match="production_"):
        normalize_production(compiled, plan, sources, workspace=workspace)


def test_symlinked_resource_fails_closed(tmp_path: Path) -> None:
    compiled, plan, sources, engine, workspace, document = environment(tmp_path)
    link = workspace / "alias.md"
    link.symlink_to(document)
    plan = plan.model_copy(update={"nodes": (plan.nodes[0].model_copy(update={"resource_id": str(link)}),)})
    with pytest.raises(PlanError, match="production_resource_not_canonical"):
        normalize_production(compiled, plan, sources, workspace=workspace)


def test_tool_version_mismatch_fails_closed(tmp_path: Path) -> None:
    compiled, plan, sources, engine, workspace, document = environment(tmp_path)
    plan = plan.model_copy(update={"nodes": (plan.nodes[0].model_copy(update={"tool_version": "fixture-v1"}),)})
    with pytest.raises(PlanError, match="tool_manifest_changed"):
        normalize_production(compiled, plan, sources, workspace=workspace)


def test_fixture_path_still_ready(tmp_path: Path) -> None:
    """The offline fixture path (logical URIs) remains reproducible."""
    organization = Organization(
        policy_id="d2-org-v1",
        resources=(Resource(resource_id="file:///workspace/README.md", kind="document"),),
        forbidden_data_classes=frozenset(),
        max_ttl_seconds=600,
    )
    request = TrustedTask(
        task_id="task-fixture",
        principal="user:synthetic",
        template="read_document",
        resource_ids=("file:///workspace/README.md",),
        expires_at=NOW + timedelta(hours=1),
    )
    compiled = compile_task(request, organization, now=NOW).compiled
    assert compiled is not None
    source = Source(
        source_id="synthetic-source",
        label=TrustLabel(provenance=frozenset({"synthetic-source"})),
        fields=(DataField(name="focus", value="文档介绍项目结构。"),),
    )
    node = ToolNode(
        node_id="read",
        tool_id=TOOLS[0].tool_id,
        tool_version="fixture-v1",
        resource_id="file:///workspace/README.md",
        effect_refs=("effect-read",),
        source_ids=(source.source_id,),
        depends_on=(),
        data_slots=(DataSlot(name="focus", binding=Binding(source_id=source.source_id, field="focus")),),
    )
    plan = CandidatePlan(task_id=request.task_id, nodes=(node,))
    engine = PolicyEngine(
        load_rules("""id: allow-registered-read
when:
  effect.type: READ
  effect.operation: read_file
  effect.resource_matches: file:///workspace/**
then: ALLOW
""")
    )
    validated = validate_plan(
        compiled,
        plan,
        sources=(source,),
        tools=TOOLS,
        normalized=normalize_fixture(compiled, plan, (source,)),
        engine=engine,
        now=NOW,
    )
    assert validated.status == "READY"
