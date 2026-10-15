"""Compile exact read-only scopes from trusted task parameters and organization limits."""

import hashlib
import json
from datetime import datetime, timedelta

from pydantic import BaseModel

from camel.core import AllowedEffect, DelegationSpec, EffectType, IntentContract
from camel.planner.models import Compilation, CompiledTask, Organization, TrustedTask


def fingerprint(value) -> str:
    def encode(item):
        if isinstance(item, BaseModel):
            return item.model_dump(mode="python")
        if isinstance(item, set | frozenset):
            return sorted(item)
        if isinstance(item, datetime):
            return item.isoformat()
        raise TypeError("unsupported fingerprint value")

    return hashlib.sha256(json.dumps(value, default=encode, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def require_clock(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("explicit timezone-aware clock required")


def compile_task(task: TrustedTask, organization: Organization, *, now: datetime) -> Compilation:
    """No external-text or candidate-plan parameter exists on this authorization API."""
    require_clock(now)
    kinds = {"read_document": "document", "review_code": "code"}
    if task.template not in kinds:
        return Compilation(status="UNSUPPORTED", reasons=("unsupported_task_template",), compiled=None)
    if not task.resource_ids:
        return Compilation(status="REQUIRES_AUTHORIZATION", reasons=("explicit_resources_required",), compiled=None)
    if len(task.resource_ids) > organization.max_resources or len(set(task.resource_ids)) != len(task.resource_ids):
        return Compilation(status="DENIED", reasons=("invalid_resource_budget_or_duplicates",), compiled=None)
    catalog = {item.resource_id: item for item in organization.resources}
    if len(catalog) != len(organization.resources):
        raise ValueError("duplicate organization resource IDs")
    if any(resource not in catalog or catalog[resource].kind != kinds[task.template] for resource in task.resource_ids):
        return Compilation(
            status="REQUIRES_AUTHORIZATION", reasons=("resource_not_in_approved_template_catalog",), compiled=None
        )
    if task.expires_at <= now:
        return Compilation(status="DENIED", reasons=("task_expired",), compiled=None)
    expiry = min(task.expires_at, now + timedelta(seconds=organization.max_ttl_seconds))
    identity = fingerprint({"task": task, "organization": organization, "expiry": expiry})
    contract = IntentContract(
        contract_id="d2-" + identity[:24],
        principal=task.principal,
        goal=task.template,
        allowed_effects=tuple(
            AllowedEffect(effect=EffectType.READ, operation="read_file", resource=resource)
            for resource in task.resource_ids
        ),
        forbidden_data_classes=organization.forbidden_data_classes,
        allowed_destinations=(),
        side_effect_budget=0,
        delegation=DelegationSpec(allowed=False, max_depth=0),
        expires_at=expiry,
    )
    compiled = CompiledTask(
        issued_at=now, task=task, organization=organization, contract=contract, fingerprint=fingerprint(contract)
    )
    return Compilation(status="READY", reasons=(), compiled=compiled)
