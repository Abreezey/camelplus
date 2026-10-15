"""Filesystem effects: absolute paths, realpath and workspace containment.

The broker must bind the checked path to its actual open handle (arch.md §6.4).
This adapter does not claim to eliminate a concurrent filesystem TOCTOU race.
"""

from pathlib import Path
from urllib.parse import unquote, urlsplit

from camel.core.effect import DataReference, EffectType
from camel.core.labels import Confidentiality, TrustLabel
from camel.normalization.ingress import structural_text
from camel.normalization.models import NormalizationContext, NormalizationError, NormalizationResult, make_effect


def resolve_path(resource: str, context: NormalizationContext) -> Path:
    structural_text(resource)
    if not resource or any(c in resource for c in "\x00\r\n"):
        raise NormalizationError("invalid_path")
    if resource.startswith("file:"):
        uri = urlsplit(resource)
        if uri.scheme != "file" or uri.netloc or uri.query or uri.fragment:
            raise NormalizationError("invalid_file_uri")
        resource = unquote(uri.path, errors="strict")
        structural_text(resource)
        if any(c in resource for c in "\x00\r\n"):
            raise NormalizationError("invalid_path")
    elif "://" in resource:
        raise NormalizationError("non_file_resource")
    root = context.workspace.resolve(strict=True)
    cwd = context.cwd.resolve(strict=True)
    if not cwd.is_relative_to(root):
        raise NormalizationError("cwd_outside_workspace")
    path = Path(resource)
    if not path.is_absolute():
        path = cwd / path
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError, ValueError) as err:
        raise NormalizationError("path_resolution_failed") from err
    if not resolved.is_relative_to(root):
        raise NormalizationError("path_outside_workspace")
    return resolved


def normalize_fs(operation: str, paths: tuple[str, ...], context: NormalizationContext) -> NormalizationResult:
    types = {
        "read": EffectType.READ,
        "list": EffectType.READ,
        "stat": EffectType.READ,
        "write": EffectType.WRITE,
        "append": EffectType.WRITE,
        "delete": EffectType.WRITE,
        "mkdir": EffectType.WRITE,
        "touch": EffectType.WRITE,
    }
    if operation not in types or not paths:
        raise NormalizationError("unsupported_filesystem_operation")
    effects = []
    for path in paths:
        resolved = str(resolve_path(path, context))
        references = context.data_refs
        if types[operation] is EffectType.READ:
            label = context.resource_labels.get(resolved, TrustLabel(confidentiality=Confidentiality.SECRET))
            references = (*references, DataReference(ref="file://" + resolved, label=label))
        effects.append(
            make_effect(context, types[operation], f"file_{operation}", resources=(resolved,), data_refs=references)
        )
    return NormalizationResult(effects=tuple(effects))
