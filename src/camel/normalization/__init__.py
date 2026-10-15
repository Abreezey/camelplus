"""Ingress and effect normalization (module B, arch.md §6.1/§6.4)."""

from camel.normalization.fs import normalize_fs, resolve_path
from camel.normalization.git import normalize_git
from camel.normalization.ingress import IngressNormalizer, TextView
from camel.normalization.models import (
    EffectSpec,
    NormalizationContext,
    NormalizationError,
    NormalizationResult,
    ToolBinding,
)
from camel.normalization.net import NetworkPolicy, NetworkTarget, normalize_net
from camel.normalization.normalizer import EffectNormalizer
from camel.normalization.shell import ShellNormalizer

__all__ = [
    "EffectNormalizer",
    "EffectSpec",
    "IngressNormalizer",
    "NetworkPolicy",
    "NetworkTarget",
    "NormalizationContext",
    "NormalizationError",
    "NormalizationResult",
    "ShellNormalizer",
    "TextView",
    "ToolBinding",
    "normalize_fs",
    "normalize_git",
    "normalize_net",
    "resolve_path",
]
