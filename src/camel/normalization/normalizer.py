"""Dispatch deployment-owned tool bindings to fail-closed effect adapters."""

from typing import Any

from camel.core.effect import CanonicalEffect, DataReference, EffectType
from camel.core.labels import Confidentiality, TrustLabel
from camel.normalization.fs import normalize_fs, resolve_path
from camel.normalization.git import normalize_git
from camel.normalization.models import (
    NormalizationContext,
    NormalizationError,
    NormalizationResult,
    ToolBinding,
    failed,
    make_effect,
)
from camel.normalization.net import NetworkPolicy, Resolver, normalize_net, resolve_dns
from camel.normalization.shell import ShellNormalizer


class EffectNormalizer:
    def __init__(
        self,
        network: NetworkPolicy | None = None,
        *,
        resolver: Resolver = resolve_dns,
        remote_urls: dict[str, str] | None = None,
    ) -> None:
        self.network = network or NetworkPolicy()
        self._resolver = resolver
        self._remotes = dict(remote_urls or {})
        self._shell = ShellNormalizer(self.network, resolver, self._remotes)

    def normalize(
        self,
        binding: ToolBinding,
        arguments: dict[str, Any],
        context: NormalizationContext,
    ) -> NormalizationResult:
        try:
            args = binding.arguments(arguments)
            if "cwd" in args:
                context = context.model_copy(update={"cwd": resolve_path(self._string(args, "cwd"), context)})
                args["cwd"] = str(context.cwd)
            if binding.adapter == "fs":
                if set(args) - {"path", "paths", "content", "cwd"} or ("path" in args and "paths" in args):
                    raise NormalizationError("ambiguous_filesystem_arguments")
                path = args.get("path")
                paths = (path,) if isinstance(path, str) else args.get("paths")
                if not isinstance(paths, tuple | list) or not all(isinstance(p, str) for p in paths):
                    raise NormalizationError("filesystem_paths_required")
                result = normalize_fs(binding.operation, tuple(paths), context)
                if "path" in args:
                    args["path"] = result.effects[0].resources[0]
                else:
                    args["paths"] = [e.resources[0] for e in result.effects]
                return self._prepared(binding, args, result)
            if binding.adapter == "shell":
                if set(args) - {"command", "cwd"}:
                    raise NormalizationError("unsupported_shell_arguments")
                return self._prepared(binding, args, self._shell.normalize(self._string(args, "command"), context))
            if binding.adapter == "net":
                if set(args) - {"url", "body", "headers"}:
                    raise NormalizationError("unsupported_network_arguments")
                result = normalize_net(
                    binding.operation or "GET", self._string(args, "url"), context, self.network, self._resolver
                )
                args["url"] = result.effects[0].destination
                return self._prepared(binding, args, result)
            if binding.adapter == "git":
                if set(args) - {"argv", "cwd"}:
                    raise NormalizationError("unsupported_git_arguments")
                argv = args.get("argv")
                if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
                    raise NormalizationError("git_argv_required")
                result = normalize_git(
                    tuple(argv), context, remote_urls=self._remotes, network=self.network, resolver=self._resolver
                )
                if result.effects[0].destination is not None:
                    args["argv"] = [argv[0], result.effects[0].destination, *argv[2:]]
                return self._prepared(binding, args, result)
            if binding.adapter == "mcp" and binding.effects:
                effects: list[CanonicalEffect] = []
                for spec in binding.effects:
                    destinations = self._string(args, spec.destination_field) if spec.destination_field else None
                    resources = tuple(
                        str(resolve_path(self._string(args, key), context)) for key in spec.resource_fields
                    )
                    for key, resource in zip(spec.resource_fields, resources):
                        args[key] = resource
                    for resource in resources or (None,):
                        references = context.data_refs
                        if resource and spec.type in {EffectType.READ, EffectType.EGRESS}:
                            references = (
                                *references,
                                DataReference(
                                    ref="file://" + resource,
                                    label=context.resource_labels.get(
                                        resource, TrustLabel(confidentiality=Confidentiality.SECRET)
                                    ),
                                ),
                            )
                        effects.append(
                            make_effect(
                                context,
                                spec.type,
                                spec.operation,
                                resources=(resource,) if resource else (),
                                destination=destinations,
                                required_capabilities=spec.required_capabilities,
                                data_refs=references,
                            )
                        )
                # One RPC has no declared internal dataflow. Every output may
                # depend on every file input, regardless of effect ordering.
                inputs = tuple(ref for effect in effects if effect.type is EffectType.READ for ref in effect.data_refs)
                effects = [
                    effect.model_copy(
                        update={
                            "data_refs": tuple(
                                {ref.model_dump_json(): ref for ref in (*effect.data_refs, *inputs)}.values()
                            )
                        }
                    )
                    for effect in effects
                ]
                return self._prepared(binding, args, NormalizationResult(effects=tuple(effects)))
            raise NormalizationError("unknown_or_unmapped_tool")
        except (ValueError, OSError, RuntimeError) as err:
            return failed(context, str(err) if isinstance(err, NormalizationError) else "normalization_error")

    @staticmethod
    def _prepared(binding: ToolBinding, args: dict[str, Any], result: NormalizationResult) -> NormalizationResult:
        reverse = {v: k for k, v in binding.argument_map.items()}
        forwarded = {reverse.get(k, k): v for k, v in args.items()}
        return result.model_copy(update={"arguments": forwarded})

    @staticmethod
    def _string(arguments: dict[str, Any], key: str) -> str:
        value = arguments.get(key)
        if not isinstance(value, str) or not value:
            raise NormalizationError("string_argument_required:" + key)
        return value
