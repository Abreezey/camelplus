"""Git effects distinguish inspection, working-tree changes and remote publication.

Global configuration overrides, external diff helpers and ambiguous subcommands
are rejected. Remote aliases come from deployment-owned configuration rather
than executing Git or trusting repository-controlled include directives.
"""

from camel.core.effect import DataReference, EffectType
from camel.core.labels import Confidentiality, Integrity, TrustLabel
from camel.normalization.fs import resolve_path
from camel.normalization.ingress import structural_text
from camel.normalization.models import (
    NormalizationContext,
    NormalizationError,
    NormalizationResult,
    digest,
    make_effect,
)
from camel.normalization.net import NetworkPolicy, Resolver, resolve_dns

_READ = {"status", "diff", "log", "show", "ls-files", "rev-parse", "ls-tree"}
_WORKTREE = {"add", "restore", "checkout", "switch", "reset", "clean", "rm", "mv", "merge", "rebase", "cherry-pick"}
_READ_FLAGS = {
    "--short",
    "--porcelain",
    "--porcelain=v1",
    "--porcelain=v2",
    "--branch",
    "--oneline",
    "--stat",
    "--name-only",
    "--name-status",
    "--cached",
    "--staged",
    "--no-ext-diff",
    "--no-textconv",
    "--",
}


def normalize_git(
    argv: tuple[str, ...],
    context: NormalizationContext,
    *,
    remote_urls: dict[str, str] | None = None,
    network: NetworkPolicy | None = None,
    resolver: Resolver = resolve_dns,
) -> NormalizationResult:
    if not argv or argv[0].startswith("-"):
        raise NormalizationError("git_global_options_or_missing_command")
    for arg in argv:
        structural_text(arg)
        if "\x00" in arg or any(
            arg == flag or arg.startswith(flag + "=")
            for flag in (
                "--ext-diff",
                "--textconv",
                "--output",
                "--exec",
                "--config-env",
                "--upload-pack",
                "--receive-pack",
            )
        ):
            raise NormalizationError("git_external_effect_option")
    command, *args = argv
    repo = str(resolve_path(str(context.cwd), context))
    if command in _READ:
        for arg in args:
            if arg.startswith("-") and arg not in _READ_FLAGS:
                raise NormalizationError("unsupported_git_read_option")
            if not arg.startswith("-"):
                resolve_path(arg, context)
    if command in {"push", "fetch", "pull"} and any(arg.startswith("-") for arg in args[1:]):
        raise NormalizationError("git_remote_override_option")
    if command in _WORKTREE or command == "branch":
        if any(arg.startswith("-") and not (command == "branch" and args == ["--list"]) for arg in args):
            raise NormalizationError("unsupported_git_mutation_option")
        if command in {"add", "restore", "rm", "mv"}:
            for arg in args:
                resolve_path(arg, context)
    if command == "commit" and not (len(args) == 2 and args[0] == "-m"):
        raise NormalizationError("git_commit_requires_literal_message")
    if command == "tag" and (not args or any(arg.startswith("-") for arg in args)):
        raise NormalizationError("unsupported_git_tag_option")
    context = context.model_copy(
        update={
            "data_refs": (
                *context.data_refs,
                DataReference(ref="git-argv:" + digest(argv), label=TrustLabel(integrity=Integrity.TRUSTED_SYSTEM)),
                DataReference(
                    ref="file://" + repo,
                    label=context.resource_labels.get(repo, TrustLabel(confidentiality=Confidentiality.SECRET)),
                ),
            )
        }
    )
    destination = None
    if command in _READ or (command == "branch" and (not args or args == ["--list"])):
        kind, operation = EffectType.READ, f"git_{command}"
    elif command in _WORKTREE or command == "branch":
        kind, operation = EffectType.REPO_MUTATE, "working_tree"
    elif command in {"commit", "tag"}:
        # Hooks and signing programs are runtime effects and require C's sandbox.
        kind, operation = EffectType.REPO_MUTATE, command
    elif command == "remote":
        if not args or args[0] in {"-v", "show", "get-url"}:
            # `remote show` contacts a remote unless -n is present.
            if args and args[0] == "show" and "-n" not in args:
                raise NormalizationError("git_remote_show_requires_network")
            kind, operation = EffectType.READ, "git_remote"
        elif args[0] in {"add", "remove", "rename", "set-url", "set-head", "set-branches", "prune", "update"}:
            if any(arg.startswith("-") for arg in args[1:]):
                raise NormalizationError("git_remote_change_option")
            if args[0] in {"prune", "update"}:
                raise NormalizationError("git_implicit_network_operation")
            kind, operation = EffectType.REPO_MUTATE, "remote_change"
        else:
            raise NormalizationError("unsupported_git_remote_operation")
    elif command in {"push", "fetch", "pull"}:
        if not args or args[0].startswith("-") or network is None:
            raise NormalizationError("git_requires_explicit_remote")
        remote = (remote_urls or {}).get(args[0], args[0])
        destination = network.target(remote, resolver).url
        kind, operation = EffectType.REPO_MUTATE, command
    else:
        raise NormalizationError("unsupported_git_command")
    effects = [make_effect(context, kind, operation, resources=(repo,), destination=destination)]
    if destination is not None:
        effects.append(make_effect(context, EffectType.EGRESS, f"git_{command}", destination=destination))
    return NormalizationResult(effects=tuple(effects))
