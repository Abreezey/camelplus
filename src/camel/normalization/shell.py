"""Bash AST reduction; never executes shell input (arch.md §6.4).

The accepted grammar is deliberately small. Unsupported AST nodes, expansion,
unknown commands and decoded/interpreter streams retain discovered effects but
also produce a FAILED EXEC effect. Regex is never used to parse shell syntax.
"""

from typing import Any

import bashlex
from bashlex.errors import ParsingError

from camel.core.effect import CanonicalEffect, DataReference, EffectType
from camel.normalization.fs import normalize_fs
from camel.normalization.git import normalize_git
from camel.normalization.ingress import structural_text
from camel.normalization.models import (
    NormalizationContext,
    NormalizationError,
    NormalizationResult,
    digest,
    failed,
    make_effect,
)
from camel.normalization.net import NetworkPolicy, Resolver, normalize_net, resolve_dns


class ShellNormalizer:
    def __init__(
        self,
        network: NetworkPolicy | None = None,
        resolver: Resolver = resolve_dns,
        remote_urls: dict[str, str] | None = None,
        max_nodes: int = 1024,
        max_depth: int = 8,
    ) -> None:
        self._network = network or NetworkPolicy()
        self._resolver = resolver
        self._remotes = dict(remote_urls or {})
        self._max_nodes = max_nodes
        self._max_depth = max_depth

    def normalize(self, script: str, context: NormalizationContext, *, depth: int = 0) -> NormalizationResult:
        effects: list[CanonicalEffect] = []
        failures: list[str] = []
        try:
            structural_text(script)
            if not script.strip():
                raise NormalizationError("empty_shell_program")
            if len(script) > 65536 or depth >= self._max_depth:
                raise NormalizationError("shell_parse_budget_exceeded")
            try:
                nodes = bashlex.parse(script)
            except AttributeError as err:
                # bashlex 0.18 raises AttributeError for comment-only programs.
                raise NormalizationError("shell_parse_failed") from err
            visited = 0

            def walk(node: Any) -> None:
                nonlocal visited
                visited += 1
                if visited > self._max_nodes:
                    raise NormalizationError("shell_ast_budget_exceeded")
                kind = node.kind
                if kind in {"list", "pipeline"}:
                    for part in node.parts:
                        walk(part)
                    return
                if kind == "operator":
                    if node.op not in {";", "&&", "||", "\n"}:
                        raise NormalizationError("unsupported_shell_operator")
                    return
                if kind == "pipe":
                    if node.pipe != "|":
                        raise NormalizationError("unsupported_shell_pipe")
                    return
                if kind != "command":
                    raise NormalizationError("unsupported_shell_ast")
                words = []
                dynamic = False
                for part in node.parts:
                    if part.kind == "redirect":
                        if part.heredoc is not None or not hasattr(part.output, "word") or part.output.parts:
                            raise NormalizationError("dynamic_shell_redirect")
                        operation = {"<": "read", ">": "write", ">>": "append"}.get(part.type)
                        if operation is None:
                            raise NormalizationError("unsupported_shell_redirect")
                        effects.extend(normalize_fs(operation, (part.output.word,), context).effects)
                    elif part.kind == "word":
                        for expansion in part.parts:
                            if expansion.kind in {"commandsubstitution", "processsubstitution"}:
                                walk(expansion.command)
                            dynamic = True
                        if any(c in part.word for c in "*?[]{}~"):
                            dynamic = True
                        words.append(part.word)
                    else:
                        raise NormalizationError("shell_assignment_or_unsupported_part")
                if dynamic:
                    raise NormalizationError("dynamic_shell_word")
                if words:
                    effects.extend(self._command(tuple(words), context, depth))

            for node in nodes:
                walk(node)
            if not effects:
                raise NormalizationError("empty_shell_program")
        except (NormalizationError, ParsingError, NotImplementedError, RecursionError) as err:
            failure = failed(context, str(err) if isinstance(err, NormalizationError) else "shell_parse_failed")
            effects.extend(failure.effects)
            failures.extend(failure.failures)
        # Conservative flow across pipelines, redirections and command lists.
        # Unknown file contents cannot become public merely because curl is a
        # separate AST command. More precise per-pipe flows may narrow this later.
        references = tuple(dict.fromkeys(ref.model_dump_json() for e in effects for ref in e.data_refs))
        all_refs = tuple(DataReference.model_validate_json(ref) for ref in references)
        return NormalizationResult(
            effects=tuple(e.model_copy(update={"data_refs": all_refs}) for e in effects), failures=tuple(failures)
        )

    def _command(self, argv: tuple[str, ...], context: NormalizationContext, depth: int) -> list[CanonicalEffect]:
        command, *args = argv
        if "/" in command:
            raise NormalizationError("shell_executable_path_not_pinned")
        effects = [make_effect(context, EffectType.EXEC, "shell_command:" + digest(argv))]
        if command in {"sh", "bash", "dash"}:
            if len(args) != 2 or args[0] != "-c":
                raise NormalizationError("shell_stream_or_script_execution")
            nested = self.normalize(args[1], context, depth=depth + 1)
            if nested.blocked:
                raise NormalizationError("nested_shell_not_exact")
            effects.extend(nested.effects)
        elif command == "git":
            if (
                len(args) > 1
                and args[0] in {"push", "fetch", "pull"}
                and not args[1].startswith(("https://", "http://"))
            ):
                raise NormalizationError("git_remote_alias_in_shell")
            effects.extend(
                normalize_git(
                    tuple(args), context, remote_urls=self._remotes, network=self._network, resolver=self._resolver
                ).effects
            )
        elif command in {"cat", "head", "tail", "wc", "ls", "stat"}:
            if any(a.startswith("-") for a in args):
                raise NormalizationError("unsupported_read_command_option")
            if args:
                effects.extend(normalize_fs("read", tuple(args), context).effects)
            elif command == "ls":
                effects.extend(normalize_fs("list", (str(context.cwd),), context).effects)
        elif command in {"tee", "touch", "mkdir", "rm"}:
            if not args or any(a.startswith("-") for a in args):
                raise NormalizationError("unsupported_write_command_option")
            op = {"tee": "write", "touch": "touch", "mkdir": "mkdir", "rm": "delete"}[command]
            effects.extend(normalize_fs(op, tuple(args), context).effects)
        elif command == "curl":
            method, url, read_paths = self._curl(args)
            effects.extend(normalize_net(method, url, context, self._network, self._resolver).effects)
            for path in read_paths:
                effects.extend(normalize_fs("read", (path,), context).effects)
        elif command == "base64":
            if args and args[0] in {"-d", "--decode"}:
                raise NormalizationError("encoded_shell_stream")
            if len(args) > 1 or any(a.startswith("-") for a in args):
                raise NormalizationError("unsupported_base64_option")
            if args:
                effects.extend(normalize_fs("read", tuple(args), context).effects)
        elif command in {"echo", "printf", "true", "false", "pwd"}:
            # printf -v writes shell variables; file/network effects remain unsupported.
            if command == "printf" and args and args[0].startswith("-"):
                raise NormalizationError("unsupported_printf_option")
        else:
            raise NormalizationError("unknown_shell_command")
        return effects

    def _curl(self, args: list[str]) -> tuple[str, str, list[str]]:
        urls: list[str] = []
        paths: list[str] = []
        method = "GET"
        index = 0
        while index < len(args):
            arg = args[index]
            if arg in {"-s", "--silent", "-S", "--show-error", "-f", "--fail"}:
                index += 1
                continue
            if arg in {"-X", "--request", "-d", "--data", "--data-binary", "-T", "--upload-file"}:
                index += 1
                if index >= len(args):
                    raise NormalizationError("missing_curl_option_value")
                value = args[index]
                if arg in {"-X", "--request"}:
                    method = value
                elif arg in {"-T", "--upload-file"}:
                    method = "PUT"
                    paths.append(value)
                else:
                    method = "POST"
                    if value.startswith("@"):
                        paths.append(value[1:])
            elif arg.startswith("-"):
                # Includes redirects, output files, proxy/config and alternate protocols.
                raise NormalizationError("unsupported_curl_option")
            else:
                urls.append(arg)
            index += 1
        if len(urls) != 1:
            raise NormalizationError("curl_requires_one_url")
        return method, urls[0], paths
