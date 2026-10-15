"""Read installed AgentDojo metadata and write a disabled smoke proposal; never run it."""

import argparse
import ast
import json
import sys
from pathlib import Path

from camel.adapters.agentdojo.catalog import build_draft, inspect_installed, oracle_direction_probe, sha256

ROOT = Path(__file__).resolve().parents[1]


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("requires a fresh output directory under artifacts/d")

    def guard(event, arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "urllib.Request", "subprocess.Popen"}:
            raise RuntimeError("AgentDojo preparation prohibits networking and child processes")

    sys.addaudithook(guard)
    output.mkdir(parents=True)
    source_paths = [
        Path(__file__),
        *sorted((ROOT / "src/camel/adapters").rglob("*.py")),
        ROOT / "main.py",
        ROOT / "uv.lock",
    ]
    sources = {path.relative_to(ROOT).as_posix(): sha256(path) for path in source_paths}
    write(output / "freeze.json", dict(source_sha256=sources))
    catalog = inspect_installed()
    project_tree = ast.parse((ROOT / "main.py").read_text(encoding="utf-8"))
    main_function = next(
        node for node in project_tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    catalog["project_main_parameters"] = [argument.arg for argument in main_function.args.args]
    catalog["project_main_get_suite_versions"] = sorted(
        {
            node.args[0].value
            for node in ast.walk(main_function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "get_suite"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        }
    )
    proposal = build_draft(catalog)
    probes = oracle_direction_probe()
    root = Path(catalog["package_root"])
    if any(sha256(root / path) != digest for path, digest in catalog["package_file_sha256"].items()):
        raise RuntimeError("installed_package_changed_during_catalog")
    if any(sha256(ROOT / path) != digest for path, digest in sources.items()):
        raise RuntimeError("adapter_source_changed_during_catalog")
    for name, value in [("catalog.json", catalog), ("smoke_draft.json", proposal), ("oracle_probe.json", probes)]:
        write(output / name, value)
    write(
        output / "summary.json",
        dict(
            status="PASS_PREPARATION_ONLY",
            full_D6_accepted=False,
            ready=False,
            package_version=catalog["package_version"],
            suite_counts={
                version: {
                    name: dict(user_tasks=len(suite["user_tasks"]), injection_tasks=len(suite["injection_tasks"]))
                    for name, suite in suites.items()
                }
                for version, suites in catalog["suites"].items()
            },
            benchmark_episodes=0,
            model_requests=0,
            downloads=0,
            environment_loads=0,
            evidence_sha256={
                name: sha256(output / name)
                for name in ("freeze.json", "catalog.json", "smoke_draft.json", "oracle_probe.json")
            },
        ),
    )
    print(f"PASS_PREPARATION_ONLY: AgentDojo {catalog['package_version']}; draft disabled; {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
