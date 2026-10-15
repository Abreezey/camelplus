"""Record offline D0 diagnostics using an existing Python; never install dependencies."""

import argparse
import ast
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # pytest's locked Python 3.10 dependency

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts" / "d"):
        parser.error("output must be within this repository's artifacts/d directory")
    output.mkdir(parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["UV_OFFLINE"] = "1"
    environment["PYRIGHT_PYTHON_FORCE_VERSION"] = "1.1.401"
    environment["PYRIGHT_PYTHON_USE_BUNDLED_PYRIGHT"] = "1"
    environment["PYRIGHT_PYTHON_GLOBAL_NODE"] = "1"
    records = []

    def run(name: str, command: list[str], timeout: int = 60):
        started = datetime.now(timezone.utc).isoformat()
        tick = time.perf_counter()
        try:
            result = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
            text, code = result.stdout, result.returncode
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout or b""
            text = partial.decode("utf-8", errors="replace") if isinstance(partial, bytes) else partial
            text += f"\nD0 per-check {timeout}-second timeout exceeded"
            code = 124
        (output / f"{name}.txt").write_text(text, encoding="utf-8")
        records.append(
            {
                "name": name,
                "command": command,
                "started_utc": started,
                "finished_utc": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": time.perf_counter() - tick,
                "exit_code": code,
                "log": f"{name}.txt",
            }
        )
        print(f"{name}: exit={code}", flush=True)
        return text, code

    bundle_manifest = ROOT / "source_manifest.json"
    if (ROOT / ".git").exists():
        run("git_commit", ["git", "rev-parse", "HEAD"])
        run("git_branch", ["git", "branch", "--show-current"])
        run("git_status", ["git", "status", "--short"])
        run("git_tracked_diff", ["git", "diff", "HEAD", "--no-ext-diff"])
        source_revision = {"kind": "git_checkout", "git_checks_run": True}
    elif bundle_manifest.is_file():
        source_revision = {
            "kind": "source_bundle",
            "git_checks_run": False,
            "manifest": json.loads(bundle_manifest.read_text(encoding="utf-8")),
        }
        (output / "source_manifest.json").write_bytes(bundle_manifest.read_bytes())
        (output / "working_tree.patch").write_bytes((ROOT / "working_tree.patch").read_bytes())
    else:
        parser.error("source requires a Git checkout or an explicit source_manifest.json bundle")
    # Block socket operations in pytest itself; this is not an OS sandbox.
    pytest_launcher = (
        "import sys\n"
        "def offline_guard(event, args):\n"
        "    if event in ('socket.connect', 'socket.getaddrinfo', 'urllib.Request'):\n"
        "        raise RuntimeError('D0 tests prohibit network access')\n"
        "sys.addaudithook(offline_guard)\n"
        "import pytest\n"
        "raise SystemExit(pytest.main(sys.argv[1:]))\n"
    )
    for name, paths in (
        ("core_policy", ["tests/unit/core", "tests/unit/policy"]),
        ("full_suite", []),
    ):
        run(
            name,
            [
                sys.executable,
                "-c",
                pytest_launcher,
                "-q",
                *paths,
                "-o",
                "junit_family=xunit1",
                f"--junitxml={output / (name + '.xml')}",
                f"--basetemp={output / (name + '_tmp')}",
            ],
            timeout=120,
        )
    for name, arguments in (
        ("ruff_check", ["ruff", "check", "."]),
        ("ruff_format", ["ruff", "format", "--check", "."]),
        ("pyright", ["pyright"]),
    ):
        run(name, [sys.executable, "-m", *arguments], timeout=120)

    sys.path.insert(0, str(ROOT / "src"))
    from camel.core import CanonicalEffect, CanonicalEvent, Decision, IntentContract, RiskSignal, TrustLabel

    models = (TrustLabel, IntentContract, CanonicalEffect, Decision, CanonicalEvent, RiskSignal)
    schemas = {model.__name__: model.model_json_schema() for model in models}
    (output / "public_schemas.json").write_text(json.dumps(schemas, indent=2), encoding="utf-8")
    fields = {model.__name__: list(model.model_fields) for model in models}
    (output / "public_fields.json").write_text(json.dumps(fields, indent=2), encoding="utf-8")
    policy_text, policy_code = run(
        "policy_import",
        [
            sys.executable,
            "-c",
            "import json; from datetime import datetime, timezone; "
            "from camel.policy import PolicyEngine; "
            "from camel.core import CanonicalEffect, EffectType, IntentContract, RiskSignal; "
            "now = datetime(2026, 10, 15, tzinfo=timezone.utc); "
            "engine = PolicyEngine([]); "
            "effect = CanonicalEffect(effect_id='d0-effect', type=EffectType.READ, operation='read_file'); "
            "signal = RiskSignal(name='synthetic', confidence=0.9, detector_version='d0-v1'); "
            "expired = IntentContract(contract_id='d0-expired', principal='user:synthetic', "
            "goal='synthetic read', expires_at=now); "
            "print(json.dumps({'empty_policy_version': engine.policy_version, "
            "'no_allow_high_risk': engine.evaluate(effect, now=now, risk_signals=(signal,)).decision, "
            "'expired_contract': engine.evaluate(effect, now=now, contract=expired).decision}))",
        ],
    )
    run("d0_probes", [sys.executable, "-m", "unittest", "discover", "-s", "tests/unit/d0", "-v"])
    run(
        "platform_features",
        [sys.executable, "-c", "import os; print('O_NOFOLLOW:', hasattr(os, 'O_NOFOLLOW'))"],
    )

    syntax_errors = []
    files = list((ROOT / "src").rglob("*.py")) + list((ROOT / "tests").rglob("*.py"))
    files += list((ROOT / "scripts").glob("*.py")) + list(ROOT.glob("*.py"))
    for path in files:
        try:
            ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except SyntaxError as exc:
            syntax_errors.append({"path": str(path.relative_to(ROOT)), "error": str(exc)})

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    locked = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    requirements = declared["project"]["dependencies"] + declared["dependency-groups"]["dev"]
    versions = {}
    for requirement in [*requirements, "PyYAML", "uv", "typing-extensions"]:
        name = requirement.split(">=")[0]
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            installed = None
        versions[name] = {
            "installed": installed,
            "lock_versions": sorted({p["version"] for p in locked["package"] if p["name"] == name.lower()}),
        }
    installed = {
        dist.metadata["Name"].lower().replace("_", "-"): dist.version for dist in importlib.metadata.distributions()
    }
    lock_mismatches = {
        name: version
        for name, version in installed.items()
        if version not in {pkg["version"] for pkg in locked["package"] if pkg["name"] == name}
    }
    (output / "installed_packages.json").write_text(json.dumps(installed, indent=2), encoding="utf-8")
    test_counts = {}
    for name in ("core_policy", "full_suite"):
        xml_path = output / f"{name}.xml"
        if not xml_path.exists():
            test_counts[name] = {"status": "NO_JUNIT_REPORT"}
            continue
        counts: dict[str, dict[str, int]] = {
            "existing": dict.fromkeys(("passed", "failed", "errors", "skipped"), 0),
            "d0": dict.fromkeys(("passed", "failed", "errors", "skipped"), 0),
        }
        for case in ET.parse(xml_path).iter("testcase"):
            group = "d0" if "tests/unit/d0/" in case.get("file", "").replace("\\", "/") else "existing"
            outcome = "passed"
            for tag, state in (("failure", "failed"), ("error", "errors"), ("skipped", "skipped")):
                if case.find(tag) is not None:
                    outcome = state
                    break
            counts[group][outcome] += 1
        test_counts[name] = counts
    policy_info = json.loads(policy_text) if policy_code == 0 else None
    summary = {
        "stage": "D0",
        "run_id": output.name,
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "executable": sys.executable,
        "python_version": sys.version,
        "source_revision": source_revision,
        "platform": platform.platform(),
        "python_requested": (ROOT / ".python-version").read_text().strip(),
        "dependencies": versions,
        "installed_package_count": len(installed),
        "installed_versions_absent_from_lock": lock_mismatches,
        "test_counts": test_counts,
        "checks": records,
        "syntax": {"files": len(files), "errors": syntax_errors, "evidence_level": "E0"},
        "random_seed": None,
        "model": None,
        "samples": "synthetic D0 unit boundaries; no dataset split",
        "policy_probe": policy_info,
        "policy_version_reason": "Each policy unit test supplies its own rules; no deployment policy is selected",
        "platform_features": {"O_NOFOLLOW": hasattr(os, "O_NOFOLLOW")},
        "test_network_guard": "Python audit hook rejects socket connect, DNS and urllib requests in pytest",
        "python_utf8": True,
        "evidence_limits": "E0/E1 only; no model, external benchmark or OS-isolation certification",
    }
    for relative in ("scripts/d0_baseline.py", "tests/unit/d0/test_boundaries.py"):
        snapshot = output / "source" / f"{relative}.txt"
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes((ROOT / relative).read_bytes())
    (output / "run.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 1 if any(record["exit_code"] for record in records) or syntax_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
