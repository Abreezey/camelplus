"""Snapshot current source, then reuse an existing D0 Linux runtime entirely offline."""

import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "camelplus-d5"
DEFAULT_BUNDLE = "artifacts/d/D5_linux_source_01.tar.gz"
DEFAULT_RECEIPT = "artifacts/d/D0_wsl_return_20261015T032226Z/receipt.json"
SUFFIXES = {".py", ".sh", ".yaml", ".yml", ".json", ".jsonl", ".txt", ".md", ".toml", ".lock"}
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def source_files(root: Path) -> list[Path]:
    files = [path for folder in ("src", "tests", "scripts") for path in (root / folder).rglob("*")]
    files += list(root.glob("*.py"))
    files += [
        root / name for name in ("pyproject.toml", "uv.lock", ".python-version", ".gitignore", "README.md", "LICENSE")
    ]
    selected = []
    for path in sorted(set(files)):
        if "__pycache__" in path.parts:
            continue
        if path.is_symlink():
            raise ValueError("source_symlink_refused")
        if path.is_file() and (path.suffix in SUFFIXES or path.name in {"LICENSE", ".gitignore", ".python-version"}):
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("source_outside_workspace")
            selected.append(path)
    return selected


def make_bundle(root: Path, target: Path) -> dict:
    root = root.resolve()
    target = target.resolve()
    if not target.is_relative_to(root / "artifacts/d"):
        raise ValueError("bundle_must_be_under_artifacts_d")
    if target.exists():
        raise FileExistsError(target)
    selected = source_files(root)
    bodies = {path.relative_to(root).as_posix(): path.read_bytes() for path in selected}
    if any(len(body) > MAX_FILE for body in bodies.values()) or sum(map(len, bodies.values())) > MAX_TOTAL:
        raise ValueError("source_budget_exceeded")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    patch = subprocess.check_output(["git", "diff", "HEAD", "--no-ext-diff", "--", *bodies], cwd=root)
    manifest = dict(
        stage="D5",
        base_commit=revision,
        created_utc=datetime.now(timezone.utc).isoformat(),
        files={name: hashlib.sha256(body).hexdigest() for name, body in bodies.items()},
        purpose="Current-source Linux engineering gate plus D5 probes; no downloads/models/Git writes",
    )
    bodies["source_manifest.json"] = json.dumps(manifest, sort_keys=True, indent=2).encode()
    bodies["working_tree.patch"] = patch
    target.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids overwriting an existing frozen snapshot.
    with target.open("xb") as output, tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, body in bodies.items():
            info = tarfile.TarInfo(f"{PREFIX}/{name}")
            info.size = len(body)
            info.mode = 0o755 if name.endswith(".sh") else 0o644
            archive.addfile(info, io.BytesIO(body))
    return manifest


def unpack_bundle(bundle: Path, destination: Path) -> dict:
    if destination.exists():
        raise FileExistsError(destination)
    with tarfile.open(bundle, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 5000 or sum(member.size for member in members) > MAX_TOTAL:
            raise ValueError("archive_budget_exceeded")
        names = set()
        folded_names = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or member.size > MAX_FILE
                or path.is_absolute()
                or len(path.parts) < 2
                or path.parts[0] != PREFIX
                or any(part in {".", ".."} or ":" in part or "\\" in part for part in path.parts)
                or member.name.casefold() in folded_names
                or path.as_posix() != member.name
            ):
                raise ValueError("unsafe_archive_member")
            names.add(member.name)
            folded_names.add(member.name.casefold())
            relative = path.relative_to(PREFIX)
            if relative.suffix not in SUFFIXES | {".patch"} and relative.as_posix() not in {
                "LICENSE",
                ".gitignore",
                ".python-version",
            }:
                raise ValueError("unexpected_archive_file_type")
        manifest_member = archive.getmember(f"{PREFIX}/source_manifest.json")
        stream = archive.extractfile(manifest_member)
        if stream is None:
            raise ValueError("missing_source_manifest")
        with stream:
            manifest = json.load(stream)
        if manifest.get("stage") != "D5" or not isinstance(manifest.get("files"), dict):
            raise ValueError("invalid_source_manifest")
        expected = {f"{PREFIX}/{name}" for name in manifest["files"]} | {
            f"{PREFIX}/source_manifest.json",
            f"{PREFIX}/working_tree.patch",
        }
        if names != expected:
            raise ValueError("archive_manifest_members_mismatch")
        verified = []
        for member in members:
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("missing_archive_body")
            with stream:
                body = stream.read()
            name = PurePosixPath(member.name).relative_to(PREFIX).as_posix()
            if name in manifest["files"] and hashlib.sha256(body).hexdigest() != manifest["files"][name]:
                raise ValueError("archive_source_hash_mismatch")
            verified.append((name, body, member.mode))
    # Validate all members before creating files. Never use tar.extractall.
    destination.mkdir(parents=True, exist_ok=False)
    for name, body, mode in verified:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        target.chmod(0o755 if mode & 0o111 else 0o644)
    return manifest


def runtime_paths(receipt: dict, home: Path) -> tuple[Path, Path, Path]:
    native = Path(receipt["native_directory"]).resolve()
    if (
        receipt.get("exit_code") != 0
        or not native.is_relative_to(home.resolve())
        or not native.name.startswith("camelplus-d0-")
    ):
        raise ValueError("unverified_D0_runtime_location")
    old_project = native / "camelplus-d0"
    python = old_project / ".venv/bin/python"
    node = Path(receipt["tools"]["node_path"])
    for executable in (python, node):
        if not executable.resolve().is_relative_to(native) or not executable.is_file():
            raise ValueError("existing_D0_runtime_missing_or_outside_native_directory")
    return old_project, python, node


def native_probes(directory: Path) -> dict:
    """Actual POSIX writes; success here does not claim audit/IO atomicity."""
    from camel.audit.store import AuditStore
    from camel.broker.executor import ExecutionAuditError
    from camel.core import EffectType
    from camel.evaluation.integration import Probe

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(nofollow, int) or nofollow <= 0:
        raise ValueError("native_probes_require_POSIX_O_NOFOLLOW")
    directory.mkdir()
    marker = directory / "private-marker"
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
    os.close(fd)
    if stat.S_IMODE(marker.stat().st_mode) != 0o600:
        raise ValueError("native_filesystem_must_enforce_0600")
    link = directory / "marker-link"
    link.symlink_to(marker.name)
    try:
        fd = os.open(link, os.O_WRONLY | nofollow)
    except OSError as error:
        import errno

        if error.errno != errno.ELOOP:
            raise
    else:
        os.close(fd)
        raise ValueError("O_NOFOLLOW_failed")
    observations = []
    for kind in ("valid_write", "intent_fault", "completion_fault"):
        probe = Probe(directory / kind, kind)
        target = probe.scratch / "write.txt"
        if kind != "valid_write":
            target.write_bytes(b"OLD")
        effect = probe.effect(type=EffectType.WRITE, operation="write_file", resources=(str(target),))
        probe.audit.fail_source = {"intent_fault": "execution_intent", "completion_fault": "execution"}.get(kind)
        output = None
        error_type = None
        try:
            output = probe.broker.execute(effect, probe.ticket(effect), content=b"NEW", **probe.scope)
        except OSError as error:
            error_type = type(error).__name__
        try:
            changed = target.exists() and target.read_bytes() == b"NEW"
            pending = len(probe.audit.pending_executions())
            if kind == "valid_write":
                assert output is not None and changed and pending == 0
                assert stat.S_IMODE(target.stat().st_mode) == 0o600
            elif kind == "intent_fault":
                assert output is None and error_type == "OSError" and not changed and pending == 0
                assert not probe.broker.io_effects and target.read_bytes() == b"OLD"
            else:
                assert output is None and error_type == ExecutionAuditError.__name__ and changed and pending == 1
            probe.audit.verify_chain()
            probe.audit.close()
            reopened = AuditStore(probe.root / "audit.sqlite")
            try:
                assert len(reopened.pending_executions()) == pending
                reopened.verify_chain()
            finally:
                reopened.close()
            observations.append(
                dict(
                    case=kind,
                    mechanism_check="PASS",
                    file_changed=changed,
                    unresolved_intents=pending,
                    actual_io_calls=len(probe.broker.io_effects),
                    error_type=error_type,
                )
            )
        finally:
            probe.audit.close()
            probe.tickets.close()
    return dict(
        platform_checks="PASS",
        observations=observations,
        strict_audit_io_atomicity_accepted=False,
        scope="Actual C broker with synthetic host-issued canonical WRITE/ticket; not B/A full-chain authorization",
    )


def copy_evidence(source: Path, target: Path):
    target.mkdir(exist_ok=False)
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        if any(
            part.startswith("pytest") or part.endswith("_tmp") or part in {"workspace", "scratch"}
            for part in relative.parts
        ):
            continue
        if path.is_file() and not path.is_symlink() and path.suffix in {".json", ".xml", ".txt", ".patch"}:
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)


def run_linux(bundle: Path, runtime_receipt: Path) -> int:
    if sys.platform != "linux":
        raise ValueError("run_with_Ubuntu_python3_via_WSL")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    returned = ROOT / "artifacts/d" / f"D5_wsl_return_{stamp}"
    returned.mkdir(exist_ok=False)
    native = Path(tempfile.mkdtemp(prefix="camelplus-d5-", dir=Path.home()))
    project = native / PREFIX
    receipt: dict[str, Any] = dict(
        stage="D5",
        exit_code=2,
        engineering_status="NOT_RUN",
        full_chain_accepted=False,
        native_directory=str(native),
        source_bundle=str(bundle),
        model_requests=0,
        downloads=0,
    )
    try:
        old_receipt = json.loads(runtime_receipt.read_text(encoding="utf-8"))
        old_project, python, node = runtime_paths(old_receipt, Path.home())
        receipt.update(runtime_python=str(python), source_bundle_sha256=digest(bundle))
        manifest = unpack_bundle(bundle, project)
        if digest(old_project / "uv.lock") != digest(project / "uv.lock"):
            raise ValueError("D0_runtime_lock_differs_no_automatic_install")
        # Pyright's existing pyproject configuration resolves .venv locally.
        # This link lives only in the new snapshot, and does not alter the runtime.
        (project / ".venv").symlink_to(old_project / ".venv", target_is_directory=True)
        environment = dict(
            os.environ,
            PYTHONPATH=str(project / "src"),
            PYTHONUTF8="1",
            PYTHONIOENCODING="utf-8",
            PYTHONDONTWRITEBYTECODE="1",
            PYTHONOPTIMIZE="0",
            PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
            UV_OFFLINE="1",
            PIP_NO_INDEX="1",
            PYRIGHT_PYTHON_FORCE_VERSION="1.1.401",
            PYRIGHT_PYTHON_USE_BUNDLED_PYRIGHT="1",
            PYRIGHT_PYTHON_GLOBAL_NODE="1",
            PATH=str(node.parent) + os.pathsep + os.environ.get("PATH", ""),
        )
        version = subprocess.check_output([str(python), "--version"], env=environment, text=True).strip()
        if version != "Python " + (project / ".python-version").read_text().strip():
            raise ValueError("existing_python_version_mismatch")
        receipt.update(python_version=version, source_file_count=len(manifest["files"]))
        output = project / "artifacts/d" / f"D5_linux_{stamp}"
        output.mkdir(parents=True)
        sys.path.insert(0, str(project / "src"))
        # Execute native probes with the existing project runtime, not bootstrap Python.
        commands = [
            ("baseline", [str(python), "scripts/d0_baseline.py", "--output", str(output / "engineering")], 600),
            (
                "native_write",
                [str(python), "scripts/d5_linux_acceptance.py", "--native-probes", str(output / "native_write")],
                60,
            ),
            ("d5_probes", [str(python), "scripts/d5_eval.py", "--output", str(output / "d5_probes")], 120),
        ]
        codes = {}
        for name, command, timeout in commands:
            print(f"Running {name} in native Linux directory: {project}", flush=True)
            with (output / f"{name}_launcher.txt").open("w", encoding="utf-8") as log:
                result = subprocess.run(
                    command,
                    cwd=project,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    check=False,
                )
            codes[name] = result.returncode
            print((output / f"{name}_launcher.txt").read_text(encoding="utf-8"), flush=True)
        receipt.update(
            check_exit_codes=codes,
            engineering_status="PASS" if codes["baseline"] == codes["native_write"] == 0 else "FAIL",
        )
        d5_report = json.loads((output / "d5_probes/report.json").read_text(encoding="utf-8"))
        receipt["d5_counts"] = d5_report["counts"]
        receipt["only_known_strict_failure"] = d5_report["counts"] == {"PASS": 21, "FAIL": 1} and [
            item["scenario"] for item in d5_report["observations"] if item["status"] != "PASS"
        ] == ["execution_audit_fault"]
        receipt["exit_code"] = 1 if receipt["engineering_status"] == "PASS" and codes["d5_probes"] == 1 else 2
        receipt["full_D5_status"] = "PARTIAL_FAIL" if receipt["exit_code"] == 1 else "CHECK_RESULTS"
    except Exception as error:
        receipt["error_type"] = type(error).__name__
        (returned / "launcher_error.txt").write_text(traceback.format_exc(), encoding="utf-8")
        print(traceback.format_exc(), flush=True)
    finally:
        receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(returned / "receipt.json", receipt)
        for output in (project / "artifacts/d").glob("D5_linux_*"):
            copy_evidence(output, returned / output.name)
    print(
        f"Engineering: {receipt['engineering_status']}; full D5 not accepted; exit={receipt['exit_code']}; evidence: {returned}",
        flush=True,
    )
    return receipt["exit_code"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-bundle", action="store_true")
    parser.add_argument("--bundle", type=Path, default=ROOT / DEFAULT_BUNDLE)
    parser.add_argument("--runtime-receipt", type=Path, default=ROOT / DEFAULT_RECEIPT)
    parser.add_argument("--native-probes", type=Path)
    args = parser.parse_args()
    if args.native_probes is not None:
        if sys.platform != "linux":
            parser.error("native probes require Linux")
        result = native_probes(args.native_probes)
        write_json(args.native_probes / "report.json", result)
        return 0
    if args.prepare_bundle:
        manifest = make_bundle(ROOT, args.bundle)
        print(f"Prepared {len(manifest['files'])} source files: {args.bundle}")
        return 0
    return run_linux(args.bundle, args.runtime_receipt)


if __name__ == "__main__":
    raise SystemExit(main())
