"""Run from a user-owned WSL terminal; return D0 evidence to the Windows checkout."""

import hashlib
import http.client
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def file_digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def fetch(url: str, target: Path, digest: str | None = None, expected_size: int | None = None) -> None:
    if target.exists():
        raise FileExistsError(target)
    cached = ROOT / "artifacts/d/.bootstrap_cache" / target.name
    if digest and cached.is_file() and file_digest(cached) == digest:
        if expected_size is None or cached.stat().st_size == expected_size:
            shutil.copyfile(cached, target)
            if file_digest(target) != digest:
                raise ValueError(f"Cached copy SHA256 mismatch: {target.name}")
            print(f"Verified local cache: {target.name}", flush=True)
            return
    last_error = None
    for attempt in range(1, 4):
        partial = target.with_name(f"{target.name}.attempt{attempt}.part")
        record = {"url": url, "attempt": attempt, "expected_size": expected_size, "expected_sha256": digest}
        print(f"Downloading {url} (attempt {attempt}/3)", flush=True)
        try:
            with urllib.request.urlopen(url, timeout=60) as response, partial.open("xb") as output:
                record["http_status"] = response.status
                record["content_length"] = response.headers.get("Content-Length")
                record["content_type"] = response.headers.get("Content-Type")
                shutil.copyfileobj(response, output)
            actual_size = partial.stat().st_size
            actual_digest = file_digest(partial)
            record.update(actual_size=actual_size, actual_sha256=actual_digest)
            advertised_size = record.get("content_length")
            if expected_size is not None and actual_size != expected_size:
                raise ValueError(f"Length mismatch: expected {expected_size}, received {actual_size}")
            if advertised_size and actual_size != int(advertised_size):
                raise ValueError(f"Incomplete HTTP body: expected {advertised_size}, received {actual_size}")
            if digest and actual_digest != digest:
                raise ValueError(f"SHA256 mismatch: expected {digest}, received {actual_digest}")
        except (OSError, ValueError, http.client.IncompleteRead) as exc:
            last_error = exc
            record["error"] = str(exc)
            if partial.is_file():
                record.update(actual_size=partial.stat().st_size, actual_sha256=file_digest(partial))
            print(f"Download rejected: {exc}", flush=True)
        else:
            partial.rename(target)
            record["verified"] = True
            last_error = None
        with (target.parent / "downloads.jsonl").open("a", encoding="utf-8") as evidence:
            evidence.write(json.dumps(record) + "\n")
        if last_error is None:
            return
        if attempt < 3:
            time.sleep(1)
    raise ValueError(f"Download failed after 3 attempts: {target.name}; see downloads.jsonl") from last_error


def metadata(url: str):
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def unpack_source(bundle: Path, destination: Path) -> None:
    with tarfile.open(bundle, "r:gz") as archive:
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or name.parts[0] != "camelplus-d0":
                raise ValueError(f"Invalid archive path: {member.name}")
            if not member.isfile():
                raise ValueError(f"Only regular source files are accepted: {member.name}")
            target = destination.joinpath(*name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"Missing file data: {member.name}")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if target.suffix == ".sh" else 0o644)


def prepare_tools(project: Path, environment: dict[str, str]) -> dict:
    tools = project / "artifacts/d/.runtime/bootstrap"
    tools.mkdir(parents=True)
    machine = platform.machine()
    if machine not in {"x86_64", "aarch64"}:
        raise ValueError(f"Unsupported bootstrap architecture: {machine}")
    uv_info = metadata("https://pypi.org/pypi/uv/0.13.1/json")
    wheel = next(
        item
        for item in uv_info["urls"]
        if f"manylinux_2_17_{machine}" in item["filename"] and item["filename"].endswith(".whl")
    )
    uv_archive = tools / wheel["filename"]
    fetch(wheel["url"], uv_archive, wheel["digests"]["sha256"], wheel["size"])
    uv_path = tools / "uv"
    with zipfile.ZipFile(uv_archive) as archive:
        binary = next(name for name in archive.namelist() if name.endswith("/scripts/uv"))
        uv_path.write_bytes(archive.read(binary))
    uv_path.chmod(0o755)
    environment["D0_UV"] = str(uv_path)
    runtime = {"uv": "0.13.1", "uv_sha256": wheel["digests"]["sha256"]}
    existing_node = shutil.which("node")
    if existing_node and os.access(existing_node, os.X_OK):
        runtime["node"] = subprocess.check_output([existing_node, "--version"], text=True).strip()
        runtime["node_path"] = existing_node
    else:
        # Official LTS metadata checked on 2026-10-15; freeze this bootstrap runtime.
        release = next(item for item in metadata("https://nodejs.org/dist/index.json") if item["version"] == "v24.22.0")
        version = release["version"]
        architecture = "x64" if machine == "x86_64" else "arm64"
        filename = f"node-{version}-linux-{architecture}.tar.xz"
        base = f"https://nodejs.org/dist/{version}"
        checksums = tools / "SHASUMS256.txt"
        fetch(f"{base}/SHASUMS256.txt", checksums)
        digest = next(line.split()[0] for line in checksums.read_text().splitlines() if line.split()[-1] == filename)
        node_archive = tools / filename
        fetch(f"{base}/{filename}", node_archive, digest)
        with tarfile.open(node_archive, "r:xz") as archive:
            member = archive.getmember(f"node-{version}-linux-{architecture}/bin/node")
            if not member.isfile():
                raise ValueError("Node binary must be a regular file")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("Node binary missing")
            with source:
                (tools / "node").write_bytes(source.read())
        (tools / "node").chmod(0o755)
        runtime.update(node=version, node_sha256=digest, node_path=str(tools / "node"))
        environment["PATH"] = str(tools) + os.pathsep + environment.get("PATH", "")
    return runtime


def main() -> int:
    if sys.platform != "linux":
        raise SystemExit("Run this script with Ubuntu's python3 through wsl.exe, not Windows Python.")
    bundle = ROOT / "artifacts/d/D0_linux_source_04.tar.gz"
    if not bundle.is_file():
        raise SystemExit(f"Missing prepared source bundle: {bundle}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    returned = ROOT / "artifacts/d" / f"D0_wsl_return_{stamp}"
    returned.mkdir(exist_ok=False)
    native = Path(tempfile.mkdtemp(prefix="camelplus-d0-", dir=Path.home()))
    receipt = {
        "stage": "D0",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "source_bundle": bundle.name,
        "source_bundle_sha256": file_digest(bundle),
        "native_directory": str(native),
        "returned_directory": str(returned),
        "model": None,
        "exit_code": 2,
    }
    log = (returned / "launcher.txt").open("w", encoding="utf-8", buffering=1)
    try:
        print(f"Native directory: {native}", flush=True)
        print(f"Native directory: {native}", file=log)
        unpack_source(bundle, native)
        project = native / "camelplus-d0"
        environment = os.environ.copy()
        receipt["tools"] = prepare_tools(project, environment)
        process = subprocess.Popen(
            ["sh", "scripts/d0_linux.sh", "--prepare-online"],
            cwd=project,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            log.write(line)
        receipt["exit_code"] = process.wait()
    except Exception:
        traceback.print_exc(file=log)
        traceback.print_exc()
    finally:
        log.close()
        for diagnostic in native.glob("camelplus-d0/artifacts/d/.runtime/bootstrap/downloads.jsonl"):
            shutil.copyfile(diagnostic, returned / diagnostic.name)
        # Return evidence only; never traverse pytest temporary symlinks or copy runtimes.
        for run in (native / "camelplus-d0/artifacts/d").glob("D0_linux_*"):
            if run.is_dir() and not run.is_symlink():
                destination = returned / run.name
                destination.mkdir()
                for path in run.rglob("*"):
                    relative = path.relative_to(run)
                    if any(part.startswith("pytest") or part.endswith("_tmp") for part in relative.parts):
                        continue
                    if path.is_symlink() or not path.is_file():
                        continue
                    if path.suffix not in {".json", ".xml", ".txt", ".patch"}:
                        continue
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
        receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (returned / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print((returned / "launcher.txt").read_text(encoding="utf-8"))
    print(f"D0 exit={receipt['exit_code']}; evidence: {returned}")
    return receipt["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
