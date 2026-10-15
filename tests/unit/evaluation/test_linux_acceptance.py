"""Offline source snapshots, extraction boundaries and evidence-return filtering."""

import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts/d5_linux_acceptance.py"
SPEC = importlib.util.spec_from_file_location("d5_linux_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "project"
    for folder in ("src", "tests", "scripts"):
        (root / folder).mkdir(parents=True)
    (root / "src/example.py").write_text("x = 1\n", encoding="utf-8")
    (root / "tests/frozen.jsonl").write_bytes(b'{"frozen":true}\r\n')
    (root / "scripts/entry.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    (root / ".env").write_text("SYNTHETIC-EXCLUDED", encoding="utf-8")
    (root / "src/.env").write_text("SYNTHETIC-EXCLUDED", encoding="utf-8")
    monkeypatch.setattr(
        launcher.subprocess,
        "check_output",
        lambda *a, **kw: "synthetic-revision" if kw.get("text") else b"synthetic diff\n",
    )
    return root


def archive(path, entries, manifest=None):
    if manifest is None:
        manifest = dict(stage="D5", files={})
    items = [
        ("camelplus-d5/source_manifest.json", json.dumps(manifest).encode(), None),
        ("camelplus-d5/working_tree.patch", b"", None),
        *entries,
    ]
    with tarfile.open(path, "w:gz") as output:
        for name, body, kind in items:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            if kind is not None:
                info.type = kind
                info.linkname = "../outside"
            output.addfile(info, io.BytesIO(body))


def test_snapshot_roundtrip_preserves_frozen_bytes_and_excludes_environment(project):
    bundle = project / "artifacts/d/source.tar.gz"
    manifest = launcher.make_bundle(project, bundle)
    assert set(manifest["files"]) == {"src/example.py", "tests/frozen.jsonl", "scripts/entry.sh"}
    extracted = project / "extracted"
    assert launcher.unpack_bundle(bundle, extracted) == manifest
    assert (extracted / "tests/frozen.jsonl").read_bytes() == b'{"frozen":true}\r\n'
    assert not (extracted / ".env").exists()


def test_snapshot_refuses_to_overwrite(project):
    bundle = project / "artifacts/d/source.tar.gz"
    launcher.make_bundle(project, bundle)
    original = bundle.read_bytes()
    with pytest.raises(FileExistsError):
        launcher.make_bundle(project, bundle)
    assert bundle.read_bytes() == original


def test_snapshot_refuses_output_outside_artifacts(project):
    target = project / "source.tar.gz"
    with pytest.raises(ValueError, match="under_artifacts"):
        launcher.make_bundle(project, target)
    assert not target.exists()


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "camelplus-d5/../escape",
        "camelplus-d5/C:stream",
        "camelplus-d5/dir\\escape",
        "camelplus-d5/./duplicate",
    ],
)
def test_unsafe_archive_paths_refused_before_extraction(tmp_path, name):
    bundle = tmp_path / "bad.tar.gz"
    archive(bundle, [(name, b"bad", None)])
    target = tmp_path / "target"
    with pytest.raises(ValueError):
        launcher.unpack_bundle(bundle, target)
    assert not target.exists()


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_nonregular_archive_members_refused(tmp_path, kind):
    bundle = tmp_path / "bad.tar.gz"
    archive(bundle, [("camelplus-d5/link", b"", kind)])
    with pytest.raises(ValueError, match="unsafe_archive_member"):
        launcher.unpack_bundle(bundle, tmp_path / "target")


def test_case_colliding_archive_members_refused(tmp_path):
    bundle = tmp_path / "bad.tar.gz"
    archive(bundle, [("camelplus-d5/A.py", b"", None), ("camelplus-d5/a.py", b"", None)])
    with pytest.raises(ValueError, match="unsafe_archive_member"):
        launcher.unpack_bundle(bundle, tmp_path / "target")


@pytest.mark.parametrize("mode", ["hash", "missing", "extra"])
def test_source_manifest_must_match_all_archive_members(tmp_path, mode):
    bundle = tmp_path / "bad.tar.gz"
    manifest = dict(stage="D5", files={"src/a.py": "0" * 64})
    entries = [] if mode == "missing" else [("camelplus-d5/src/a.py", b"changed", None)]
    if mode == "extra":
        manifest["files"] = {}
    archive(bundle, entries, manifest)
    with pytest.raises(ValueError):
        launcher.unpack_bundle(bundle, tmp_path / "target")
    assert not (tmp_path / "target").exists()


def test_existing_extraction_destination_is_preserved(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        launcher.unpack_bundle(tmp_path / "nonexistent.tar.gz", target)
    assert (target / "keep").read_bytes() == b"keep"


def test_runtime_paths_reuse_only_verified_native_runtime(tmp_path):
    native = tmp_path / "camelplus-d0-synthetic"
    python = native / "camelplus-d0/.venv/bin/python"
    node = native / "camelplus-d0/tools/node"
    for path in (python, node):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic-executable")
    receipt = dict(native_directory=str(native), tools=dict(node_path=str(node)), exit_code=0)
    assert launcher.runtime_paths(receipt, tmp_path)[1:] == (python, node)
    receipt["exit_code"] = 2
    with pytest.raises(ValueError):
        launcher.runtime_paths(receipt, tmp_path)


def test_runtime_escape_refused(tmp_path):
    receipt = dict(
        native_directory=str(tmp_path.parent / "camelplus-d0-outside"), tools=dict(node_path="missing"), exit_code=0
    )
    with pytest.raises(ValueError, match="runtime_location"):
        launcher.runtime_paths(receipt, tmp_path)


def test_evidence_return_excludes_payloads_databases_and_pytest_temporaries(tmp_path):
    source = tmp_path / "source"
    for name in (
        "report.json",
        "run/probe/trace.json",
        "pytest-0/secret.txt",
        "full_suite_tmp/payload.json",
        "probe/workspace/document.txt",
        "probe/scratch/write.txt",
        "audit.sqlite",
    ):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic", encoding="utf-8")
    destination = tmp_path / "returned"
    launcher.copy_evidence(source, destination)
    files = {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()}
    assert files == {"report.json", "run/probe/trace.json"}
