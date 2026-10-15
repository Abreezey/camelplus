"""Offline regressions for verified bootstrap downloads; no real HTTP requests."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
from urllib.error import URLError

import pytest

SOURCE = Path(__file__).resolve().parents[3] / "scripts/d0_wsl_acceptance.py"
SPEC = importlib.util.spec_from_file_location("d0_wsl_download", SOURCE)
assert SPEC is not None and SPEC.loader is not None
downloader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(downloader)
PAYLOAD = b"synthetic verified binary"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class Response(io.BytesIO):
    status = 200

    def __init__(self, content: bytes, length: int | None = None):
        super().__init__(content)
        self.headers = {"Content-Length": str(len(content) if length is None else length)}


@pytest.fixture
def download(tmp_path, monkeypatch):
    monkeypatch.setattr(downloader, "ROOT", tmp_path)
    monkeypatch.setattr(downloader.time, "sleep", lambda _: None)
    target = tmp_path / "native/tool.whl"
    target.parent.mkdir()
    return target


@pytest.mark.parametrize("first", [b"short", b"x" * len(PAYLOAD)])
def test_rejects_bad_body_then_retries_verified_body(download, monkeypatch, first):
    responses = iter([Response(first), Response(PAYLOAD)])
    monkeypatch.setattr(downloader.urllib.request, "urlopen", lambda *a, **k: next(responses))
    downloader.fetch("https://synthetic.invalid/tool", download, DIGEST, len(PAYLOAD))
    assert download.read_bytes() == PAYLOAD
    records = [json.loads(line) for line in (download.parent / "downloads.jsonl").read_text().splitlines()]
    assert len(records) == 2 and "error" in records[0] and records[1]["verified"] is True
    assert records[0]["actual_sha256"] == hashlib.sha256(first).hexdigest()
    assert download.with_name(download.name + ".attempt1.part").read_bytes() == first


def test_persistent_corruption_never_publishes_download(download, monkeypatch):
    monkeypatch.setattr(downloader.urllib.request, "urlopen", lambda *a, **k: Response(b"bad"))
    with pytest.raises(ValueError, match="failed after 3 attempts"):
        downloader.fetch("https://synthetic.invalid/tool", download, DIGEST, len(PAYLOAD))
    assert not download.exists()
    assert len(list(download.parent.glob("*.part"))) == 3
    assert len((download.parent / "downloads.jsonl").read_text().splitlines()) == 3


def test_verified_cache_avoids_network(download, monkeypatch):
    cached = downloader.ROOT / "artifacts/d/.bootstrap_cache" / download.name
    cached.parent.mkdir(parents=True)
    cached.write_bytes(PAYLOAD)

    def forbidden_network(*args, **kwargs):
        raise AssertionError("cache hit must not contact network")

    monkeypatch.setattr(downloader.urllib.request, "urlopen", forbidden_network)
    downloader.fetch("https://synthetic.invalid/tool", download, DIGEST, len(PAYLOAD))
    assert download.read_bytes() == PAYLOAD


def test_corrupt_cache_is_not_used(download, monkeypatch):
    cached = downloader.ROOT / "artifacts/d/.bootstrap_cache" / download.name
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"bad")
    monkeypatch.setattr(downloader.urllib.request, "urlopen", lambda *a, **k: Response(PAYLOAD))
    downloader.fetch("https://synthetic.invalid/tool", download, DIGEST, len(PAYLOAD))
    assert download.read_bytes() == PAYLOAD
    assert cached.read_bytes() == b"bad"


def test_incomplete_http_length_is_rejected_without_metadata_size(download, monkeypatch):
    monkeypatch.setattr(downloader.urllib.request, "urlopen", lambda *a, **k: Response(PAYLOAD, len(PAYLOAD) + 1))
    with pytest.raises(ValueError, match="failed after 3 attempts"):
        downloader.fetch("https://synthetic.invalid/tool", download, DIGEST)
    assert not download.exists()


def test_transport_failure_is_retried(download, monkeypatch):
    attempts = iter([URLError("synthetic disconnect"), Response(PAYLOAD)])

    def open_response(*args, **kwargs):
        response = next(attempts)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(downloader.urllib.request, "urlopen", open_response)
    downloader.fetch("https://synthetic.invalid/tool", download, DIGEST, len(PAYLOAD))
    assert download.read_bytes() == PAYLOAD


def test_existing_target_is_never_overwritten(download):
    download.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        downloader.fetch("https://synthetic.invalid/tool", download, DIGEST)
    assert download.read_bytes() == b"existing"
