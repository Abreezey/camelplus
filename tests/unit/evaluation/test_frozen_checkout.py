"""Line-ending restoration must never accept or rewrite changed source content."""

import hashlib
import json
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
MODULE = runpy.run_path(str(ROOT / "scripts/d_frozen_checkout.py"))
MATCH = MODULE["matching_bytes"]
PREPARE = MODULE["prepare"]


@pytest.mark.parametrize("old,new", [(b"a\nb\n", b"a\r\nb\r\n"), (b"a\r\nb\r\n", b"a\nb\n"), (b"a\n", b"a\n")])
def test_lf_crlf_reconstruction_requires_original_digest(old, new):
    assert MATCH(new, hashlib.sha256(old).hexdigest()) == old


def test_actual_content_change_is_rejected():
    with pytest.raises(ValueError, match="content_changed"):
        MATCH(b"changed\r\n", hashlib.sha256(b"original\n").hexdigest())


def test_check_is_read_only_and_restore_is_explicit(tmp_path):
    source = tmp_path / "source.py"
    source.write_bytes(b"# example\n")
    pin = tmp_path / MODULE["PIN"]
    pin.parent.mkdir(parents=True)
    pin.write_text(json.dumps(dict(source_sha256={"source.py": hashlib.sha256(b"# example\r\n").hexdigest()})))
    assert PREPARE(tmp_path, restore=False) == ["source.py"]
    assert source.read_bytes() == b"# example\n"
    assert PREPARE(tmp_path, restore=True) == ["source.py"]
    assert source.read_bytes() == b"# example\r\n"


def test_invalid_later_file_prevents_any_earlier_write(tmp_path):
    source = tmp_path / "source.py"
    source.write_bytes(b"# example\n")
    other = tmp_path / "data.json"
    other.write_bytes(b"{}")
    pin = tmp_path / MODULE["PIN"]
    pin.parent.mkdir(parents=True)
    pin.write_text(
        json.dumps(
            dict(source_sha256={"source.py": hashlib.sha256(b"# example\r\n").hexdigest(), "data.json": "0" * 64})
        )
    )
    with pytest.raises(ValueError, match="non_python"):
        PREPARE(tmp_path, restore=True)
    assert source.read_bytes() == b"# example\n"
