"""Sandbox profile: containment, symlink escapes, write scoping."""

from pathlib import Path

import pytest

from camel.broker import SandboxProfile, SandboxViolationError, to_path


@pytest.fixture()
def profile(tmp_path: Path) -> SandboxProfile:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    return SandboxProfile.workspace(workspace, scratch)


def test_read_inside_root_ok(profile: SandboxProfile, tmp_path: Path) -> None:
    target = tmp_path / "ws" / "note.txt"
    target.write_text("hello")
    resolved = profile.resolve_read(f"file://{target}")
    assert resolved == target


def test_read_outside_root_rejected(profile: SandboxProfile, tmp_path: Path) -> None:
    with pytest.raises(SandboxViolationError):
        profile.resolve_read(f"file://{tmp_path / 'outside.txt'}")


def test_dotdot_escape_rejected(profile: SandboxProfile, tmp_path: Path) -> None:
    with pytest.raises(SandboxViolationError):
        profile.resolve_read(f"file://{tmp_path / 'ws' / '..' / 'secret.txt'}")


def test_relative_resource_rejected(profile: SandboxProfile) -> None:
    with pytest.raises(SandboxViolationError):
        profile.resolve_read("relative/path.txt")


def test_symlink_escape_rejected(profile: SandboxProfile, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s")
    link = tmp_path / "ws" / "link"
    link.symlink_to(outside)
    with pytest.raises(SandboxViolationError):
        profile.resolve_read(f"file://{link / 'secret.txt'}")


def test_write_inside_scratch_ok(profile: SandboxProfile, tmp_path: Path) -> None:
    resolved = profile.resolve_write(f"file://{tmp_path / 'scratch' / 'out.txt'}")
    assert resolved.parent == tmp_path / "scratch"


def test_write_into_read_only_root_rejected(profile: SandboxProfile, tmp_path: Path) -> None:
    with pytest.raises(SandboxViolationError):
        profile.resolve_write(f"file://{tmp_path / 'ws' / 'out.txt'}")


def test_write_outside_rejected(profile: SandboxProfile, tmp_path: Path) -> None:
    with pytest.raises(SandboxViolationError):
        profile.resolve_write(f"file://{tmp_path / 'elsewhere' / 'out.txt'}")


def test_empty_profile_rejects_everything() -> None:
    empty = SandboxProfile()
    with pytest.raises(SandboxViolationError):
        empty.resolve_read("file:///etc/passwd")
    with pytest.raises(SandboxViolationError):
        empty.resolve_write("file:///tmp/out.txt")


def test_to_path_strips_scheme() -> None:
    assert to_path("file:///a/b.txt") == Path("/a/b.txt")
    with pytest.raises(SandboxViolationError):
        to_path("a/b.txt")
