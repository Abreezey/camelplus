"""Sandbox profiles and path containment for the execution broker (arch.md §6.9).

v0 profile (first-round scope, arch.md §13 task 6): a read-only workspace
root plus one explicit writable scratch directory. No network, no subprocess
execution — those need the egress proxy / kernel sandbox and stay
unsupported (fail closed) until they exist.

Containment strategy:

- resources must be absolute ``file://`` URIs (or absolute paths);
- reads: the fully resolved path (``realpath`` follows symlinks) must stay
  inside a read root — a symlink pointing outside is rejected;
- writes: the resolved *parent* directory must stay inside a write dir and
  the final component is opened with ``O_NOFOLLOW`` by the executor.

Known v0 limitation (documented in handoff-c.md): an ancestor directory
swapped for a symlink between the ``realpath`` check and the open is a
residual TOCTOU race; the kernel-level sandbox is the designated fix.
"""

import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class SandboxViolationError(Exception):
    """Raised when a resource escapes the sandbox profile."""


def to_path(resource: str) -> Path:
    """Convert a ``file://`` URI (or absolute path) to a ``Path``.

    Relative resources are rejected: the normalizer (module B) must produce
    absolute paths, and the broker refuses to guess a base directory.
    """
    path = Path(resource.removeprefix("file://"))
    if not path.is_absolute():
        raise SandboxViolationError(f"resource must be absolute: {resource!r}")
    return path


def _resolved(path: Path) -> Path:
    return Path(os.path.realpath(path))


def _contained(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class SandboxProfile(BaseModel):
    """Declarative v0 sandbox: what an executed effect may touch."""

    model_config = ConfigDict(frozen=True)

    read_roots: tuple[Path, ...] = ()
    write_dirs: tuple[Path, ...] = ()

    @classmethod
    def workspace(cls, root: Path, scratch: Path) -> "SandboxProfile":
        """The v0 profile: one read-only workspace root + one writable scratch dir."""
        return cls(read_roots=(root,), write_dirs=(scratch,))

    def resolve_read(self, resource: str) -> Path:
        """Resolve a read resource; symlinks must not escape the read roots."""
        if not self.read_roots:
            raise SandboxViolationError("no read roots configured")
        resolved = _resolved(to_path(resource))
        if not any(_contained(resolved, _resolved(root)) for root in self.read_roots):
            raise SandboxViolationError(f"read escapes sandbox: {resource!r}")
        return resolved

    def resolve_write(self, resource: str) -> Path:
        """Resolve a write resource: the parent dir must be inside a write dir."""
        if not self.write_dirs:
            raise SandboxViolationError("no write dirs configured")
        path = to_path(resource)
        parent = _resolved(path.parent)
        if not any(_contained(parent, _resolved(directory)) for directory in self.write_dirs):
            raise SandboxViolationError(f"write escapes sandbox: {resource!r}")
        return parent / path.name
