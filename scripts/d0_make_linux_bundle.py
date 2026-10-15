"""Package current D0 source and its local diff, excluding secrets and environments."""

import argparse
import io
import json
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    output = parser.parse_args().output.resolve()
    if not output.is_relative_to(ROOT / "artifacts" / "d"):
        parser.error("output must be under artifacts/d")
    if output.exists():
        parser.error("output already exists; choose another version")
    output.parent.mkdir(parents=True, exist_ok=True)
    files = [p for directory in ("src", "tests", "scripts") for p in (ROOT / directory).rglob("*")]
    files += list(ROOT.glob("*.py"))
    files += [
        ROOT / name for name in ("pyproject.toml", "uv.lock", ".python-version", ".gitignore", "README.md", "LICENSE")
    ]
    files += [ROOT / "docs/d/D0_linux_acceptance.md"]
    allowed_suffixes = {".py", ".sh", ".yaml", ".yml", ".json", ".jsonl", ".txt", ".md", ".toml", ".lock"}
    selected = []
    for path in sorted(set(files)):
        if path.is_symlink():
            raise ValueError(f"refusing source symlink: {path}")
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.suffix not in allowed_suffixes and path.name not in {"LICENSE", ".gitignore", ".python-version"}:
            continue
        if not path.resolve().is_relative_to(ROOT):
            raise ValueError("source file outside project")
        selected.append(path)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    diff = subprocess.check_output(["git", "diff", "HEAD", "--no-ext-diff"], cwd=ROOT)
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": commit,
        "working_tree_diff": "working_tree.patch",
        "files": [path.relative_to(ROOT).as_posix() for path in selected],
        "new_files_included": True,
        "purpose": "D0 native Linux acceptance; no model or benchmark execution",
    }
    with tarfile.open(output, "w:gz") as archive:
        for path in selected:
            info = archive.gettarinfo(str(path), arcname=f"camelplus-d0/{path.relative_to(ROOT).as_posix()}")
            info.mode = 0o755 if path.suffix == ".sh" else 0o644
            with path.open("rb") as stream:
                archive.addfile(info, stream)
        for name, data in (
            ("source_manifest.json", json.dumps(manifest, indent=2).encode()),
            ("working_tree.patch", diff),
        ):
            info = tarfile.TarInfo(f"camelplus-d0/{name}")
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    print(f"Packaged {len(selected)} source/config files: {output}")


if __name__ == "__main__":
    main()
