"""Verify historical byte pins and optionally restore proven Python line endings."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = "docs/d/evidence/D_detection_v2_validation_selection.json"


def matching_bytes(data: bytes, expected: str) -> bytes:
    if hashlib.sha256(data).hexdigest() == expected:
        return data
    lf = data.replace(b"\r\n", b"\n")
    for candidate in (lf, lf.replace(b"\n", b"\r\n")):
        if hashlib.sha256(candidate).hexdigest() == expected:
            return candidate
    raise ValueError("content_changed_not_just_line_endings")


def prepare(root: Path, *, restore: bool) -> list[str]:
    pin = json.loads((root / PIN).read_text(encoding="utf-8"))
    changes = []
    for name, expected in pin["source_sha256"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError("invalid_frozen_path:" + name)
        original = path.read_bytes()
        if hashlib.sha256(original).hexdigest() == expected:
            continue
        if path.suffix != ".py":
            raise ValueError("non_python_frozen_file_changed:" + name)
        replacement = matching_bytes(original, expected)
        changes.append((name, path, replacement))
    # Verify the whole plan before writing; never fix an actual code/data change.
    if restore:
        for _, path, replacement in changes:
            path.write_bytes(replacement)
    return [name for name, _, _ in changes]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore-line-endings", action="store_true")
    args = parser.parse_args()
    changes = prepare(ROOT, restore=args.restore_line_endings)
    print(
        json.dumps(
            dict(
                status="RESTORED" if args.restore_line_endings else "CHECKED",
                python_line_ending_changes=changes,
                code_content_changes=0,
            )
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
