#!/bin/sh
# Run the complete D0 gate in an extracted checkout on a native Linux filesystem.
set -eu

if [ "$(uname -s)" != Linux ]; then
    echo "D0 Linux acceptance requires Linux; Windows/MSYS is not supported." >&2
    exit 2
fi
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$task_root"
export PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 PYTHONIOENCODING=utf-8
task_bootstrap_python=${D0_BOOTSTRAP_PYTHON:-python3}
"$task_bootstrap_python" - <<'PY'
import errno
import os
import stat
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory(prefix=".d0-platform-", dir=".") as temporary:
    target = Path(temporary) / "synthetic.txt"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    os.close(descriptor)
    if stat.S_IMODE(target.stat().st_mode) != 0o600:
        raise SystemExit("Use a native Linux filesystem that enforces mode 0600, not a Windows mount.")
    link = Path(temporary) / "synthetic-link"
    link.symlink_to("synthetic.txt")
    try:
        descriptor = os.open(link, os.O_WRONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno != errno.ELOOP:
            raise
    else:
        os.close(descriptor)
        raise SystemExit("O_NOFOLLOW did not reject the synthetic symlink.")
print("Native filesystem permissions, symlinks and O_NOFOLLOW verified.")
PY

task_uv=${D0_UV:-uv}
command -v "$task_uv" >/dev/null 2>&1 || {
    echo "Provide uv 0.13.1 through D0_UV; see docs/d/D0_linux_acceptance.md." >&2
    exit 2
}
command -v node >/dev/null 2>&1 || {
    echo "Provide Node.js for the bundled pyright; no automatic global installation is performed." >&2
    exit 2
}
export UV_CACHE_DIR="$task_root/artifacts/d/.runtime/uv-cache"
export UV_PYTHON_INSTALL_DIR="$task_root/artifacts/d/.runtime/python"
export UV_PYTHON_BIN_DIR="$task_root/artifacts/d/.runtime/bin"
export UV_PROJECT_ENVIRONMENT="$task_root/.venv"
case "${1:-}" in
    --prepare-online)
        "$task_uv" sync --frozen --group dev --python 3.10.12 --no-config
        ;;
    "")
        "$task_uv" sync --offline --frozen --group dev --python 3.10.12 --no-python-downloads --no-config
        ;;
    *)
        echo "Usage: sh scripts/d0_linux.sh [--prepare-online]" >&2
        exit 2
        ;;
esac
task_run="D0_linux_$(date -u +%Y%m%dT%H%M%SZ)"
echo "Running complete D0 acceptance; output: artifacts/d/$task_run"
exec .venv/bin/python scripts/d0_baseline.py --output "artifacts/d/$task_run"
