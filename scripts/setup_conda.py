"""Create the project's Conda environment and install its locked dependencies.

Run with Python from an initialized Conda terminal on Linux, macOS or Windows.
Existing environments are reused only if their Python version matches the repo.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_NAME = "camelplus"


def main() -> None:
    conda = os.environ.get("CONDA_EXE") or shutil.which("conda")
    if not conda:
        raise SystemExit("Conda was not found. Run this script from an initialized Conda terminal.")
    required_python = (PROJECT_ROOT / ".python-version").read_text().strip()
    listed = subprocess.run([conda, "env", "list", "--json"], check=True, capture_output=True, text=True)
    environments = json.loads(listed.stdout)["envs"]
    if not any(Path(prefix).name == ENVIRONMENT_NAME for prefix in environments):
        subprocess.run(
            [conda, "env", "create", "--file", str(PROJECT_ROOT / "environment.yml"), "--yes", "--quiet"],
            check=True,
            cwd=PROJECT_ROOT,
        )
    inspect = subprocess.run(
        [
            conda,
            "run",
            "--no-capture-output",
            "--name",
            ENVIRONMENT_NAME,
            "python",
            "-c",
            "import json,sys; print(json.dumps({'prefix':sys.prefix,'python':sys.executable,'version':sys.version.split()[0]}))",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    interpreter = json.loads(inspect.stdout)
    if interpreter["version"] != required_python:
        raise SystemExit(
            f"Existing {ENVIRONMENT_NAME} uses Python {interpreter['version']}; expected {required_python}."
        )
    environment = os.environ.copy()
    environment.pop("VIRTUAL_ENV", None)
    environment["UV_PROJECT_ENVIRONMENT"] = interpreter["prefix"]
    environment["UV_PYTHON_DOWNLOADS"] = "never"
    # Preserve Conda-owned packages; install the project into this prefix rather
    # than silently creating a second .venv beside it. Never regenerate uv.lock.
    subprocess.run(
        [
            conda,
            "run",
            "--no-capture-output",
            "--name",
            ENVIRONMENT_NAME,
            "uv",
            "sync",
            "--project",
            str(PROJECT_ROOT),
            "--locked",
            "--inexact",
            "--group",
            "dev",
            "--python",
            interpreter["python"],
            "--no-python-downloads",
        ],
        check=True,
        cwd=PROJECT_ROOT,
        env=environment,
    )
    subprocess.run(
        [
            conda,
            "run",
            "--no-capture-output",
            "--name",
            ENVIRONMENT_NAME,
            "python",
            "-c",
            "import camel.gateway,camel.normalization; print('CaMeL Plus imports OK')",
        ],
        check=True,
        cwd=PROJECT_ROOT,
    )
    print(f"Environment ready: {interpreter['prefix']}\nActivate with: conda activate {ENVIRONMENT_NAME}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr, file=sys.stderr)
        raise SystemExit(error.returncode) from error
