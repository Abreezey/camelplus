"""Single-process durable request reservations and bounded credential-only IPC."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE_URL = "https://myai.bupt.edu.cn/llm-gw/v1"
EMBEDDING_MODEL = "bge-m3"
VERIFIER_MODEL = "deepseek-v4-flash"
GENERATION_LIMIT = 54
EMBEDDING_LIMIT = 10
OUTPUT_LIMIT = 128


def write_json(path: Path, value) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def worker_request(packet, timeout):
    """Kill the local HTTP worker at its deadline; remote billing can still continue."""
    environment = os.environ.copy()
    source_root = str(Path(__file__).resolve().parents[3])
    environment.update(PYTHONPATH=source_root, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
    process = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "camel.detection.remote.http_worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
        try:
            stdout, _ = process.communicate(json.dumps(packet).encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=1)
            return {"status": "TIMEOUT", "worker_terminated": process.poll() is not None}
        if process.returncode != 0 or len(stdout) > 4_300_000:
            return {"status": "WORKER_ERROR", "worker_terminated": True}
        result = json.loads(stdout)
        if not isinstance(result, dict):
            return {"status": "WORKER_ERROR", "worker_terminated": True}
        result["worker_terminated"] = True
        return result
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"status": "WORKER_ERROR", "worker_terminated": process is None or process.poll() is not None}
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)


class GatewayClient:
    """Never retries, never logs keys; each failed attempt still consumes its reservation."""

    def __init__(self, directory: Path, credential: str, *, transport=None, budget_directory: Path | None = None):
        if not credential or any(char.isspace() for char in credential):
            raise ValueError("credential_missing_or_invalid")
        self._credential = credential
        self.directory = directory
        self.transport = transport or worker_request
        self.budget_file = (budget_directory or directory) / "request_budget.json"
        self.state = (
            json.loads(self.budget_file.read_text(encoding="utf-8"))
            if self.budget_file.exists()
            else {
                "generation_attempts": 0,
                "embedding_attempts": 0,
                "requested_output_tokens": 0,
                "requests": [],
            }
        )

    def request(self, endpoint: str, payload: dict, *, case_ids: list[str], timeout: float = 30.0):
        generation = endpoint == "chat/completions"
        if endpoint not in {"chat/completions", "embeddings"}:
            raise ValueError("endpoint_not_allowed")
        expected_model = VERIFIER_MODEL if generation else EMBEDDING_MODEL
        if payload.get("model") != expected_model:
            raise ValueError("model_not_allowed")
        if generation and (payload.get("max_tokens") != OUTPUT_LIMIT or payload.get("n", 1) != 1):
            raise ValueError("generation_budget_configuration_changed")
        count_key = "generation_attempts" if generation else "embedding_attempts"
        limit = GENERATION_LIMIT if generation else EMBEDDING_LIMIT
        # A single CLI process owns the run lock. Refuse externally edited accounting.
        disk = json.loads(self.budget_file.read_text(encoding="utf-8")) if self.budget_file.exists() else self.state
        if disk != self.state:
            raise ValueError("request_accounting_changed")
        if self.state[count_key] >= limit:
            raise ValueError("request_budget_exhausted")
        if self._credential in json.dumps(payload):
            raise ValueError("credential_in_payload")
        self.state[count_key] += 1
        self.state["requested_output_tokens"] += OUTPUT_LIMIT if generation else 0
        row = {
            "index": len(self.state["requests"]) + 1,
            "endpoint": endpoint,
            "model": expected_model,
            "case_ids": case_ids,
            "payload_sha256": fingerprint(payload),
            "status": "RESERVED",
        }
        self.state["requests"].append(row)
        write_json(self.budget_file, self.state)
        tick = time.monotonic()
        try:
            result = self.transport({"endpoint": endpoint, "payload": payload, "credential": self._credential}, timeout)
        except Exception:
            result = {"status": "TRANSPORT_ERROR", "worker_terminated": False}
        if self._credential in json.dumps(result):
            result = {"status": "CREDENTIAL_REFLECTION", "worker_terminated": result.get("worker_terminated", False)}
        if generation and isinstance(result.get("body"), dict):
            usage = result["body"].get("usage")
            if (
                isinstance(usage, dict)
                and type(usage.get("completion_tokens")) is int
                and usage["completion_tokens"] > OUTPUT_LIMIT
            ):
                result["status"] = "OUTPUT_BUDGET_VIOLATION"
        row.update(status=result.get("status", "PROTOCOL_ERROR"), elapsed_seconds=time.monotonic() - tick)
        row["worker_terminated"] = result.get("worker_terminated", False)
        row["http_status"] = result.get("http_status")
        write_json(self.budget_file, self.state)
        return result
