"""Minimal-context extraction with strict literal grounding and killable worker deadlines."""

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from camel.detection.models import (
    ContentView,
    FactPayload,
    ParseAttempt,
    ParseOutcome,
    ParseRequest,
    ParserLimits,
    ParseStatus,
    ParseTask,
    ProviderResponse,
    ProviderSettings,
    VerifiedFact,
)


def build_request(view: ContentView, task: ParseTask, limits: ParserLimits) -> ParseRequest:
    if task.source_id != view.source_id or not 0 <= task.window_start < task.window_end <= len(view.raw_text):
        raise ValueError("invalid_source_window")
    if len(set(task.requested_fields)) != len(task.requested_fields):
        raise ValueError("duplicate_requested_field")
    text = view.raw_text[task.window_start : task.window_end]
    if len(text) > limits.max_input_characters:
        raise OverflowError("selected_window_exceeds_input_budget")
    return ParseRequest(source_id=view.source_id, text=text, requested_fields=task.requested_fields)


def strict_response(raw: str) -> ProviderResponse:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("nonfinite_json_number")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    return ProviderResponse.model_validate_json(json.dumps(value, ensure_ascii=False))


def grounded_facts(
    response: ProviderResponse, request: ParseRequest, task: ParseTask, view: ContentView
) -> tuple[VerifiedFact, ...]:
    if not response.have_enough_information or not response.facts:
        raise ValueError("no_complete_facts")
    if {fact.field for fact in response.facts} != set(request.requested_fields):
        raise ValueError("missing_requested_field")
    facts = []
    seen = set()
    for fact in response.facts:
        if fact.source_id != request.source_id or fact.field not in request.requested_fields:
            raise ValueError("unrequested_field_or_source")
        if not 0 <= fact.start < fact.end <= len(request.text) or request.text[fact.start : fact.end] != fact.value:
            raise ValueError("fact_not_literal_source_span")
        if (
            fact.field == "email"
            and re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", fact.value) is None
        ):
            raise ValueError("unsupported_email_shape")
        if fact.field == "path" and not (
            fact.value.startswith(("file://", "/", "./", "../")) or re.match(r"^[A-Za-z]:[\\/]", fact.value)
        ):
            raise ValueError("unsupported_path_shape")
        if fact.field == "identifier" and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", fact.value) is None:
            raise ValueError("unsupported_identifier_shape")
        key = (fact.field, fact.start, fact.end)
        if key in seen:
            raise ValueError("duplicate_fact")
        seen.add(key)
        facts.append(
            VerifiedFact(
                field=fact.field,
                value=fact.value,
                source_id=view.source_id,
                raw_start=task.window_start + fact.start,
                raw_end=task.window_start + fact.end,
                label=view.label,
            )
        )
    return tuple(facts)


def legacy_complete(request: ParseRequest, model: str) -> str:
    """Actual compatibility adapter; real models require separately selected configuration."""
    from pydantic_ai.models import KnownModelName

    from camel.quarantined_llm import NotEnoughInformationError, query_quarantined_llm

    try:
        output = query_quarantined_llm(
            llm=cast(KnownModelName, model), query=request.model_dump_json(), output_schema=FactPayload, retries=0
        )
    except NotEnoughInformationError:
        return json.dumps({"schema_version": 1, "have_enough_information": False, "facts": []})
    if not hasattr(output, "have_enough_information"):
        raise ValueError("legacy_missing_completion_flag")
    return output.model_dump_json()


def run_worker(settings: ProviderSettings, request: ParseRequest, limits: ParserLimits, attempt: int, timeout: float):
    environment = os.environ.copy()
    source_root = str(Path(__file__).resolve().parents[2])
    environment["PYTHONPATH"] = source_root + (
        os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
    )
    environment.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    packet = json.dumps(
        {
            "settings": settings.model_dump(mode="json"),
            "request": request.model_dump(mode="json"),
            "attempt": attempt,
            "max_output_bytes": limits.max_output_bytes,
        },
        ensure_ascii=False,
    ).encode()
    process = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "camel.detection.worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
        try:
            output, _ = process.communicate(packet, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=1.0)
            return "TIMEOUT", None, process.poll() is not None, "worker_deadline_exceeded"
        if process.returncode != 0 or len(output) > limits.max_output_bytes * 8 + 4096:
            return "PROVIDER_ERROR", None, True, "worker_protocol_or_exit_error"
        result = json.loads(output)
        if set(result) != {"status", "payload"} or result["status"] not in {"OK", "PROVIDER_ERROR", "OUTPUT_LIMIT"}:
            return "PROVIDER_ERROR", None, True, "invalid_worker_protocol"
        return result["status"], result["payload"], True, None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return "PROVIDER_ERROR", None, process is None or process.poll() is not None, "worker_start_or_cleanup_failed"
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1.0)


def parse_bounded(
    view: ContentView, task: ParseTask, *, provider: ProviderSettings, limits: ParserLimits | None = None
) -> ParseOutcome:
    budget = limits or ParserLimits()
    started = time.monotonic()
    try:
        request = build_request(view, task, budget)
    except OverflowError:
        return ParseOutcome(
            status="INPUT_LIMIT", facts=(), attempts=(), request_sha256=None, error_code="input_budget_exceeded"
        )
    except ValueError:
        return ParseOutcome(
            status="INVALID_REQUEST",
            facts=(),
            attempts=(),
            request_sha256=None,
            error_code="invalid_source_window_or_fields",
        )
    request_hash = hashlib.sha256(request.model_dump_json().encode()).hexdigest()
    attempts = []
    status: ParseStatus = "PROVIDER_ERROR"
    error = None
    for attempt in range(1, budget.max_attempts + 1):
        remaining = budget.total_seconds - (time.monotonic() - started)
        if remaining <= 0:
            status = "TIMEOUT"
            error = "total_deadline_exceeded"
            break
        tick = time.monotonic()
        worker_status, raw, terminated, error = run_worker(
            provider, request, budget, attempt, min(budget.timeout_seconds, remaining)
        )
        status = cast(ParseStatus, worker_status)
        if not terminated:
            status = "PROVIDER_ERROR"
            error = "worker_cleanup_not_confirmed"
        elif status != "OK" and error is None:
            error = "provider_" + status.lower()
        facts = ()
        if status == "OK":
            try:
                if not isinstance(raw, str):
                    raise ValueError("provider_must_return_json_text")
                if len(raw.encode("utf-8")) > budget.max_output_bytes:
                    status = "OUTPUT_LIMIT"
                    error = "provider_output_budget_exceeded"
                else:
                    response = strict_response(raw)
                    if not response.have_enough_information and not response.facts:
                        status = "INSUFFICIENT"
                        error = "insufficient_information"
                    else:
                        facts = grounded_facts(response, request, task, view)
            except (ValidationError, ValueError, RecursionError):
                status = "INVALID_OUTPUT"
                error = "schema_or_literal_grounding_failed"
        attempts.append(
            ParseAttempt(
                number=attempt,
                status=status,
                worker_terminated=terminated,
                elapsed_seconds=time.monotonic() - tick,
                error_code=error,
            )
        )
        if status == "OK":
            return ParseOutcome(
                status="OK", facts=facts, attempts=tuple(attempts), request_sha256=request_hash, error_code=None
            )
        if status == "INSUFFICIENT":
            break
        if not terminated:
            break
    return ParseOutcome(
        status=status, facts=(), attempts=tuple(attempts), request_sha256=request_hash, error_code=error
    )
