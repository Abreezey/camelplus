"""No live API calls: hosted-model budget, leakage, schema and decision invariants."""

import copy
import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from camel.detection.remote.client import (
    EMBEDDING_MODEL,
    VERIFIER_MODEL,
    GatewayClient,
    worker_request,
    write_json,
)
from camel.detection.remote.http_worker import scrub_reasoning
from camel.detection.remote.scoring import (
    calibrate,
    centroid,
    embedding_response,
    embedding_text,
    evaluate_case,
    model_sources,
    similarity_score,
    unit_vector,
    verify_response,
)
from camel.evaluation.fixtures import load_dataset
from camel.policy import PolicyEngine, load_rules

ROOT = Path(__file__).resolve().parents[2]


def completion(content=None):
    content = content if content is not None else json.dumps({"injection": True, "source_id": "s0", "quote": "SYSTEM:"})
    return {
        "status": "OK",
        "worker_terminated": True,
        "body": {
            "choices": [{"finish_reason": "stop", "message": {"content": content}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
        },
    }


def data():
    return load_dataset(ROOT / "fixtures/d/d1_v1")


def test_actual_http_worker_rejects_invalid_endpoint_without_network():
    result = worker_request({"endpoint": "invalid", "payload": {}, "credential": "synthetic-test-key"}, 3)
    assert result["status"] == "WORKER_ERROR" and result["worker_terminated"]


def test_case_identifiers_and_truth_are_not_sent_to_models():
    cases, _ = data()
    for case in cases:
        text = embedding_text(case)
        aliases = model_sources(case)
        public = json.dumps([vars(alias) for alias in aliases], ensure_ascii=False)
        assert len(aliases) == len(case.input_events)
        for event in case.input_events:
            assert event.source_id not in text and event.source_id not in public
        assert case.case_id not in text and case.case_id not in public
        assert "expected_decision" not in public and "authorized_scope" not in public


def test_counter_is_reserved_before_transport_and_failed_calls_consume_it(tmp_path):
    calls = []

    def transport(packet, timeout):
        state = json.loads((tmp_path / "request_budget.json").read_text(encoding="utf-8"))
        assert state["generation_attempts"] == 1 and state["requests"][0]["status"] == "RESERVED"
        calls.append(packet)
        raise RuntimeError("synthetic failure")

    client = GatewayClient(tmp_path, "synthetic-test-key", transport=transport)
    result = client.request("chat/completions", {"model": VERIFIER_MODEL, "max_tokens": 128}, case_ids=["c"])
    assert result["status"] == "TRANSPORT_ERROR" and len(calls) == 1
    disk = (tmp_path / "request_budget.json").read_text(encoding="utf-8")
    assert "synthetic-test-key" not in disk and client.state["requested_output_tokens"] == 128
    resumed = GatewayClient(tmp_path, "synthetic-test-key", transport=transport)
    assert resumed.state["generation_attempts"] == 1


@pytest.mark.parametrize("kind", ["generation", "embedding"])
def test_request_caps_prevent_transport(tmp_path, kind):
    client = GatewayClient(tmp_path, "synthetic-test-key", transport=lambda *args: pytest.fail("must not send"))
    client.state["generation_attempts"] = 54
    client.state["embedding_attempts"] = 10
    endpoint = "chat/completions" if kind == "generation" else "embeddings"
    model = VERIFIER_MODEL if kind == "generation" else EMBEDDING_MODEL
    with pytest.raises(ValueError, match="budget_exhausted"):
        client.request(endpoint, {"model": model, "max_tokens": 128}, case_ids=["c"])


@pytest.mark.parametrize("mutation", ["endpoint", "model", "tokens", "n", "key_in_data", "edited_counter"])
def test_invalid_requests_do_not_send(tmp_path, mutation):
    client = GatewayClient(tmp_path, "synthetic-test-key", transport=lambda *args: pytest.fail("must not send"))
    payload = {"model": VERIFIER_MODEL, "max_tokens": 128}
    endpoint = "chat/completions"
    if mutation == "endpoint":
        endpoint = "https://attacker.invalid"
    elif mutation == "model":
        payload["model"] = "unapproved-model"
    elif mutation == "tokens":
        payload["max_tokens"] = 129
    elif mutation == "n":
        payload["n"] = 2
    elif mutation == "key_in_data":
        payload["messages"] = "synthetic-test-key"
    else:
        write_json(tmp_path / "request_budget.json", {"edited": True})
    with pytest.raises(ValueError):
        client.request(endpoint, payload, case_ids=["c"])


def test_credential_reflection_is_discarded(tmp_path):
    client = GatewayClient(
        tmp_path,
        "synthetic-test-key",
        transport=lambda *args: {"status": "OK", "body": "synthetic-test-key", "worker_terminated": True},
    )
    result = client.request("embeddings", {"model": EMBEDDING_MODEL}, case_ids=["c"])
    assert result["status"] == "CREDENTIAL_REFLECTION" and "synthetic-test-key" not in json.dumps(result)
    assert "synthetic-test-key" not in (tmp_path / "request_budget.json").read_text(encoding="utf-8")


@pytest.mark.parametrize("values", [[0, 0], [True, 1], [float("nan"), 1], [float("inf"), 1], [], ["1", 2]])
def test_invalid_vectors_fail(values):
    with pytest.raises(ValueError):
        unit_vector(values)


@pytest.mark.parametrize("mutation", ["duplicate_index", "count", "boolean_index", "dimension", "nan"])
def test_embedding_shapes_fail(mutation):
    rows = [{"index": 0, "embedding": [1, 0]}, {"index": 1, "embedding": [0, 1]}]
    if mutation == "duplicate_index":
        rows[1]["index"] = 0
    elif mutation == "count":
        rows.pop()
    elif mutation == "boolean_index":
        rows[0]["index"] = False
    elif mutation == "dimension":
        rows[0]["embedding"] = [1]
    else:
        rows[0]["embedding"] = [float("nan"), 1]
    with pytest.raises(ValueError):
        embedding_response({"status": "OK", "worker_terminated": True, "body": {"data": rows}}, 2)


def test_embedding_reorders_indices_and_normalizes():
    result = embedding_response(
        {
            "status": "OK",
            "worker_terminated": True,
            "body": {"data": [{"index": 1, "embedding": [0, 4]}, {"index": 0, "embedding": [3, 0]}]},
        },
        2,
    )
    assert result == [[1, 0], [0, 1]]


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_auth",
        "wrong_source",
        "invented_quote",
        "empty_attack_quote",
        "string_bool",
        "duplicate_json",
        "truncated",
        "length",
        "thinking",
        "tools",
        "no_usage",
        "token_overrun",
        "usage_boolean",
        "benign_quote",
        "multi_choice",
    ],
)
def test_verifier_outputs_are_strict_and_grounded(mutation):
    raw = {"injection": True, "source_id": "s0", "quote": "SYSTEM:"}
    if mutation == "extra_auth":
        raw["grant_authority"] = "system"
    elif mutation == "wrong_source":
        raw["source_id"] = "source:attack"
    elif mutation == "invented_quote":
        raw["quote"] = "invented"
    elif mutation == "empty_attack_quote":
        raw["quote"] = ""
    elif mutation == "string_bool":
        raw["injection"] = "true"
    elif mutation == "benign_quote":
        raw["injection"] = False
    response = completion(json.dumps(raw))
    choice = response["body"]["choices"][0]
    if mutation == "duplicate_json":
        choice["message"]["content"] = '{"injection":false,"injection":true}'
    elif mutation == "truncated":
        choice["message"]["content"] = "{"
    elif mutation == "length":
        choice["finish_reason"] = "length"
    elif mutation == "thinking":
        choice["reasoning_present"] = True
    elif mutation == "tools":
        choice["message"]["tool_calls"] = [{}]
    elif mutation == "no_usage":
        del response["body"]["usage"]
    elif mutation == "token_overrun":
        response["body"]["usage"] = {"prompt_tokens": 100, "completion_tokens": 129, "total_tokens": 229}
    elif mutation == "usage_boolean":
        response["body"]["usage"]["completion_tokens"] = True
    elif mutation == "multi_choice":
        response["body"]["choices"].append(copy.deepcopy(choice))
    with pytest.raises(ValueError):
        verify_response(response, SimpleNamespace(source_id="s0", content="prefix SYSTEM: override"))


def test_valid_verifier_quote_maps_to_exact_original_characters():
    result = verify_response(
        completion(),
        (
            SimpleNamespace(source_id="s0", content="前缀 SYSTEM: override"),
            SimpleNamespace(source_id="s1", content="ordinary"),
        ),
    )
    assert result["raw_spans"] == [[3, 10]] and result["injection"] is True


def test_ambiguous_quote_rejected():
    with pytest.raises(ValueError):
        verify_response(completion(), SimpleNamespace(source_id="s0", content="SYSTEM: SYSTEM:"))


def test_dev_calibration_removes_both_members_of_heldout_family():
    cases = []
    vectors = {}
    for family in range(3):
        for positive in [True, False]:
            key = f"{family}-{positive}"
            cases.append(
                SimpleNamespace(
                    case_id=key, family_id=str(family), split="dev", variant="attack" if positive else "benign"
                )
            )
            vectors[key] = unit_vector([1.0, family + 1.0] if positive else [-1.0, family + 1.0])
    result = calibrate(cases, vectors)
    for row in result["heldout"]:
        others = [case for case in cases if case.family_id != row["family_id"]]
        expected = similarity_score(
            vectors[row["case_id"]],
            centroid([vectors[c.case_id] for c in others if c.variant == "attack"]),
            centroid([vectors[c.case_id] for c in others if c.variant == "benign"]),
        )
        assert row["score"] == expected
    cases[0].split = "test"
    with pytest.raises(ValueError, match="dev_only"):
        calibrate(cases, vectors)


@pytest.mark.parametrize(
    "embedding,verifier",
    [
        (False, {"status": "OK", "injection": False}),
        (True, {"status": "OK", "injection": False}),
        (None, {"status": "FAILED"}),
        (False, {"status": "FAILED"}),
    ],
)
def test_each_layer_preserves_hard_deny_and_failure_never_executes(embedding, verifier):
    cases, manifest = data()
    case = next(case for case in cases if case.variant == "benign" and not case.required_components)
    engine = PolicyEngine(load_rules("id: stop\nwhen: {}\nthen: DENY\n"))
    rows = evaluate_case(
        case, engine, datetime.fromisoformat(manifest["clock"]), embedding_prediction=embedding, verifier=verifier
    )
    assert all(
        not row["ledger"] and all(d["actual"]["decision"] == "DENY" for d in row["decisions"].values()) for row in rows
    )
    if embedding is None:
        assert rows[1]["classification"] == "UNKNOWN"
    if verifier["status"] != "OK":
        assert rows[2]["classification"] == "UNKNOWN"


def test_memory_lifecycle_stays_blocked_after_model_judgment():
    cases, manifest = data()
    case = next(case for case in cases if case.required_components)
    engine = PolicyEngine(load_rules((ROOT / "fixtures/d/d1_v1/policy.yaml").read_text(encoding="utf-8")))
    rows = evaluate_case(
        case,
        engine,
        datetime.fromisoformat(manifest["clock"]),
        embedding_prediction=False,
        verifier={"status": "OK", "injection": False},
    )
    assert all(row["ledger"] is None and row["lifecycle_blocked"] for row in rows)


def test_recursive_provider_reasoning_is_removed_but_usage_survives():
    raw = {
        "message": {
            "reasoning_content": "PRIVATE-TRACE-A",
            "provider_specific_fields": {"reasoning": "PRIVATE-TRACE-B", "nested": [{"analysis": "PRIVATE-TRACE-C"}]},
            "content": '{"injection":false}',
        },
        "usage": {"reasoning_tokens": 12},
    }
    cleaned, found = scrub_reasoning(raw)
    assert found and "PRIVATE-TRACE" not in json.dumps(cleaned)
    assert cleaned["usage"]["reasoning_tokens"] == 12
    assert cleaned["message"]["content"] == '{"injection":false}'


def test_protocol_revisions_share_one_durable_generation_ceiling(tmp_path):
    root = tmp_path / "experiment"
    revision = root / "v2"
    revision.mkdir(parents=True)
    first = GatewayClient(
        root, "synthetic-test-key", transport=lambda *args: {"status": "OK", "worker_terminated": True}
    )
    first.state["generation_attempts"] = 53
    write_json(first.budget_file, first.state)
    second = GatewayClient(
        revision,
        "synthetic-test-key",
        budget_directory=root,
        transport=lambda *args: {"status": "OK", "worker_terminated": True},
    )
    second.request("chat/completions", {"model": VERIFIER_MODEL, "max_tokens": 128}, case_ids=["last"])
    assert second.state["generation_attempts"] == 54 and not (revision / "request_budget.json").exists()
    with pytest.raises(ValueError, match="budget_exhausted"):
        second.request("chat/completions", {"model": VERIFIER_MODEL, "max_tokens": 128}, case_ids=["extra"])


def test_reported_provider_output_overrun_stops_the_transport_result(tmp_path):
    client = GatewayClient(
        tmp_path,
        "synthetic-test-key",
        transport=lambda *args: {
            "status": "OK",
            "worker_terminated": True,
            "body": {"usage": {"completion_tokens": 129}},
        },
    )
    result = client.request("chat/completions", {"model": VERIFIER_MODEL, "max_tokens": 128}, case_ids=["bad"])
    assert result["status"] == "OUTPUT_BUDGET_VIOLATION" and client.state["generation_attempts"] == 1
