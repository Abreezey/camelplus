"""Check real D data flow and lifecycle refresh independently of demo summaries."""

import importlib.util
from pathlib import Path

import pytest
from pydantic import ValidationError

from camel.evaluation.connected import DOCUMENT, OWNER, FlowCase, controls, run_flow
from camel.evaluation.replay import RecordingTool
from camel.memory.store import MemoryGate, digest

ROOT = Path(__file__).resolve().parents[3]


def stage(row, name):
    return next(item["value"] for item in row["stages"] if item["stage"] == name)


@pytest.fixture(scope="module")
def rows(tmp_path_factory):
    directory = tmp_path_factory.mktemp("connected")
    return {case.case_id: run_flow(case, directory / case.case_id) for case, _ in controls()}


def test_actual_retrieved_memory_fills_plan_and_recorded_payload(rows):
    row = rows["normal"]
    assert row["status"] == "RECORDED"
    initial, final = stage(row, "memory_read_B"), stage(row, "memory_refresh_C")
    bound = stage(row, "bound_plan")
    assert initial["content"] == final["content"] == bound["sources"][0]["fields"][0]["value"]
    assert row["ledger"][0]["payload"] == row["ledger"][0]["response"] == final["content"]
    assert stage(row, "recording_only")["payload_ref"] == digest(final["content"])
    assert bound["plan"]["nodes"][0]["data_slots"][0]["binding"] == dict(
        source_id="memory-entry:entry", field="memory_text"
    )


def test_trusted_contract_stays_readonly_and_separate_from_memory_text(rows):
    for row in rows.values():
        contract = stage(row, "trusted_compile")["contract"]
        assert contract["principal"] == OWNER and contract["side_effect_budget"] == 0
        assert contract["delegation"]["allowed"] is False and contract["allowed_destinations"] == []
        assert len(contract["allowed_effects"]) == 1
        assert contract["allowed_effects"][0]["effect"] == "READ"
        assert contract["allowed_effects"][0]["resource"] == DOCUMENT


def test_memory_label_and_tdg_survive_slot_binding(rows):
    bound = stage(rows["normal"], "bound_plan")
    label = bound["sources"][0]["label"]
    assert label["authority"] == "data_only" and label["execute_scopes"] == []
    assert {"host-source", "memory-entry:entry"} <= set(label["provenance"])
    validation = stage(rows["normal"], "revalidation_and_detection_C")["validation"]
    assert dict(source="source:memory-entry:entry", target="tool:read", kind="data") in validation["edges"]
    assert validation["effects"][0]["data_refs"][0]["label"] == label
    assert validation["normalization_backends"] == ["fixture_stub"]


def test_memory_outbox_spans_three_sessions_without_fabricating_c_audit(rows):
    events = rows["normal"]["memory_events"]
    assert {item[0]["session_id"] for item in events} == {"A", "B", "C"}
    write = next(item[0] for item in events if item[1]["operation"] == "write")
    reads = [item[0] for item in events if item[1]["operation"] == "read"]
    assert len(reads) == 2
    assert all(write["event_id"] in item["parent_ids"] for item in reads)


def test_memory_injection_is_quarantined_before_planning(rows):
    row = rows["memory_injection"]
    assert stage(row, "memory_write_A")["status"] == "QUARANTINED"
    assert row["status"] == "MEMORY_BLOCKED" and row["ledger"] == []
    assert "bound_plan" not in [item["stage"] for item in row["stages"]]


def test_benign_quote_false_positive_is_preserved(rows):
    assert rows["quoted_example"]["status"] == "MEMORY_BLOCKED"
    assert rows["quoted_example"]["reasons"] == ["quarantined"]


def test_zero_width_rule_miss_is_reported_without_new_tool_authority(rows):
    row = rows["zero_width_miss"]
    assert stage(row, "memory_write_A")["status"] == "STORED"
    assert stage(row, "planning_and_detection_B")["detection"]["findings"] == []
    assert stage(row, "revalidation_and_detection_C")["detection"]["findings"] == []
    assert row["status"] == "RECORDED" and len(row["ledger"]) == 1
    assert row["ledger"][0]["type"] == "READ" and row["ledger"][0]["destination"] is None
    assert "\u200b" in row["ledger"][0]["payload"]


def test_actual_document_risk_changes_a_decision_and_has_grounded_spans(rows):
    result = stage(rows["document_injection"], "planning_and_detection_B")
    assert result["validation"]["status"] == "READY"
    assert result["validation"]["explanations"][0]["decision"]["decision"] == "ALLOW"
    assert result["assessments"][0]["decision"]["decision"] == "CONFIRM"
    assert result["assessments"][0]["executable"] is False
    findings = result["detection"]["findings"]
    assert findings and all(item["evidence"]["source_id"] == "synthetic-document" for item in findings)
    assert rows["document_injection"]["ledger"] == []


@pytest.mark.parametrize(
    "name,reason",
    [
        ("expire_before_use", "expired"),
        ("quarantine_before_use", "quarantined"),
        ("tamper_before_use", "corrupt_record"),
    ],
)
def test_snapshot_that_was_ready_cannot_bypass_later_memory_state(rows, name, reason):
    row = rows[name]
    assert stage(row, "memory_read_B")["status"] == "RETURNED"
    assert stage(row, "planning_and_detection_B")["validation"]["status"] == "READY"
    assert stage(row, "planning_and_detection_B")["assessments"][0]["executable"] is True
    assert row["status"] == "REFRESH_BLOCKED" and row["reasons"] == [reason]
    assert row["ledger"] == [] and stage(row, "memory_refresh_C")["content"] is None


def test_cannot_change_resources_or_register_push_via_candidate(rows):
    assert rows["resource_expansion"]["status"] == "PLAN_BLOCKED"
    assert "resource_scope_change_requires_authorization" in rows["resource_expansion"]["reasons"]
    assert rows["unregistered_push"]["status"] == "PLAN_INVALID"
    assert rows["unregistered_push"]["reasons"] == ["unregistered_tool"]
    assert not rows["resource_expansion"]["ledger"] and not rows["unregistered_push"]["ledger"]


def test_clean_detector_cannot_erase_secret_labels_or_hard_denial(rows):
    row = rows["secret_provenance"]
    assert stage(row, "memory_read_B")["status"] == "RETURNED"
    source = stage(row, "bound_plan")["sources"][0]
    assert source["label"]["confidentiality"] == "secret" and source["label"]["data_classes"] == ["credentials"]
    assessment = stage(row, "planning_and_detection_B")
    assert assessment["detection"]["findings"] == []
    assert assessment["assessments"][0]["decision"]["decision"] == "DENY"
    assert any(
        "contract_forbidden_data_class" in reason for reason in assessment["assessments"][0]["decision"]["hard_reasons"]
    )
    assert row["ledger"] == []


def test_candidate_replacement_cannot_redefine_trusted_host_write_binding(rows):
    row = rows["binding_mismatch"]
    assert row["status"] == "WRITE_BLOCKED" and row["reasons"] == ["host_data_flow_binding_mismatch"]
    assert not any(item[1]["operation"] == "write" for item in row["memory_events"])


def test_incomplete_detection_does_not_fall_back_to_base_allow(rows):
    row = rows["detection_failure"]
    result = stage(row, "planning_and_detection_B")
    assert result["validation"]["status"] == "READY"
    assert result["detection"]["status"] == "INPUT_LIMIT"
    assert "detection_incomplete" in row["reasons"] and row["ledger"] == []


def test_unanticipated_memory_read_audit_error_propagates_without_recording(tmp_path, monkeypatch):
    recorder = RecordingTool()
    original = MemoryGate._event

    def fault(self, operation, context, now, **kwargs):
        if operation == "read" and context.session_id == "C":
            raise OSError("SYNTHETIC MEMORY READ AUDIT FAILURE")
        return original(self, operation, context, now, **kwargs)

    monkeypatch.setattr(MemoryGate, "_event", fault)
    with pytest.raises(OSError, match="AUDIT FAILURE"):
        run_flow(FlowCase(case_id="audit_failure", memory_text="public content"), tmp_path / "flow", recorder=recorder)
    assert recorder.ledger == []


def test_actual_payload_follows_new_input_instead_of_a_canned_success_response(tmp_path):
    content = "A different public value with a unique marker 314159."
    row = run_flow(FlowCase(case_id="changed_value", memory_text=content), tmp_path / "flow")
    assert row["ledger"][0]["payload"] == row["ledger"][0]["response"] == content


def test_changed_snapshot_output_is_refused_even_if_retrieval_claims_success(tmp_path, monkeypatch):
    original = MemoryGate.get

    def changed(self, entry_id, *, context, now):
        value = original(self, entry_id, context=context, now=now)
        return value.model_copy(update={"content": "SUBSTITUTED SNAPSHOT"}) if context.session_id == "C" else value

    monkeypatch.setattr(MemoryGate, "get", changed)
    row = run_flow(FlowCase(case_id="snapshot_change", memory_text="original content"), tmp_path / "flow")
    assert row["status"] == "SNAPSHOT_CHANGED" and row["ledger"] == []


@pytest.mark.parametrize("case_id", ["../escape", "/absolute", "A", "with space"])
def test_case_paths_cannot_come_from_untrusted_text(case_id):
    with pytest.raises(ValidationError):
        FlowCase(case_id=case_id, memory_text="data")


def test_no_output_reuse_or_preloaded_effect_ledger(tmp_path):
    recorder = RecordingTool()
    recorder.ledger.append({"type": "WRITE"})
    case = FlowCase(case_id="fresh", memory_text="public content")
    with pytest.raises(ValueError, match="fresh"):
        run_flow(case, tmp_path / "flow", recorder=recorder)
    assert not (tmp_path / "flow").exists()
    (tmp_path / "flow").mkdir()
    with pytest.raises(FileExistsError):
        run_flow(case, tmp_path / "flow")


def test_command_acceptance_rejects_missing_records_and_changed_payload(rows):
    import copy

    spec = importlib.util.spec_from_file_location("connected_eval_tests", ROOT / "scripts/d_connected_eval.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.check_observations(list(rows.values()))
    with pytest.raises(ValueError, match="terminal"):
        module.check_observations(list(rows.values())[1:])
    altered = copy.deepcopy(list(rows.values()))
    altered[0]["ledger"][0]["payload"] = "FAKE RESPONSE"
    with pytest.raises(ValueError, match="data_or_scope"):
        module.check_observations(altered)
