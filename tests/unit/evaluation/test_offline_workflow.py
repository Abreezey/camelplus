"""A runnable D workflow must preserve failed runs and reject incomplete evidence."""

import importlib.util
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts/d_offline_acceptance.py"
SPEC = importlib.util.spec_from_file_location("d_offline_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)


def test_existing_output_is_preserved(tmp_path):
    target = tmp_path / "artifacts/d/existing"
    target.mkdir(parents=True)
    keep = target / "receipt.json"
    keep.write_bytes(b"preserve existing evidence")
    with pytest.raises(ValueError, match="fresh_output"):
        workflow.output_path(target, tmp_path)
    assert keep.read_bytes() == b"preserve existing evidence"


def test_output_cannot_escape_through_parent_path(tmp_path):
    with pytest.raises(ValueError, match="fresh_output"):
        workflow.output_path(tmp_path / "artifacts/d/../../outside", tmp_path)
    assert not (tmp_path / "outside").exists()


def test_child_failure_keeps_exit_code_and_actual_log(tmp_path):
    command = [sys.executable, "-c", "import sys; print('synthetic failure'); sys.exit(7)"]
    receipt = workflow.run_step("failure", command, tmp_path, dict(os.environ))
    assert receipt["status"] == "FAILED"
    assert receipt["exit_code"] == 7
    assert "synthetic failure" in (tmp_path / "failure.log").read_text()


def test_child_timeout_does_not_become_success(tmp_path):
    command = [sys.executable, "-c", "import time; time.sleep(5)"]
    receipt = workflow.run_step("timeout", command, tmp_path, dict(os.environ), timeout=0.05)
    assert receipt["status"] == "TIMEOUT"
    assert receipt["exit_code"] is None
    assert receipt["error"] == "child_time_budget_exceeded"


def test_missing_child_executable_keeps_failure_receipt(tmp_path):
    receipt = workflow.run_step("missing", [str(tmp_path / "no_such_executable")], tmp_path, dict(os.environ))
    assert receipt["status"] == "FAILED"
    assert receipt["error"] == "FileNotFoundError"


def xml_report(tmp_path, problem=None):
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for group in workflow.TEST_GROUPS:
        if problem == "missing_group" and group == "memory":
            continue
        case = ET.SubElement(suite, "testcase", classname=f"tests.unit.{group}.test_synthetic", name=f"test_{group}")
        if group == "planner" and problem in {"failure", "error", "skipped"}:
            ET.SubElement(case, problem)
    if problem == "empty":
        suite.clear()
    path = tmp_path / "results.xml"
    ET.ElementTree(root).write(path, encoding="utf-8")
    return path


def test_every_selected_test_group_needs_executed_cases(tmp_path):
    result = workflow.unit_results(xml_report(tmp_path))
    assert result["passed"] == len(workflow.TEST_GROUPS)
    assert all(value == 1 for value in result["groups"].values())


@pytest.mark.parametrize("problem", ["missing_group", "empty", "failure", "error", "skipped"])
def test_zero_exit_is_not_sufficient_for_incomplete_unit_artifacts(tmp_path, problem):
    with pytest.raises(ValueError, match="incomplete_or_failed"):
        workflow.unit_results(xml_report(tmp_path, problem))


def test_duplicate_example_ids_rejected():
    with pytest.raises(ValueError, match="duplicate_demo_record"):
        workflow.index_rows([dict(case_id="same"), dict(case_id="same")], "case_id")
