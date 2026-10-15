"""Positive D5 subchain invariants; negative acceptance results live in d5_eval."""

import pytest

from camel.evaluation.integration import SCENARIOS, run_probe

# These have unresolved acceptance invariants. They are NOT skipped tests or
# converted to success: scripts/d5_eval.py runs them and exits 1 on failure.
OPEN_ACCEPTANCE_CASES = {"execution_audit_fault"}


@pytest.mark.parametrize("scenario", [name for name in SCENARIOS if name not in OPEN_ACCEPTANCE_CASES])
def test_available_subchain_invariant(scenario, tmp_path):
    result, trace = run_probe(scenario, tmp_path / scenario)
    assert result["status"] == "PASS", result
    assert result["assertions"]
    assert "edges" in trace


def test_unknown_probe_refused_before_filesystem_changes(tmp_path):
    with pytest.raises(ValueError, match="unknown_d5_scenario"):
        run_probe("unregistered-probe", tmp_path / "probe")
    assert not (tmp_path / "probe").exists()
