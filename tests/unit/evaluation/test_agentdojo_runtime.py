from pathlib import Path

import pytest
from agentdojo.task_suite import get_suite

from camel.adapters.agentdojo.runtime import AgentDojoGatewayRuntime, suite_bindings


@pytest.mark.parametrize(
    "suite_name,read_tool,write_tool",
    [
        ("workspace", "search_emails", "send_email"),
        ("travel", "get_hotels_prices", "reserve_hotel"),
        ("banking", "get_balance", "send_money"),
        ("slack", "get_channels", "post_webpage"),
        ("slack", "get_webpage", "send_channel_message"),
    ],
)
def test_suite_tool_inventory_is_fully_reviewed(suite_name: str, read_tool: str, write_tool: str):
    suite = get_suite("v1.2", suite_name)
    bindings = suite_bindings(suite_name, suite.tools)
    assert set(bindings) == {function.name for function in suite.tools}
    assert bindings[read_tool].effects[0].type.value == "READ"
    assert bindings[write_tool].effects[0].type.value == "WRITE"


def test_gateway_runtime_allows_reads_detects_results_and_withholds_side_effects(tmp_path: Path):
    suite = get_suite("v1.2", "workspace")
    environment = suite.load_and_inject_default_environment({})
    runtime = AgentDojoGatewayRuntime(
        suite.tools,
        root=tmp_path / "runtime",
        model_version="deepseek-flash",
        session_id="test-session",
    )
    try:
        day, error = runtime.run_function(environment, "get_current_day", {})
        assert error is None and isinstance(day, str)
        events, error = runtime.run_function(environment, "get_day_calendar_events", {"day": "2024-05-15"})
        assert error is None and isinstance(events, list) and len(events) == 3
        files, error = runtime.run_function(environment, "list_files", {})
        assert error is None and isinstance(files, list) and len(files) == 26
        denied, error = runtime.run_function(
            environment,
            "send_email",
            {
                "recipients": ["attacker@example.invalid"],
                "subject": "blocked",
                "body": "blocked",
            },
        )
        assert denied == "Tool call blocked by security policy (CONFIRM)." and error is None
        summary = runtime.summary()
        assert summary["audit_events"] >= 12
        assert summary["detection_results"] == 3
        assert summary["decisions"] == {"ALLOW": 3, "CONFIRM": 1, "DENY": 0}
        assert "decision" in summary["audit_sources"]
        assert summary["manifest_digest"].startswith("sha256:")
    finally:
        runtime.close()


def test_gateway_runtime_can_approve_a_trusted_benign_write(tmp_path: Path):
    suite = get_suite("v1.2", "workspace")
    environment = suite.load_and_inject_default_environment({})
    runtime = AgentDojoGatewayRuntime(
        suite.tools,
        root=tmp_path / "runtime",
        model_version="deepseek-flash",
        session_id="benign-session",
        auto_approve_writes=True,
    )
    try:
        sent, error = runtime.run_function(
            environment,
            "send_email",
            {
                "recipients": ["friend@gmail.com"],
                "subject": "benign",
                "body": "expected",
            },
        )
        assert error is None
        assert getattr(sent, "subject", None) == "benign"  # FunctionReturnType union; send_email returns Email
        summary = runtime.summary()
        assert summary["decisions"] == {"ALLOW": 0, "CONFIRM": 2, "DENY": 0}
        assert summary["confirmations"] == {"requested": 1, "approved": 1, "denied": 0}
    finally:
        runtime.close()


def test_nonworkspace_gateway_runtime_allows_reviewed_read(tmp_path: Path):
    suite = get_suite("v1.2", "banking")
    environment = suite.load_and_inject_default_environment({})
    runtime = AgentDojoGatewayRuntime(
        suite.tools,
        root=tmp_path / "runtime",
        model_version="deepseek-flash",
        session_id="banking-session",
        suite="banking",
    )
    try:
        balance, error = runtime.run_function(environment, "get_balance", {})
        assert error is None and isinstance(balance, float | int)
        assert runtime.summary()["decisions"] == {"ALLOW": 1, "CONFIRM": 0, "DENY": 0}
        assert runtime.transport.manifest.identity == "agentdojo:banking:0.1.34:v1.2"
    finally:
        runtime.close()
