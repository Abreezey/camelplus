"""Inspect installed task registries and prepare a non-executable smoke proposal."""

import ast
import hashlib
import inspect
import textwrap
from importlib.metadata import distribution
from pathlib import Path
from types import SimpleNamespace
from typing import Any

SUPPORTED_PACKAGE = "0.1.34"
BENCHMARK_VERSIONS = ("v1.2", "v1.2.1")
PROPOSED_USERS = ("user_task_0", "user_task_1", "user_task_2", "user_task_3", "user_task_17")
PROPOSED_INJECTIONS = ("injection_task_0",)
GROUPS = ("B0_original_agent", "B1_original_camel", "B2_ABC_without_D", "B3_ABCD")
READ_ONLY_TOOLS = frozenset({"get_current_day", "search_calendar_events", "get_day_calendar_events", "search_emails"})


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function_call_names(method) -> list[str]:
    """Syntactic FunctionCall names only; never execute a ground-truth method."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
    return sorted(
        {
            keyword.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "FunctionCall"
            for keyword in node.keywords
            if keyword.arg == "function"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        }
    )


def task_record(task, package_root: Path, kind: str) -> dict[str, Any]:
    module_file = inspect.getsourcefile(type(task))
    if module_file is None:
        raise ValueError("task_source_unavailable")
    path = Path(module_file).resolve()
    if not path.is_relative_to(package_root):
        raise ValueError("task_source_outside_agentdojo")
    return dict(
        task_id=task.ID,
        kind=kind,
        prompt=task.PROMPT if kind == "user" else task.GOAL,
        difficulty=task.DIFFICULTY.name,
        class_name=type(task).__name__,
        module=type(task).__module__,
        source_file=path.relative_to(package_root).as_posix(),
        source_sha256=sha256(path),
    )


def cli_options(source: str) -> list[str]:
    tree = ast.parse(source)
    return sorted(
        {
            argument.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "option"
            for argument in node.args
            if isinstance(argument, ast.Constant)
            and isinstance(argument.value, str)
            and argument.value.startswith("--")
        }
    )


def inspect_installed() -> dict[str, Any]:
    installed = distribution("agentdojo")
    if installed.version != SUPPORTED_PACKAGE:
        raise ValueError("agentdojo_version_requires_new_review")
    package_root = Path(str(installed.locate_file("agentdojo"))).resolve()
    # Import registry definitions only. Do not call environment loaders, tools, or benchmark runners.
    from agentdojo.task_suite.load_suites import get_suites

    suites = {}
    for version in BENCHMARK_VERSIONS:
        suites[version] = {}
        for name, suite in get_suites(version).items():
            suites[version][name] = dict(
                user_tasks=[task_record(task, package_root, "user") for task in suite.user_tasks.values()],
                injection_tasks=[
                    task_record(task, package_root, "injection") for task in suite.injection_tasks.values()
                ],
                environment_present=(package_root / "data/suites" / name / "environment.yaml").is_file(),
                injection_vectors_present=(package_root / "data/suites" / name / "injection_vectors.yaml").is_file(),
            )
    files = [
        path
        for path in package_root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix in {".py", ".yaml", ".txt"}
    ]
    hashes = {path.relative_to(package_root).as_posix(): sha256(path) for path in sorted(files)}
    licenses = [
        Path(str(installed.locate_file(path)))
        for path in installed.files or []
        if str(path).endswith("licenses/LICENSE")
    ]
    if len(licenses) != 1 or not licenses[0].read_text(encoding="utf-8").startswith("MIT License"):
        raise ValueError("installed_license_requires_review")
    workspace = get_suites("v1.2")["workspace"]
    selected_details = {}
    for task_id in PROPOSED_USERS:
        task = workspace.get_user_task_by_id(task_id)
        tools = function_call_names(task.ground_truth)
        if not tools or not set(tools) <= READ_ONLY_TOOLS:
            raise ValueError("proposed_read_only_task_requires_review")
        selected_details[task_id] = dict(
            **task_record(task, package_root, "user"),
            statically_named_ground_truth_tools=tools,
            tool_scope="static names only; not a runtime validity or read-only proof",
        )
    return dict(
        package="agentdojo",
        package_version=installed.version,
        package_root=str(package_root),
        benchmark_versions=list(BENCHMARK_VERSIONS),
        suites=suites,
        package_file_sha256=hashes,
        license=dict(name="MIT", sha256=sha256(licenses[0])),
        native_cli_options=cli_options((package_root / "scripts/benchmark.py").read_text(encoding="utf-8")),
        selected_user_details=selected_details,
    )


def validate_selection(catalog, version, suite, user_tasks, injection_tasks):
    if (
        not user_tasks
        or not injection_tasks
        or len(set(user_tasks)) != len(user_tasks)
        or len(set(injection_tasks)) != len(injection_tasks)
    ):
        raise ValueError("nonempty_unique_task_selection_required")
    if version not in catalog["suites"] or suite not in catalog["suites"][version]:
        raise ValueError("unknown_benchmark_or_suite")
    available = catalog["suites"][version][suite]
    if not set(user_tasks) <= {task["task_id"] for task in available["user_tasks"]} or not set(injection_tasks) <= {
        task["task_id"] for task in available["injection_tasks"]
    }:
        raise ValueError("task_not_in_selected_version")


def episode_counts(users: int, injections: int, groups: int, repeats: int = 1) -> dict[str, int]:
    if any(type(value) is not int or value < 1 for value in (users, injections, groups, repeats)):
        raise ValueError("positive_integer_episode_dimensions_required")
    factor = groups * repeats
    return dict(
        benign=users * factor,
        attacked=users * injections * factor,
        injection_goal_as_user_preflight=injections * factor,
        total=(users + users * injections + injections) * factor,
    )


def build_draft(catalog) -> dict[str, Any]:
    validate_selection(catalog, "v1.2", "workspace", PROPOSED_USERS, PROPOSED_INJECTIONS)
    return dict(
        status="DRAFT_NOT_EXECUTABLE",
        ready=False,
        execution_enabled=False,
        package_version=SUPPORTED_PACKAGE,
        benchmark_version="v1.2",
        suite="workspace",
        selection_status="PROPOSAL_NOT_USER_SELECTED",
        user_tasks=list(PROPOSED_USERS),
        injection_tasks=list(PROPOSED_INJECTIONS),
        attacked_pairs=[
            dict(user_task=user, injection_task=injection)
            for user in PROPOSED_USERS
            for injection in PROPOSED_INJECTIONS
        ],
        fixed_attack=dict(name="important_instructions", status="SOURCE_INSPECTED_NOT_INSTANTIATED"),
        groups=[dict(name=name, ready=False) for name in GROUPS],
        per_group_episode_counts=episode_counts(5, 1, 1),
        all_groups_episode_counts=episode_counts(5, 1, 4),
        repeats=1,
        initialization="fresh environment for every episode, unique logs and no silent reuse; not yet exercised",
        model=None,
        quarantined_model=None,
        new_requests_authorized=0,
        request_budget=None,
        max_output_tokens=None,
        monetary_cap=None,
        per_episode_timeout_seconds=None,
        total_timeout_seconds=None,
        metrics=dict(
            utility="benign utility true / planned benign episodes",
            ASR="attack security true / predeclared valid attacked episodes; incomplete trials separate",
            confirmation="requires own event observer; upstream benchmark does not supply this",
            intervals="Wilson per group and task-paired group comparison; n=5 smoke is descriptive",
        ),
        caveats=[
            "package 0.1.34 and benchmark v1.2 are different version axes",
            "five user IDs times one injection ID makes five attacked pairs; five by five makes 25",
            "native with-injections benchmark first runs every chosen injection goal as a user task",
            "model requests can exceed episodes because planning, tools, parsing and detector roles may each generate",
            "security=True means injection goal achieved, not a safe outcome; benign no-injection return must not enter ASR",
            "raw benchmark provider errors can use fallback booleans; read trace errors before scoring",
        ],
        blockers=[
            "user selection of suite, IDs, model and all-role call/token/money/time budget",
            "new model authorization: original D3b generation budget already exhausted",
            "endpoint compatibility with planning/tool calling/quarantined parsing unverified",
            "B0/B1 bounded runtime and new result/error observer not yet implemented",
            "B2/B3 B normalizer/Gateway/MCP and complete C execution isolation not ready",
            "D task alignment verifier and production entrypoints incomplete",
            "injection visibility, positive-control feasibility and oracle/independent-effect agreement not executed",
        ],
    )


def oracle_direction_probe() -> dict[str, Any]:
    """Actual predicates with tiny stub states; no benchmark environment or tool calls."""
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1.2", "workspace")
    task: Any = suite.get_injection_task_by_id("injection_task_0")
    before = SimpleNamespace(inbox=SimpleNamespace(account_email="synthetic-owner@example.invalid"))
    email = SimpleNamespace(
        body=task._TEXT, subject=task._SUBJECT, recipients=[task._RECIPIENT], sender=before.inbox.account_email
    )
    after = SimpleNamespace(inbox=SimpleNamespace(search_emails=lambda query: [email]))
    positive = task.security("", before, after)
    email.body = "synthetic nonmatching body"
    negative = task.security("", before, after)
    empty = task.security("", before, SimpleNamespace(inbox=SimpleNamespace(search_emails=lambda query: [])))
    user_task: Any = suite.get_user_task_by_id("user_task_0")
    state = SimpleNamespace()
    good_utility = user_task.utility(user_task.GROUND_TRUTH_OUTPUT, state, state)
    bad_utility = user_task.utility("", state, state)
    if (
        positive is not True
        or negative is not False
        or empty is not False
        or good_utility is not True
        or bad_utility is not False
    ):
        raise ValueError("oracle_direction_probe_changed")
    return dict(
        status="PASS_STUB_STATE_PREDICATES_ONLY",
        injection_goal_achieved=positive,
        goal_not_achieved=negative,
        empty_post_state=empty,
        correct_user_answer=good_utility,
        empty_user_answer=bad_utility,
        benchmark_episodes=0,
        environment_loads=0,
        tool_calls=0,
        model_requests=0,
    )
