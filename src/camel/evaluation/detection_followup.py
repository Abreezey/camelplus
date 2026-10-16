"""Newly authored paired detector scenarios; no task or tool execution."""

import hashlib
import json
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from camel.core import TrustLabel
from camel.core.labels import Authority, Confidentiality, Integrity
from camel.detection.models import identity_view
from camel.detection.rules import detect, predicted_attack
from camel.evaluation.ablation import wilson
from camel.evaluation.replay import stable

MECHANISMS = (
    "authority_laundering",
    "workflow_hijack",
    "evidence_tamper",
    "exfiltration",
    "cross_source",
    "answer_contamination",
)
SOURCES = ("web", "document", "mail_issue", "tool_result", "tool_description", "memory")
SPLITS = ("dev", "validation", "test")


class Case(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    case_id: str = Field(min_length=1, max_length=128)
    variant: Literal["attack", "benign"]
    text: str = Field(min_length=1, max_length=4000)
    truth_rationale: str = Field(min_length=1)


class Pair(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    group_id: str = Field(min_length=1, max_length=128)
    split: Literal["dev", "validation", "test"]
    mechanism: Literal[
        "authority_laundering",
        "workflow_hijack",
        "evidence_tamper",
        "exfiltration",
        "cross_source",
        "answer_contamination",
    ]
    source_type: Literal["web", "document", "mail_issue", "tool_result", "tool_description", "memory"]
    task: str = Field(min_length=1)
    authorized_actions: tuple[str, ...] = Field(min_length=1)
    forbidden_action: str = Field(min_length=1)
    cases: tuple[Case, ...] = Field(min_length=2, max_length=2)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized(text: str) -> str:
    return "".join(char for char in unicodedata.normalize("NFKC", text).casefold() if not char.isspace())


def grams(text: str) -> set[str]:
    compact = "".join(char for char in normalized(text) if char.isalnum())
    return {compact[i : i + 3] for i in range(max(0, len(compact) - 2))}


def validate_pairs(pairs: tuple[Pair, ...], old_texts: tuple[str, ...]) -> None:
    if len(pairs) != 36 or len({pair.group_id for pair in pairs}) != 36:
        raise ValueError("requires_36_unique_groups")
    seen_ids, seen_texts = set(), {normalized(text) for text in old_texts}
    for pair in pairs:
        if {case.variant for case in pair.cases} != {"attack", "benign"}:
            raise ValueError("requires_one_attack_and_one_benign")
        if (
            not pair.task.strip()
            or not pair.forbidden_action.strip()
            or any(not a.strip() for a in pair.authorized_actions)
        ):
            raise ValueError("empty_task_or_scope")
        for case in pair.cases:
            text = normalized(case.text)
            if not text or not case.truth_rationale.strip() or text in seen_texts or case.case_id in seen_ids:
                raise ValueError("duplicate_or_empty_case")
            seen_ids.add(case.case_id)
            seen_texts.add(text)
    for split in SPLITS:
        members = [pair for pair in pairs if pair.split == split]
        if len(members) != 12:
            raise ValueError("requires_12_pairs_per_split")
        if Counter(pair.mechanism for pair in members) != Counter(dict.fromkeys(MECHANISMS, 2)):
            raise ValueError("mechanism_split_imbalance")
        if Counter(pair.source_type for pair in members) != Counter(dict.fromkeys(SOURCES, 2)):
            raise ValueError("source_split_imbalance")


def load_pairs(root: Path) -> tuple[tuple[Pair, ...], dict, tuple[tuple[str, str], ...]]:
    folder = root / "tests/fixtures/d/detection_v2"
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if (
        manifest["version"] != "d_detection_scenarios_v2"
        or manifest["pairs_sha256"] != digest(folder / "pairs.json")
        or manifest["pairs"] != 36
        or manifest["cases"] != 72
        or manifest["pairs_per_split"] != dict.fromkeys(SPLITS, 12)
    ):
        raise ValueError("dataset_manifest_mismatch")
    expected_protocols = {
        "docs/d/D_detection_followup_protocol.md",
        "docs/d/evidence/D_detection_followup_protocol.json",
    }
    if set(manifest["protocol_sha256"]) != expected_protocols:
        raise ValueError("protocol_manifest_mismatch")
    for name in expected_protocols:
        if digest(root / name) != manifest["protocol_sha256"][name]:
            raise ValueError("protocol_digest_mismatch")
    if set(manifest["old_fixture_sha256"]) != {"cases.jsonl", "manifest.json", "policy.yaml"}:
        raise ValueError("old_fixture_manifest_mismatch")
    for name, expected in manifest["old_fixture_sha256"].items():
        if digest(root / "tests/fixtures/d/d1_v1" / name) != expected:
            raise ValueError("old_fixture_changed")
    old_sources = tuple(
        (event["source_id"], event["content"])
        for line in (root / "tests/fixtures/d/d1_v1/cases.jsonl").read_text(encoding="utf-8").splitlines()
        for event in json.loads(line)["input_events"]
    )
    pairs = TypeAdapter(tuple[Pair, ...]).validate_json((folder / "pairs.json").read_bytes())
    validate_pairs(pairs, tuple(text for _, text in old_sources))
    return pairs, manifest, old_sources


def nearest_neighbors(pairs: tuple[Pair, ...], old_sources: tuple[tuple[str, str], ...]) -> list[dict]:
    """Descriptive overlap audit, never a claim of semantic independence."""
    entries = [(case.case_id, pair.group_id, pair.split, case.text) for pair in pairs for case in pair.cases]
    old = [(source, "old", "old", text) for source, text in old_sources]
    vectors = {key: grams(text) for key, _, _, text in entries + old}
    rows = []
    for key, group, split, _ in entries:
        vector = vectors[key]
        row: dict[str, Any] = dict(case_id=key)
        for scope, candidates in (
            ("old", old),
            ("new_other_group", [entry for entry in entries if entry[1] != group]),
            ("new_other_split", [entry for entry in entries if entry[2] != split]),
        ):
            ranked = []
            for other, _, _, _ in candidates:
                union = vector | vectors[other]
                score = len(vector & vectors[other]) / len(union) if union else 0.0
                ranked.append((score, other))
            score, other = sorted(ranked, key=lambda item: (-item[0], item[1]))[0]
            row[scope] = dict(case_id=other, jaccard=score)
        rows.append(row)
    return rows


def observe(pair: Pair, case: Case) -> dict:
    source_id = "source:" + case.case_id
    label = TrustLabel(
        schema_version=1,
        provenance=frozenset({source_id}),
        integrity=Integrity.UNTRUSTED,
        confidentiality=Confidentiality.PUBLIC,
        authority=Authority.DATA_ONLY,
        execute_scopes=frozenset(),
        readers=None,
        data_classes=frozenset(),
    )
    view = identity_view(source_id, pair.source_type, case.text, label)
    result = detect((view,))
    for finding in result.findings:
        evidence = finding.evidence
        if (
            evidence.source_id != source_id
            or evidence.view != "raw"
            or not 0 <= evidence.start < evidence.end <= len(case.text)
            or evidence.raw_spans != ((evidence.start, evidence.end),)
        ):
            raise RuntimeError("ungrounded_detector_evidence")
    return dict(
        case_id=case.case_id,
        group_id=pair.group_id,
        split=pair.split,
        source_type=pair.source_type,
        mechanism=pair.mechanism,
        variant=case.variant,
        prediction=predicted_attack(result),
        detection=stable(result),
    )


def metrics(rows: list[dict]) -> dict:
    if not rows or len({row["case_id"] for row in rows}) != len(rows):
        raise ValueError("nonempty_unique_population_required")
    counts = Counter(dict.fromkeys(("TP", "FP", "FN", "TN", "attack_unknown", "benign_unknown"), 0))
    for row in rows:
        prediction, variant = row["prediction"], row["variant"]
        if variant not in {"attack", "benign"} or (prediction is not None and type(prediction) is not bool):
            raise ValueError("invalid_prediction_or_truth")
        key = (
            variant + "_unknown"
            if prediction is None
            else (("TP" if prediction else "FN") if variant == "attack" else ("FP" if prediction else "TN"))
        )
        counts[key] += 1
    attacks = sum(row["variant"] == "attack" for row in rows)
    benign = len(rows) - attacks
    return dict(
        cases=len(rows),
        groups=len({row["group_id"] for row in rows}),
        counts=dict(counts),
        precision=wilson(counts["TP"], counts["TP"] + counts["FP"]),
        end_to_end_recall=wilson(counts["TP"], attacks),
        benign_false_positive_rate=wilson(counts["FP"], benign),
        benign_unflagged_rate=wilson(counts["TN"], benign),
        errors=[
            row["case_id"]
            for row in rows
            if row["prediction"] is None or row["prediction"] != (row["variant"] == "attack")
        ],
        benign_task_completion=None,
        agent_asr=None,
    )
