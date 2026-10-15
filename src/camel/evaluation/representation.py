"""Seed-derived text stress tests for frozen D rules, without tool execution."""

import base64
import math
import random
from collections import Counter
from dataclasses import dataclass
from typing import Any

from camel.detection.models import identity_view
from camel.detection.rules import detect, predicted_attack
from camel.evaluation.ablation import join_sources, wilson
from camel.evaluation.fixtures import Scenario
from camel.evaluation.replay import stable

VARIANTS = (
    "identity",
    "ascii_case_swap",
    "fullwidth",
    "zero_width",
    "character_spacing",
    "comment_wrapper",
    "base64_wrapper",
    "long_prefix",
)
COMMENT_PREFIX, COMMENT_SUFFIX = "/* source excerpt\n", "\n*/"
ENCODED_PREFIX, ENCODED_SUFFIX = '<encoded-source encoding="base64">', "</encoded-source>"
LONG_PREFIX = "背景记录\uff1a天气晴朗\uff0c编号固定。\n" * 700
CASE_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


@dataclass(frozen=True)
class Mutation:
    variant: str
    text: str
    # Only generated fullwidth positions are reversed; existing fullwidth text survives.
    reverse_edits: tuple[tuple[int, str], ...] = ()

    def recover(self) -> str:
        if self.variant == "identity":
            return self.text
        if self.variant == "ascii_case_swap":
            return self.text.translate(CASE_TABLE)
        if self.variant == "fullwidth":
            chars = list(self.text)
            for index, original in self.reverse_edits:
                chars[index] = original
            return "".join(chars)
        if self.variant in {"zero_width", "character_spacing"}:
            return self.text[::2]
        if self.variant == "comment_wrapper":
            return self.text[len(COMMENT_PREFIX) : -len(COMMENT_SUFFIX)]
        if self.variant == "base64_wrapper":
            payload = self.text[len(ENCODED_PREFIX) : -len(ENCODED_SUFFIX)]
            return base64.b64decode(payload, validate=True).decode("utf-8")
        if self.variant == "long_prefix":
            return self.text[len(LONG_PREFIX) :]
        raise ValueError("unknown_representation_variant")


def mutate(text: str, variant: str) -> Mutation:
    if variant == "identity":
        value = Mutation(variant, text)
    elif variant == "ascii_case_swap":
        value = Mutation(variant, text.translate(CASE_TABLE))
    elif variant == "fullwidth":
        edits = tuple((i, char) for i, char in enumerate(text) if 0x20 <= ord(char) <= 0x7E)
        value = Mutation(
            variant,
            "".join(
                "\u3000" if char == " " else chr(ord(char) + 0xFEE0) if 0x21 <= ord(char) <= 0x7E else char
                for char in text
            ),
            edits,
        )
    elif variant in {"zero_width", "character_spacing"}:
        value = Mutation(variant, ("\u200b" if variant == "zero_width" else " ").join(text))
    elif variant == "comment_wrapper":
        value = Mutation(variant, COMMENT_PREFIX + text + COMMENT_SUFFIX)
    elif variant == "base64_wrapper":
        value = Mutation(variant, ENCODED_PREFIX + base64.b64encode(text.encode()).decode("ascii") + ENCODED_SUFFIX)
    elif variant == "long_prefix":
        value = Mutation(variant, LONG_PREFIX + text)
    else:
        raise ValueError("unknown_representation_variant")
    if value.recover() != text:
        raise ValueError("mutation_roundtrip_failed")
    return value


def observe(case: Scenario, variant: str) -> dict[str, Any]:
    labels, original_views = join_sources(case)
    views, sources = [], []
    for original in original_views:
        mutation = mutate(original.raw_text, variant)
        view = identity_view(original.source_id, original.source_type, mutation.text, original.label)
        views.append(view)
        sources.append(
            dict(
                source_id=original.source_id,
                original_text=original.raw_text,
                transformed_text=mutation.text,
                changed=mutation.text != original.raw_text,
                reverse_edits=mutation.reverse_edits,
                label=stable(view.label),
                roundtrip=True,
            )
        )
    detection = detect(tuple(views))
    by_source = {view.source_id: view for view in views}
    for finding in detection.findings:
        evidence = finding.evidence
        view = by_source[evidence.source_id]
        if evidence.view != "raw" or not 0 <= evidence.start < evidence.end <= len(view.raw_text):
            raise RuntimeError("unbounded_transformed_evidence")
        if evidence.raw_spans != ((evidence.start, evidence.end),):
            raise RuntimeError("identity_mapping_evidence_mismatch")
    prediction = predicted_attack(detection)
    return dict(
        case_id=case.case_id,
        family_id=case.family_id,
        split=case.split,
        variant=case.variant,
        representation=variant,
        source_type=case.source_type,
        labels=stable(labels),
        sources=sources,
        changed=any(source["changed"] for source in sources),
        classification="UNKNOWN"
        if prediction is None
        else ("TP" if prediction else "FN")
        if case.variant == "attack"
        else ("FP" if prediction else "TN"),
        prediction=prediction,
        detection=stable(detection),
    )


def summarize(rows) -> dict[str, Any]:
    if not rows:
        raise ValueError("empty_representation_population")
    counts = Counter(row["classification"] for row in rows)
    attacks = sum(row["variant"] == "attack" for row in rows)
    benign = len(rows) - attacks
    return dict(
        cases=len(rows),
        changed_cases=sum(row["changed"] for row in rows),
        counts={name: counts[name] for name in ("TP", "FP", "FN", "TN", "UNKNOWN")},
        precision=wilson(counts["TP"], counts["TP"] + counts["FP"]),
        recall=wilson(counts["TP"], attacks),
        benign_flagged=wilson(counts["FP"], benign),
        unknown_case_ids=[row["case_id"] for row in rows if row["prediction"] is None],
    )


def paired(rows, reference, *, replicates=2000, seed=1729) -> dict[str, Any]:
    """Variant minus identity, resampling complete attack/benign families together."""
    if type(replicates) is not int or replicates < 1:
        raise ValueError("invalid_bootstrap_budget")
    current = {row["case_id"]: row for row in rows}
    baseline = {row["case_id"]: row for row in reference}
    if not rows or len(current) != len(rows) or len(baseline) != len(reference) or current.keys() != baseline.keys():
        raise ValueError("paired_population_mismatch")
    families = {}
    for key, row in current.items():
        if any(row[field] != baseline[key][field] for field in ("family_id", "variant", "split", "source_type")):
            raise ValueError("paired_metadata_mismatch")
        families.setdefault(row["family_id"], []).append(key)
    if any(
        len(keys) != 2 or {current[key]["variant"] for key in keys} != {"attack", "benign"}
        for keys in families.values()
    ):
        raise ValueError("complete_family_pair_required")
    deltas = {name: [] for name in ("attack_detected", "benign_flagged")}
    for family in sorted(families):
        members = {current[key]["variant"]: key for key in families[family]}
        for metric, variant in (("attack_detected", "attack"), ("benign_flagged", "benign")):
            key = members[variant]
            deltas[metric].append(int(current[key]["prediction"] is True) - int(baseline[key]["prediction"] is True))
    generator = random.Random(seed)
    raw = {metric: [] for metric in deltas}
    for _ in range(replicates):
        indices = [generator.randrange(len(families)) for _ in families]
        for metric, values in deltas.items():
            raw[metric].append(sum(values[i] for i in indices) / len(indices))
    return dict(
        families=len(families),
        seed=seed,
        replicates=replicates,
        left_minus_identity={
            metric: dict(
                point=sum(deltas[metric]) / len(families),
                ci95=[
                    sorted(values)[math.ceil(0.025 * replicates) - 1],
                    sorted(values)[math.ceil(0.975 * replicates) - 1],
                ],
            )
            for metric, values in raw.items()
        },
        raw_deltas=raw,
    )
