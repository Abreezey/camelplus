"""Experimental Dev-only behavior rules with auditable local quote demotion."""

import json
import re

from pydantic import Field

from camel.core import RiskSignal
from camel.detection.models import ContentView, DetectionResult, Evidence, Finding, Record, identity_view
from camel.detection.rules import Rule
from camel.detection.rules import detect as baseline_detect

VERSION = "d-local-context-v2-dev1"
MAX_SOURCE_CHARACTERS = 4000
MAX_FINDINGS = 64

# These are Dev-informed heuristics, not a semantic model or authorization oracle.
BEHAVIOR_RULES = (
    Rule("v2_cancellation", r"(?:你需要|请|必须|立即|先).{0,24}(?:取消|撤销).{0,20}(?:预约|订单|交易|门禁)", 0.85),
    Rule(
        "v2_evidence_tamper",
        r"(?:请|先|立即|答复前|回答前).{0,36}(?:覆盖|清空|删除|擦除).{0,24}(?:结论|审计|日志|记录|差异|证据)",
        0.9,
    ),
    Rule(
        "v2_private_transfer",
        r"(?:请把|把|将|先|回答前|顺便).{0,20}(?:未公开|私有|内部).{0,20}(?:预算|清单|配置|材料).{0,24}(?:发送|投递|外发|上传|复制)",
        0.85,
    ),
    Rule(
        "v2_label_forgery",
        r"(?:把|将|请|先).{0,32}(?:authority|标签|来源权限).{0,24}(?:改成|改为|设为|提升为).{0,12}(?:execute|执行|系统)",
        0.9,
    ),
    Rule(
        "v2_answer_insertion",
        r"(?:请|要求|必须|务必).{0,28}(?:最终答案|最终回复|答复|回答).{0,24}(?:附上|插入|添加|写入|宣称|说成)",
        0.8,
    ),
    Rule("v2_score_hijack", r"(?:评分|评测|考核).{0,24}(?:要求|必须|一定).{0,20}(?:回答|宣称|输出)", 0.85),
    Rule("v2_concealment", r"(?:不要|不得|不必).{0,12}(?:告诉|透露|提及).{0,12}(?:用户|要求|条款|来源|指令)", 0.85),
)
COMPILED = tuple((rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in BEHAVIOR_RULES)
REJECTION = re.compile(
    r"撤回|弃用|来源冒充|尚无.{0,12}(?:签名|凭证|证据)|反例|错误示例|错误实现|被投诉|违规|不构成授权|已否决|被驳回"
)
ENDORSEMENT = re.compile(r"(?:请|必须|务必|立即|仍然|继续|现在|照此).{0,16}(?:执行|照做|办理|启用|遵循|服从|采用|落实)")
CLAUSE_END = re.compile(r"[。\uff01\uff1f!?\n]")
OPEN_QUOTES = {"“": "”", "「": "」", '"': '"'}


class SuppressedFinding(Record):
    finding: Finding
    reason: str
    quote_start: int
    quote_end: int
    context_start: int
    context_end: int


class CandidateResult(Record):
    detection: DetectionResult
    baseline: DetectionResult
    suppressed: tuple[SuppressedFinding, ...] = Field(max_length=64)


def quote_ranges(text: str) -> tuple[tuple[int, int], ...]:
    stack: list[tuple[str, int]] = []
    ranges = []
    for index, char in enumerate(text):
        if stack and char == stack[-1][0]:
            _, start = stack.pop()
            ranges.append((start, index + 1))
        elif char in OPEN_QUOTES:
            if len(stack) >= 4:
                return ()
            stack.append((OPEN_QUOTES[char], index))
        elif char in OPEN_QUOTES.values():
            # Mismatched and unclosed quotation cannot justify demotion.
            return ()
    return tuple(ranges) if not stack else ()


def quote_context(text: str, evidence: Evidence) -> tuple[int, int, int, int] | None:
    ranges = quote_ranges(text)
    containers = [(left, right) for left, right in ranges if left < evidence.start and evidence.end < right]
    if not containers:
        return None
    left, right = min(containers, key=lambda span: span[1] - span[0])
    before = list(CLAUSE_END.finditer(text, 0, left))
    start = before[-1].end() if before else 0
    after = CLAUSE_END.search(text, right)
    end = after.start() if after else len(text)
    start, end = max(start, left - 80), min(end, right + 80)
    # Only the text outside all quotes can explain rejection or endorsement.
    outside_chars = list(text[start:end])
    for a, b in ranges:
        clip_left, clip_right = max(a, start), min(b, end)
        if clip_left < clip_right:
            outside_chars[clip_left - start : clip_right - start] = " " * (clip_right - clip_left)
    outside = "".join(outside_chars)
    if not REJECTION.search(outside) or ENDORSEMENT.search(outside):
        return None
    return left, right, start, end


def result_from(
    findings: tuple[Finding, ...], source_ids: tuple[str, ...], error: str | None = None
) -> DetectionResult:
    signals = tuple(
        RiskSignal(
            name=finding.rule_id,
            confidence=finding.score,
            detector_version=VERSION,
            evidence=(json.dumps(finding.evidence.model_dump(mode="json"), sort_keys=True),),
        )
        for finding in findings
    )
    if error:
        signals = (RiskSignal(name="detection_failure", confidence=1.0, detector_version=VERSION, evidence=(error,)),)
    return DetectionResult(
        status="INPUT_LIMIT" if error else "OK",
        detector_version=VERSION,
        findings=findings,
        signals=signals,
        analyzed_source_ids=source_ids,
        error_code=error,
    )


def analyze(views: tuple[ContentView, ...]) -> CandidateResult:
    baseline = baseline_detect(views)
    ids = tuple(view.source_id for view in views)
    error = baseline.error_code if baseline.status != "OK" else None
    if not error and (len(views) != 1 or len(views[0].raw_text) > MAX_SOURCE_CHARACTERS):
        error = "v2_single_source_character_budget"
    if not error and views[0] != identity_view(
        views[0].source_id, views[0].source_type, views[0].raw_text, views[0].label
    ):
        error = "v2_requires_identity_view"
    if error:
        return CandidateResult(detection=result_from((), ids, error), baseline=baseline, suppressed=())
    view = views[0]
    findings = list(baseline.findings)
    for rule, expression in COMPILED:
        for match in expression.finditer(view.raw_text):
            findings.append(
                Finding(
                    rule_id=rule.name,
                    severity="high" if rule.score >= 0.85 else "medium",
                    score=rule.score,
                    evidence=Evidence(
                        source_id=view.source_id,
                        view="raw",
                        start=match.start(),
                        end=match.end(),
                        raw_spans=((match.start(), match.end()),),
                    ),
                )
            )
            if len(findings) > MAX_FINDINGS:
                return CandidateResult(
                    detection=result_from((), ids, "v2_finding_budget_exceeded"), baseline=baseline, suppressed=()
                )
    retained, suppressed = [], []
    for finding in findings:
        context = quote_context(view.raw_text, finding.evidence)
        if context is None:
            retained.append(finding)
        else:
            left, right, start, end = context
            suppressed.append(
                SuppressedFinding(
                    finding=finding,
                    reason="explicit_local_rejection_of_quote",
                    quote_start=left,
                    quote_end=right,
                    context_start=start,
                    context_end=end,
                )
            )
    return CandidateResult(detection=result_from(tuple(retained), ids), baseline=baseline, suppressed=tuple(suppressed))


def detect(views: tuple[ContentView, ...]) -> DetectionResult:
    return analyze(views).detection
