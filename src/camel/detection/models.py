"""Strict D3a source views, risk evidence and bounded extraction records."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator
from typing_extensions import Self

from camel.core import Decision, RiskSignal, TrustLabel


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class SpanMap(Record):
    view_start: int = Field(ge=0)
    view_end: int = Field(gt=0)
    raw_start: int = Field(ge=0)
    raw_end: int = Field(gt=0)


class ContentView(Record):
    source_id: str = Field(min_length=1, max_length=128)
    source_type: Literal[
        "direct", "web", "document", "mail_issue", "tool_result", "tool_description", "cross_mcp", "memory"
    ]
    raw_text: str = Field(max_length=32000)
    normalized_text: str = Field(max_length=32000)
    span_map: tuple[SpanMap, ...] = Field(max_length=1024)
    label: TrustLabel

    @field_validator("label", mode="before")
    @classmethod
    def complete_label(cls, value):
        if isinstance(value, TrustLabel):
            return value
        if not isinstance(value, dict) or set(value) != set(TrustLabel.model_fields):
            raise ValueError("all public source-label fields must be explicit")
        return value

    @model_validator(mode="after")
    def grounded_mapping(self) -> Self:
        if self.source_id not in self.label.provenance:
            raise ValueError("source label provenance must include source_id")
        cursor = 0
        raw_cursor = 0
        for span in self.span_map:
            if (
                span.view_start != cursor
                or span.view_end <= span.view_start
                or span.view_end > len(self.normalized_text)
            ):
                raise ValueError("mapping must cover normalized view exactly, in order")
            if span.raw_start < raw_cursor or span.raw_end <= span.raw_start or span.raw_end > len(self.raw_text):
                raise ValueError("raw mapping must be bounded, ordered, nonoverlapping")
            cursor = span.view_end
            raw_cursor = span.raw_end
        if cursor != len(self.normalized_text):
            raise ValueError("normalized text has unmapped characters")
        return self


def identity_view(source_id: str, source_type, text: str, label: TrustLabel) -> ContentView:
    mapping = (SpanMap(view_start=0, view_end=len(text), raw_start=0, raw_end=len(text)),) if text else ()
    return ContentView(
        source_id=source_id, source_type=source_type, raw_text=text, normalized_text=text, span_map=mapping, label=label
    )


class Evidence(Record):
    source_id: str
    view: Literal["raw", "normalized"]
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    raw_spans: tuple[tuple[int, int], ...]


class Finding(Record):
    rule_id: str
    severity: Literal["medium", "high"]
    score: float = Field(ge=0, le=1, allow_inf_nan=False)
    evidence: Evidence


class DetectionResult(Record):
    status: Literal["OK", "INPUT_LIMIT"]
    detector_version: str
    findings: tuple[Finding, ...]
    signals: tuple[RiskSignal, ...]
    analyzed_source_ids: tuple[str, ...]
    error_code: str | None


FactKind = Literal["email", "path", "identifier", "text"]


class ParseTask(Record):
    request_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=128)
    window_start: int = Field(ge=0)
    window_end: int = Field(ge=0)
    requested_fields: tuple[FactKind, ...] = Field(min_length=1, max_length=4)


class ParseRequest(Record):
    operation: Literal["extract_literal_spans"] = "extract_literal_spans"
    source_id: str
    text: str
    requested_fields: tuple[FactKind, ...]


class Fact(Record):
    field: FactKind
    value: str = Field(min_length=1, max_length=2048)
    source_id: str = Field(min_length=1, max_length=128)
    start: int = Field(ge=0)
    end: int = Field(gt=0)


class FactPayload(Record):
    schema_version: Literal[1]
    facts: tuple[Fact, ...] = Field(max_length=16)

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("schema_version must be integer 1")
        return value


class ProviderResponse(FactPayload):
    have_enough_information: StrictBool


class VerifiedFact(Record):
    field: FactKind
    value: str
    source_id: str
    raw_start: int
    raw_end: int
    label: TrustLabel


class ParserLimits(Record):
    max_input_characters: int = Field(default=4000, ge=1, le=16000)
    max_output_bytes: int = Field(default=4096, ge=64, le=65536)
    max_attempts: int = Field(default=1, ge=1, le=3)
    timeout_seconds: float = Field(default=3.0, ge=0.05, le=30, allow_inf_nan=False)
    total_seconds: float = Field(default=8.0, ge=0.05, le=60, allow_inf_nan=False)


class MockReply(Record):
    mode: Literal["return", "timeout", "raise", "insufficient", "oversize"]
    output: str = Field(default="", max_length=131072)


class ProviderSettings(Record):
    kind: Literal["mock", "legacy"]
    replies: tuple[MockReply, ...] = Field(default=(), max_length=3)
    model: str | None = None

    @model_validator(mode="after")
    def configured(self) -> Self:
        if self.kind == "mock" and (not self.replies or self.model is not None):
            raise ValueError("mock requires replies and cannot select a model")
        if self.kind == "legacy" and (not self.model or self.replies):
            raise ValueError("legacy requires an explicit model and no mock replies")
        return self


ParseStatus = Literal[
    "OK",
    "INSUFFICIENT",
    "INVALID_OUTPUT",
    "PROVIDER_ERROR",
    "TIMEOUT",
    "INPUT_LIMIT",
    "OUTPUT_LIMIT",
    "INVALID_REQUEST",
]


class ParseAttempt(Record):
    number: int
    status: ParseStatus
    worker_terminated: bool
    elapsed_seconds: float
    error_code: str | None


class ParseOutcome(Record):
    status: ParseStatus
    facts: tuple[VerifiedFact, ...]
    attempts: tuple[ParseAttempt, ...]
    request_sha256: str | None
    error_code: str | None

    @model_validator(mode="after")
    def no_partial_facts(self) -> Self:
        if (self.status == "OK") != bool(self.facts):
            raise ValueError("only successful, nonempty extraction can expose facts")
        return self


class SafetyAssessment(Record):
    decision: Decision
    executable: bool
    blocked_reasons: tuple[str, ...]
    parse_status: ParseStatus | None
