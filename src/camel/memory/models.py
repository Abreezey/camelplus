"""Strict memory inputs; model-proposed text cannot supply authority, state or labels."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

from camel.core import Confidentiality, TrustLabel


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


def aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
    return value


class Context(Record):
    """Host-authenticated metadata, never constructed from a proposed write's JSON."""

    principal: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)


class Reader(Record):
    principal: str = Field(min_length=1)
    clearance: Confidentiality


class MemoryPolicy(Record):
    version: str = Field(min_length=1)
    writers: frozenset[str] = Field(min_length=1)
    readers: tuple[Reader, ...] = Field(min_length=1)
    operators: frozenset[str] = Field(min_length=1)
    max_ttl_seconds: int = Field(default=3600, ge=1, le=86400)
    max_entries: int = Field(default=1000, ge=1, le=10000)
    max_depth: int = Field(default=32, ge=1, le=64)

    @field_validator("readers")
    @classmethod
    def unique_readers(cls, value):
        if len({reader.principal for reader in value}) != len(value):
            raise ValueError("duplicate_reader")
        return value


class Source(Record):
    """Registered by the host; no content or asserted model authorization."""

    source_id: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=128)
    label: TrustLabel

    @field_validator("label", mode="before")
    @classmethod
    def explicit_label(cls, value):
        if not isinstance(value, TrustLabel) and (
            not isinstance(value, dict) or set(value) != set(TrustLabel.model_fields)
        ):
            raise ValueError("all_label_fields_required_no_extras")
        return value


class Write(Record):
    entry_id: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=32000)
    source_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    parent_ids: tuple[str, ...] = Field(default=(), max_length=8)
    expires_at: datetime

    _aware_expiry = field_validator("expires_at")(aware)


@dataclass(frozen=True)
class WriteBinding:
    """Host-only data-flow binding, separate from model-proposed Write JSON.

    D5 must obtain these references from the actual labelled values/TDG, not copy
    them out of the candidate. This record is not an authentication mechanism.
    """

    principal: str
    entry_id: str
    source_ids: tuple[str, ...]
    parent_ids: tuple[str, ...]
    content_ref: str


class Entry(Record):
    entry_id: str
    content_ref: str
    source_ids: tuple[str, ...]
    parent_ids: tuple[str, ...]
    writer: str
    session_id: str
    trace_id: str
    labels: TrustLabel
    created_at: datetime
    expires_at: datetime
    policy_version: str
    policy_digest: str
    state: Literal["active", "quarantined"]
    write_event_id: str
    state_event_id: str

    _aware_created = field_validator("created_at")(aware)
    _aware_expiry = field_validator("expires_at")(aware)


class Result(Record):
    status: Literal["STORED", "QUARANTINED", "RETURNED", "DESCRIBED", "DENIED"]
    reasons: tuple[str, ...] = ()
    entry: Entry | None = None
    content: str | None = None

    @model_validator(mode="after")
    def no_partial_content(self) -> Self:
        if (self.status == "RETURNED") != (self.content is not None):
            raise ValueError("only_completed_reads_release_content")
        if (self.status == "DENIED") != (self.entry is None):
            raise ValueError("denials_do_not_expose_entry_metadata")
        return self


class MemoryIntegrityError(Exception):
    """No value may be released when persistent state cannot be verified."""


class MemoryDeniedError(Exception):
    """Internal stable reason code; never includes stored content."""
