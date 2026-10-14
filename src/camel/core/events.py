"""Canonical events: the versioned unit of provenance across components (arch.md §5.5).

Raw text may record character/token spans in ``span_map``. After summarization,
translation, OCR or LLM rewriting, only the derivation relationship (via
``parent_ids``) and a confidence note are kept — exact token-level causality
must not be claimed.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from camel.core.labels import TrustLabel


class CanonicalEvent(BaseModel):
    """One ingress/derivation event in the provenance DAG."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal[1] = 1
    event_id: str
    trace_id: str
    session_id: str
    parent_ids: tuple[str, ...] = ()
    principal: str
    source: str
    payload_ref: str
    span_map: dict[str, tuple[int, int]] = Field(default_factory=dict)
    labels: TrustLabel = Field(default_factory=TrustLabel)
    timestamp: datetime
