"""Bounded text views retaining originals and suspicious Unicode positions.

"Normalization" never silently changes the bytes used for filesystem or shell
execution. Adapters reject ambiguous structural text; these views are for
matching and investigation. Decoding is linear, size-limited and depth-limited.
"""

import base64
import binascii
import html
import unicodedata
from urllib.parse import unquote_to_bytes

from pydantic import BaseModel, ConfigDict, Field

from camel.normalization.models import NormalizationError


class TextView(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    original: str
    normalized: str
    decoded_views: tuple[str, ...] = ()
    suspicious_positions: tuple[int, ...] = ()


class IngressNormalizer(BaseModel):
    """NFKC and reversible decoding budgets; originals stay available in memory."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_input: int = Field(default=131072, ge=1)
    max_output: int = Field(default=262144, ge=1)
    max_depth: int = Field(default=3, ge=0, le=10)

    def normalize(self, text: str) -> TextView:
        if len(text) > self.max_input:
            raise NormalizationError("ingress_input_budget_exceeded")
        normalized = unicodedata.normalize("NFKC", text)
        positions = tuple(
            i for i, char in enumerate(text) if unicodedata.category(char) in {"Cf", "Cc"} and char not in "\n\r\t"
        )
        current = normalized
        views: list[str] = []
        used = len(normalized)
        if used > self.max_output:
            raise NormalizationError("ingress_output_budget_exceeded")
        for _ in range(self.max_depth):
            decoded = self._decode(current)
            if decoded == current:
                break
            decoded = unicodedata.normalize("NFKC", decoded)
            used += len(decoded)
            if used > self.max_output:
                raise NormalizationError("ingress_output_budget_exceeded")
            views.append(decoded)
            current = decoded
        return TextView(
            original=text, normalized=normalized, decoded_views=tuple(views), suspicious_positions=positions
        )

    def _decode(self, text: str) -> str:
        try:
            if text.startswith("base64:"):
                return base64.b64decode(text[7:], validate=True).decode("utf-8")
            if "%" in text:
                return unquote_to_bytes(text).decode("utf-8")
            return html.unescape(text)
        except (ValueError, UnicodeError, binascii.Error) as err:
            raise NormalizationError("invalid_encoded_text") from err


def structural_text(text: str) -> str:
    """Reject confusable/control syntax instead of authorizing different bytes."""
    view = IngressNormalizer(max_depth=0).normalize(text)
    if view.normalized != text or view.suspicious_positions:
        raise NormalizationError("ambiguous_structural_text")
    return text
