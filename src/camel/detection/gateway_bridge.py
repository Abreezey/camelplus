"""Bridge B's tool result envelopes into D3 detection (gateway result_sink).

Findings are advisory and recorded, never blocking: D's rules deliberately
keep quoted-example false positives. Detection failure or over-budget input
raises so the gateway withholds the envelope from the Agent (fail closed).
"""

from camel.detection.models import ContentView, DetectionResult, SpanMap
from camel.detection.rules import detect
from camel.gateway.models import GatewayError, ToolResultEnvelope

MAX_VIEWS = 16
MAX_VIEW_CHARS = 32000
MAX_TOTAL_CHARS = 64000


def content_views(envelope: ToolResultEnvelope) -> tuple[ContentView, ...]:
    """One D3 view per B text view; derived source ids join the label provenance."""
    if len(envelope.text_views) > MAX_VIEWS:
        raise GatewayError("detection_failed_content_withheld")
    views: list[ContentView] = []
    total_chars = 0
    for pointer, text_view in sorted(envelope.text_views.items()):
        source_id = envelope.event_id + pointer
        if len(text_view.original) > MAX_VIEW_CHARS or len(text_view.normalized) > MAX_VIEW_CHARS:
            raise GatewayError("detection_failed_content_withheld")
        total_chars += max(len(text_view.original), len(text_view.normalized))
        if total_chars > MAX_TOTAL_CHARS:
            raise GatewayError("detection_failed_content_withheld")
        label = envelope.labels
        if source_id not in label.provenance:
            label = label.model_copy(update={"provenance": frozenset({source_id, *label.provenance})})
        views.append(
            ContentView(
                source_id=source_id,
                source_type="tool_result",
                raw_text=text_view.original,
                normalized_text=text_view.normalized,
                span_map=(
                    (
                        SpanMap(
                            view_start=0,
                            view_end=len(text_view.normalized),
                            raw_start=0,
                            raw_end=len(text_view.original),
                        ),
                    )
                    if text_view.normalized
                    else ()
                ),
                label=label,
            )
        )
    return tuple(views)


class DetectionSink:
    """Gateway ``result_sink``: run D3 detection over every envelope before it is returned."""

    def __init__(self) -> None:
        self.results: dict[str, DetectionResult] = {}

    async def __call__(self, envelope: ToolResultEnvelope) -> None:
        views = content_views(envelope)
        if not views:
            return  # nothing textual to analyze; no record
        result = detect(views)
        if result.status != "OK":
            raise GatewayError("detection_failed_content_withheld")
        self.results[envelope.event_id] = result
