"""A successful retrieval can fill a planner data slot; it never becomes authorization."""

from camel.core import Authority
from camel.memory.models import Result
from camel.planner.models import DataField, Source


def as_data_source(result: Result) -> Source:
    if result.status != "RETURNED" or result.entry is None or result.content is None:
        raise ValueError("verified_memory_retrieval_required")
    if result.entry.labels.authority != Authority.DATA_ONLY or result.entry.labels.execute_scopes:
        raise ValueError("memory_is_data_only")
    source_id = "memory-entry:" + result.entry.entry_id
    label = result.entry.labels.model_copy(update={"provenance": result.entry.labels.provenance | {source_id}})
    return Source(source_id=source_id, label=label, fields=(DataField(name="memory_text", value=result.content),))
