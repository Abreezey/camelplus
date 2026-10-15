"""Ingress budgets and filesystem adversarial/differential checks."""

import base64
from pathlib import Path

import pytest

from camel.core.effect import DataReference, EffectType, NormalizationConfidence
from camel.core.labels import Confidentiality, TrustLabel
from camel.normalization import (
    EffectNormalizer,
    IngressNormalizer,
    NormalizationContext,
    NormalizationError,
    ToolBinding,
    resolve_path,
)
from camel.normalization.fs import normalize_fs
from camel.normalization.models import digest


@pytest.fixture()
def context(tmp_path: Path) -> NormalizationContext:
    return NormalizationContext(
        workspace=tmp_path,
        cwd=tmp_path,
        parent_ids=("evt_input",),
        data_refs=(DataReference(ref="value://input", label=TrustLabel(confidentiality=Confidentiality.SECRET)),),
    )


def test_ingress_preserves_original_and_unicode_positions() -> None:
    raw = "\uff21\uff22\uff23\u200b\x00"
    view = IngressNormalizer().normalize(raw)
    assert view.original == raw and view.normalized == "ABC\u200b\x00"
    assert view.suspicious_positions == (3, 4)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("%252e%252e%252f", "../"),
        ("&lt;system&gt;", "<system>"),
        ("base64:" + base64.b64encode("秘密".encode()).decode(), "秘密"),
        ("base64:" + base64.b64encode("\uff21".encode()).decode(), "A"),
    ],
)
def test_bounded_decoding(text: str, expected: str) -> None:
    view = IngressNormalizer().normalize(text)
    assert view.decoded_views[-1] == expected
    assert view.original == text


@pytest.mark.parametrize("text", ["base64:!", "base64:/w==", "%ff"])
def test_invalid_decoding_fails(text: str) -> None:
    with pytest.raises(NormalizationError):
        IngressNormalizer().normalize(text)


def test_input_output_and_depth_budgets() -> None:
    with pytest.raises(NormalizationError):
        IngressNormalizer(max_input=2).normalize("abc")
    with pytest.raises(NormalizationError):
        IngressNormalizer(max_output=2).normalize("abc")
    with pytest.raises(NormalizationError):
        IngressNormalizer(max_output=6).normalize("%41%41")
    assert IngressNormalizer(max_depth=0).normalize("%41").decoded_views == ()
    assert len(IngressNormalizer(max_depth=1).normalize("%2541").decoded_views) == 1


def test_paths_are_absolute_resolved_and_keep_labels(context: NormalizationContext) -> None:
    root = context.workspace
    (root / "directory").mkdir()
    (root / "directory" / "note").write_bytes(b"hello")
    (root / "link").symlink_to(root / "directory", target_is_directory=True)
    result = normalize_fs("read", ("link/note", "directory/../directory/note"), context)
    assert not result.blocked
    assert len({e.effect_id for e in result.effects}) == 2
    assert all(e.resources == (str(root / "directory" / "note"),) for e in result.effects)
    assert all(e.derived_from == ("evt_input",) and e.data_refs[0] == context.data_refs[0] for e in result.effects)
    assert all(e.data_refs[-1].label.confidentiality is Confidentiality.SECRET for e in result.effects)
    assert all(e.normalization_confidence is NormalizationConfidence.EXACT for e in result.effects)


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/etc/passwd",
        "file://remote/tmp/a",
        "file:///tmp/a?q=1",
        "file:///tmp/a#x",
        "https://example.com/a",
        "",
        "a\x00b",
        "a\nb",
        "\uff46\uff49\uff4c\uff45",
        "a\u200bb",
        "file:///tmp/%00",
        "file:///tmp/%0A",
        "file:///tmp/%EF%BC%A1",
    ],
)
def test_dangerous_paths_fail_closed(path: str, context: NormalizationContext) -> None:
    result = EffectNormalizer().normalize(ToolBinding(adapter="fs", operation="read"), {"path": path}, context)
    assert result.blocked
    assert result.effects[-1].normalization_confidence is NormalizationConfidence.FAILED
    assert result.effects[-1].is_high_impact


def test_symlink_escape_loop_and_cwd_boundary(context: NormalizationContext, tmp_path: Path) -> None:
    (tmp_path / "escape").symlink_to(tmp_path.parent, target_is_directory=True)
    with pytest.raises(NormalizationError):
        resolve_path("escape/secret", context)
    (tmp_path / "loop").symlink_to("loop")
    with pytest.raises(NormalizationError):
        resolve_path("loop", context)
    with pytest.raises(NormalizationError):
        resolve_path("note", context.model_copy(update={"cwd": tmp_path.parent}))


@pytest.mark.parametrize(
    "operation,kind",
    [
        ("read", EffectType.READ),
        ("list", EffectType.READ),
        ("stat", EffectType.READ),
        ("write", EffectType.WRITE),
        ("append", EffectType.WRITE),
        ("delete", EffectType.WRITE),
        ("mkdir", EffectType.WRITE),
        ("touch", EffectType.WRITE),
    ],
)
def test_filesystem_operation_mapping(operation: str, kind: EffectType, context: NormalizationContext) -> None:
    assert normalize_fs(operation, ("note",), context).effects[0].type is kind


def test_filesystem_differential_read_and_write(context: NormalizationContext) -> None:
    path = context.workspace / "hello world"
    path.write_bytes(b"original")
    canonical = normalize_fs("read", (path.as_uri(),), context).effects[0]
    assert Path(canonical.resources[0]).read_bytes() == path.read_bytes()
    write = normalize_fs("write", ("hello world",), context).effects[0]
    Path(write.resources[0]).write_bytes(b"changed")
    assert path.read_bytes() == b"changed"


@pytest.mark.parametrize(
    "arguments,operation", [({}, "read"), ({"paths": [1]}, "read"), ({"paths": []}, "read"), ({"path": "a"}, "unknown")]
)
def test_missing_or_unknown_filesystem_inputs(arguments: dict, operation: str, context: NormalizationContext) -> None:
    assert EffectNormalizer().normalize(ToolBinding(adapter="fs", operation=operation), arguments, context).blocked


def test_call_digest_preserves_order() -> None:
    assert digest(["a", "b"]) != digest(["b", "a"])
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
