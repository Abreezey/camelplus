"""Property tests for the TrustLabel lattice (supports invariants I3/I4).

Exhaustive over all enum combinations instead of a sampling property library
(not a project dependency).
"""

import itertools

import pytest

from camel.core.labels import Authority, Confidentiality, Integrity, LabelPrivilege, TrustLabel

_RANKS = {
    "integrity": {
        Integrity.UNTRUSTED: 0,
        Integrity.VERIFIED: 1,
        Integrity.TRUSTED_USER: 2,
        Integrity.TRUSTED_SYSTEM: 3,
    },
    "confidentiality": {
        Confidentiality.PUBLIC: 0,
        Confidentiality.INTERNAL: 1,
        Confidentiality.CONFIDENTIAL: 2,
        Confidentiality.SECRET: 3,
    },
    "authority": {Authority.DATA_ONLY: 0, Authority.PROPOSE: 1, Authority.EXECUTE: 2},
}

_ALL_LABELS = [
    TrustLabel(integrity=i, confidentiality=c, authority=a)
    for i, c, a in itertools.product(Integrity, Confidentiality, Authority)
]


def _readers_subset(joined: frozenset[str] | None, source: frozenset[str] | None) -> bool:
    if source is None:  # public = universe; anything is a subset of it
        return True
    if joined is None:
        return False
    return joined <= source


def test_join_never_raises_integrity_or_authority() -> None:
    for a, b in itertools.product(_ALL_LABELS, repeat=2):
        joined = a.join(b)
        assert _RANKS["integrity"][joined.integrity] <= min(
            _RANKS["integrity"][a.integrity], _RANKS["integrity"][b.integrity]
        )
        assert _RANKS["authority"][joined.authority] <= min(
            _RANKS["authority"][a.authority], _RANKS["authority"][b.authority]
        )


def test_join_never_lowers_confidentiality() -> None:
    for a, b in itertools.product(_ALL_LABELS, repeat=2):
        joined = a.join(b)
        assert _RANKS["confidentiality"][joined.confidentiality] >= max(
            _RANKS["confidentiality"][a.confidentiality], _RANKS["confidentiality"][b.confidentiality]
        )


def test_join_is_commutative_associative_idempotent() -> None:
    for a, b in itertools.product(_ALL_LABELS, repeat=2):
        assert a.join(b) == b.join(a)
        assert a.join(a) == a
    for a, b, c in itertools.product(_ALL_LABELS, repeat=3):
        assert a.join(b).join(c) == a.join(b.join(c))


def test_join_narrows_readers() -> None:
    reader_options = [None, frozenset({"alice"}), frozenset({"alice", "bob"}), frozenset({"carol"})]
    for ra, rb in itertools.product(reader_options, repeat=2):
        a = TrustLabel(readers=ra)
        b = TrustLabel(readers=rb)
        joined = a.join(b)
        assert _readers_subset(joined.readers, ra)
        assert _readers_subset(joined.readers, rb)
    assert TrustLabel(readers=None).join(TrustLabel(readers=frozenset({"alice"}))).readers == frozenset({"alice"})
    assert TrustLabel(readers=None).join(TrustLabel(readers=None)).readers is None


def test_join_accumulates_provenance_and_data_classes() -> None:
    a = TrustLabel(provenance=frozenset({"evt_1"}), data_classes=frozenset({"credential"}))
    b = TrustLabel(provenance=frozenset({"evt_2"}), data_classes=frozenset({"document"}))
    joined = a.join(b)
    assert joined.provenance == frozenset({"evt_1", "evt_2"})
    assert joined.data_classes == frozenset({"credential", "document"})


def test_join_execute_scopes_intersect_and_drop_without_execute() -> None:
    a = TrustLabel(authority=Authority.EXECUTE, execute_scopes=frozenset({"fs:read", "net:egress"}))
    b = TrustLabel(authority=Authority.EXECUTE, execute_scopes=frozenset({"fs:read"}))
    assert a.join(b).execute_scopes == frozenset({"fs:read"})
    c = TrustLabel(authority=Authority.PROPOSE, execute_scopes=frozenset({"fs:read"}))
    joined = a.join(c)
    assert joined.authority == Authority.PROPOSE
    assert joined.execute_scopes == frozenset()


def test_flows_to_and_readable_by() -> None:
    secret = TrustLabel(confidentiality=Confidentiality.SECRET)
    assert not secret.flows_to(Confidentiality.PUBLIC)
    assert secret.flows_to(Confidentiality.SECRET)
    assert TrustLabel().flows_to(Confidentiality.PUBLIC)

    assert TrustLabel(readers=None).readable_by("anyone")
    assert TrustLabel(readers=frozenset({"alice"})).readable_by("alice")
    assert not TrustLabel(readers=frozenset({"alice"})).readable_by("bob")


def test_privileged_operations_are_explicit() -> None:
    justification = LabelPrivilege(principal="user:alice", reason="approved disclosure", policy_version="sha256:abc")
    secret = TrustLabel(confidentiality=Confidentiality.SECRET, integrity=Integrity.UNTRUSTED)
    public = secret.declassify(Confidentiality.PUBLIC, justification)
    assert public.confidentiality == Confidentiality.PUBLIC
    assert public.integrity == Integrity.UNTRUSTED  # untouched
    verified = secret.endorse(Integrity.VERIFIED, justification)
    assert verified.integrity == Integrity.VERIFIED


def test_json_roundtrip_and_schema_generation() -> None:
    label = TrustLabel(
        provenance=frozenset({"evt_1"}),
        integrity=Integrity.VERIFIED,
        confidentiality=Confidentiality.CONFIDENTIAL,
        authority=Authority.EXECUTE,
        execute_scopes=frozenset({"fs:read"}),
        readers=frozenset({"alice"}),
        data_classes=frozenset({"credential"}),
    )
    assert TrustLabel.model_validate_json(label.model_dump_json()) == label
    schema = TrustLabel.model_json_schema()
    assert "properties" in schema and "integrity" in schema["properties"]


def test_unknown_enum_value_rejected() -> None:
    with pytest.raises(ValueError):
        TrustLabel.model_validate({"integrity": "somewhat-trusted"})
