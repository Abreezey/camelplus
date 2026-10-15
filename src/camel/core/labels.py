"""Trust labels and information-flow lattice operations (arch.md §5.1).

TrustLabel is the value-level metadata carried by data flowing through the
system. Labels are merged with ``join``, which by default only:

- lowers integrity (towards untrusted),
- raises confidentiality (towards secret),
- narrows authority and readers.

Raising integrity (endorsement), lowering confidentiality (declassification)
or widening authority are explicit privileged operations that require a
justification record (:class:`LabelPrivilege`). The justification must be
recorded by the caller's audit layer; this module never upgrades silently.
"""

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Self


class Integrity(str, enum.Enum):
    """Integrity dimension of a trust label, from least to most trusted."""

    UNTRUSTED = "untrusted"
    VERIFIED = "verified"
    TRUSTED_USER = "trusted_user"
    TRUSTED_SYSTEM = "trusted_system"


_INTEGRITY_RANK = {
    Integrity.UNTRUSTED: 0,
    Integrity.VERIFIED: 1,
    Integrity.TRUSTED_USER: 2,
    Integrity.TRUSTED_SYSTEM: 3,
}


class Confidentiality(str, enum.Enum):
    """Confidentiality dimension of a trust label, from least to most sensitive."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


_CONFIDENTIALITY_RANK = {
    Confidentiality.PUBLIC: 0,
    Confidentiality.INTERNAL: 1,
    Confidentiality.CONFIDENTIAL: 2,
    Confidentiality.SECRET: 3,
}


class Authority(str, enum.Enum):
    """What the labelled content is allowed to do, from least to most powerful."""

    DATA_ONLY = "data_only"
    PROPOSE = "propose"
    EXECUTE = "execute"


_AUTHORITY_RANK = {
    Authority.DATA_ONLY: 0,
    Authority.PROPOSE: 1,
    Authority.EXECUTE: 2,
}


def _join_readers(a: frozenset[str] | None, b: frozenset[str] | None) -> frozenset[str] | None:
    """Intersect reader sets; ``None`` means public (the universe of readers)."""
    if a is None:
        return b
    if b is None:
        return a
    return a & b


class LabelPrivilege(BaseModel):
    """Justification record for a privileged label operation.

    Must be logged by the audit layer together with the before/after labels.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    principal: str
    reason: str
    policy_version: str


class TrustLabel(BaseModel):
    """Value-level provenance, sensitivity and authority metadata (arch.md §5.1).

    ``readers`` is the set of principals allowed to read the value;
    ``None`` means public (anyone may read), mirroring the legacy
    ``capabilities.readers.Public`` semantics.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    provenance: frozenset[str] = Field(default_factory=frozenset)
    integrity: Integrity = Integrity.UNTRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    authority: Authority = Authority.DATA_ONLY
    execute_scopes: frozenset[str] = Field(default_factory=frozenset)
    readers: frozenset[str] | None = None
    data_classes: frozenset[str] = Field(default_factory=frozenset)

    def join(self, other: Self) -> Self:
        """Merge two labels conservatively.

        The result never has higher integrity or authority, wider readers, or
        lower confidentiality than either input. Provenance and data classes
        accumulate (union).
        """
        integrity = min(self.integrity, other.integrity, key=lambda i: _INTEGRITY_RANK[i])
        confidentiality = max(self.confidentiality, other.confidentiality, key=lambda c: _CONFIDENTIALITY_RANK[c])
        authority = min(self.authority, other.authority, key=lambda a: _AUTHORITY_RANK[a])
        execute_scopes = self.execute_scopes & other.execute_scopes if authority == Authority.EXECUTE else frozenset()
        return type(self)(
            provenance=self.provenance | other.provenance,
            integrity=integrity,
            confidentiality=confidentiality,
            authority=authority,
            execute_scopes=execute_scopes,
            readers=_join_readers(self.readers, other.readers),
            data_classes=self.data_classes | other.data_classes,
        )

    def integrity_at_most(self, level: Integrity) -> bool:
        return _INTEGRITY_RANK[self.integrity] <= _INTEGRITY_RANK[level]

    def confidentiality_at_least(self, level: Confidentiality) -> bool:
        return _CONFIDENTIALITY_RANK[self.confidentiality] >= _CONFIDENTIALITY_RANK[level]

    def flows_to(self, clearance: Confidentiality) -> bool:
        """Whether this value may flow to a destination with the given clearance (I4)."""
        return _CONFIDENTIALITY_RANK[self.confidentiality] <= _CONFIDENTIALITY_RANK[clearance]

    def readable_by(self, principal: str) -> bool:
        return self.readers is None or principal in self.readers

    def declassify(self, to: Confidentiality, justification: LabelPrivilege) -> Self:
        """Explicit privileged lowering of confidentiality. Never called by the policy engine."""
        del justification  # recorded by the caller's audit layer
        return self.model_copy(update={"confidentiality": to})

    def endorse(self, to: Integrity, justification: LabelPrivilege) -> Self:
        """Explicit privileged raising of integrity. Never called by the policy engine."""
        del justification  # recorded by the caller's audit layer
        return self.model_copy(update={"integrity": to})
