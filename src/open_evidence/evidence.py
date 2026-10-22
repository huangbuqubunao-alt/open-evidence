"""Cryptographic AI Evidence & Provenance Sealing.

This module provides tamper-evident evidence sealing and verification using
RFC 8785 Canonical JSON and SHA-256 digests.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from open_evidence.jcs import jcs_sha256

__all__ = [
    "EvidenceSeal",
    "TamperedEvidenceError",
    "VerificationResult",
    "seal_payload",
    "verify_seal",
]

_FROZEN_CONFIG: Final = ConfigDict(extra="forbid", frozen=True)


class TamperedEvidenceError(ValueError):
    """Raised when an evidence payload does not match its cryptographic seal."""


class EvidenceSeal(BaseModel):
    """A cryptographic seal asserting the integrity and provenance of a payload."""

    model_config = _FROZEN_CONFIG

    schema_version: str = Field(default="open-evidence/v1")
    payload_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    seal_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """The result of verifying an evidence payload against an EvidenceSeal."""

    is_valid: bool
    computed_payload_hash: str
    expected_payload_hash: str
    computed_seal_hash: str
    expected_seal_hash: str
    error_message: str | None = None


def _to_plain_dict(value: Any) -> Any:
    """Normalize Pydantic models, dataclasses, or dicts into canonical JSON types."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if hasattr(value, "__dataclass_fields__"):
        import dataclasses
        return dataclasses.asdict(value)
    if isinstance(value, dict):
        return {str(k): _to_plain_dict(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_plain_dict(v) for v in value]
    return value


def seal_payload(
    payload: Any,
    *,
    metadata: dict[str, Any] | None = None,
    schema_version: str = "open-evidence/v1",
    created_at: str | None = None,
) -> EvidenceSeal:
    """Seal an arbitrary data payload with RFC 8785 Canonical JSON and SHA-256."""
    plain_payload = _to_plain_dict(payload)
    payload_hash = jcs_sha256(plain_payload)

    timestamp = created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
    meta = metadata or {}
    plain_meta = _to_plain_dict(meta)

    # Preimage for the seal hash binds schema version, payload hash, timestamp, and metadata.
    preimage = {
        "created_at": timestamp,
        "metadata": plain_meta,
        "payload_sha256": payload_hash,
        "schema_version": schema_version,
    }
    seal_hash = jcs_sha256(preimage)

    return EvidenceSeal(
        schema_version=schema_version,
        payload_sha256=payload_hash,
        created_at=timestamp,
        metadata=plain_meta,
        seal_sha256=seal_hash,
    )


def verify_seal(
    payload: Any,
    seal: EvidenceSeal | dict[str, Any],
    *,
    strict: bool = False,
) -> VerificationResult:
    """Verify an evidence payload against a seal.

    If strict is True, raises TamperedEvidenceError on mismatch.
    """
    if isinstance(seal, dict):
        seal_obj = EvidenceSeal.model_validate(seal)
    else:
        seal_obj = seal

    plain_payload = _to_plain_dict(payload)
    computed_payload_hash = jcs_sha256(plain_payload)

    preimage = {
        "created_at": seal_obj.created_at,
        "metadata": seal_obj.metadata,
        "payload_sha256": seal_obj.payload_sha256,
        "schema_version": seal_obj.schema_version,
    }
    computed_seal_hash = jcs_sha256(preimage)

    # Check 1: Is the seal itself internally coherent?
    if computed_seal_hash != seal_obj.seal_sha256:
        err = f"Seal envelope hash corrupted: expected {seal_obj.seal_sha256}, got {computed_seal_hash}"
        if strict:
            raise TamperedEvidenceError(err)
        return VerificationResult(
            is_valid=False,
            computed_payload_hash=computed_payload_hash,
            expected_payload_hash=seal_obj.payload_sha256,
            computed_seal_hash=computed_seal_hash,
            expected_seal_hash=seal_obj.seal_sha256,
            error_message=err,
        )

    # Check 2: Does the payload match the seal's payload hash?
    if computed_payload_hash != seal_obj.payload_sha256:
        err = (
            f"Payload hash mismatch: payload hash is {computed_payload_hash}, "
            f"seal asserts {seal_obj.payload_sha256}. Evidence has been tampered with."
        )
        if strict:
            raise TamperedEvidenceError(err)
        return VerificationResult(
            is_valid=False,
            computed_payload_hash=computed_payload_hash,
            expected_payload_hash=seal_obj.payload_sha256,
            computed_seal_hash=computed_seal_hash,
            expected_seal_hash=seal_obj.seal_sha256,
            error_message=err,
        )

    return VerificationResult(
        is_valid=True,
        computed_payload_hash=computed_payload_hash,
        expected_payload_hash=seal_obj.payload_sha256,
        computed_seal_hash=computed_seal_hash,
        expected_seal_hash=seal_obj.seal_sha256,
        error_message=None,
    )
