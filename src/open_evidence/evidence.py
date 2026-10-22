"""Cryptographic Content Integrity and Provenance Envelope Sealing.

This module provides deterministic content integrity sealing and verification using
RFC 8785 Canonical JSON (JCS) and SHA-256 digests.

Security and Cryptographic Boundaries:
- Content Integrity (Guaranteed): Verifies that a payload matches its expected
  canonical byte digest. Any bit flip, field modification, or structural mutation
  will be detected when checked against an authentic seal.
- Non-Autonomous Origin Authenticity: An unkeyed SHA-256 seal binds a payload
  to its metadata and timestamp. It does NOT autonomously authenticate the author
  identity or resist active replacement attacks unless the seal itself is signed
  with a digital signature (e.g., Ed25519) or anchored in a trusted, append-only store.
- Not Semantic / Factual Truth: Cryptographic hashes verify byte-level integrity,
  not whether the underlying AI model output is factual, correct, or free from hallucinations.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

from open_evidence.jcs import jcs_sha256

__all__ = [
    "EvidenceSeal",
    "IntegrityVerificationError",
    "TamperedEvidenceError",
    "VerificationResult",
    "seal_payload",
    "validate_iso8601_utc",
    "verify_seal",
]

_FROZEN_CONFIG: Final = ConfigDict(extra="forbid", frozen=True)


def validate_iso8601_utc(ts: str) -> str:
    """Validate that a string is a strict, valid ISO-8601 UTC timestamp.

    Requires:
    1. A valid ISO-8601 representation of an existing calendar date and time.
    2. An explicit UTC timezone designator ('Z' or offset '+00:00'/'-00:00').
    Fails closed with ValueError for malformed strings, invalid calendar dates
    (e.g. Feb 30), or non-UTC offsets.
    """
    if not isinstance(ts, str) or not ts.strip():
        msg = f"Timestamp must be a non-empty string, got {ts!r}"
        raise ValueError(msg)

    try:
        dt = datetime.datetime.fromisoformat(ts)
    except Exception as exc:
        msg = f"Invalid ISO-8601 timestamp string: {ts!r}"
        raise ValueError(msg) from exc

    if dt.tzinfo is None:
        msg = (
            f"Timestamp must include an explicit UTC timezone ('Z' or '+00:00'): {ts!r}"
        )
        raise ValueError(msg)

    offset = dt.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        msg = (
            f"Timestamp timezone must be UTC (offset 0), got offset {offset} in {ts!r}"
        )
        raise ValueError(msg)

    return ts


class IntegrityVerificationError(ValueError):
    """Raised when an evidence payload fails cryptographic integrity verification."""


# Backward compatibility alias
TamperedEvidenceError = IntegrityVerificationError


class EvidenceSeal(BaseModel):
    """A cryptographic integrity seal binding a payload digest with execution metadata.

    Provides content integrity verification relative to the recorded SHA-256 digest.
    """

    model_config = _FROZEN_CONFIG

    schema_version: str = Field(default="open-evidence/v1")
    payload_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    seal_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, v: str) -> str:
        return validate_iso8601_utc(v)


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
    """Normalize Pydantic models, dataclasses, or dicts into canonical JSON types.

    Enforces fail-closed validation on dictionary keys: all keys MUST be strings.
    Silent stringification of non-string keys is strictly forbidden to prevent
    implicit key collisions and field overwriting.
    """
    if isinstance(value, BaseModel):
        return _to_plain_dict(value.model_dump(mode="json"))
    if hasattr(value, "__dataclass_fields__"):
        import dataclasses

        return _to_plain_dict(dataclasses.asdict(value))
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                msg = (
                    f"Evidence payload dictionary keys must be strings, "
                    f"got {type(k).__name__}: {k!r}. Silent key coercion is forbidden."
                )
                raise TypeError(msg)
            result[k] = _to_plain_dict(v)
        return result
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

    if created_at is not None:
        timestamp = validate_iso8601_utc(created_at)
    else:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
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
            f"Payload hash mismatch: computed digest is {computed_payload_hash}, "
            f"seal asserts {seal_obj.payload_sha256}. Content integrity verification failed."
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
