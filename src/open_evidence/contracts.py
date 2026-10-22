"""Provider-Neutral Model Contracts, Structured Output Modes, and Fallback Policies.

This module provides frozen, immutable domain objects to enforce deterministic
model execution profiling and fail-closed fallback policies across AI providers.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from open_evidence.evidence import (
    EvidenceSeal,
    IntegrityVerificationError,
    VerificationResult,
    seal_payload,
    verify_seal,
)
from open_evidence.jcs import jcs_sha256

__all__ = [
    "AuditedModelResponse",
    "ExecutionProfile",
    "FallbackPolicy",
    "ModelProviderKind",
    "StructuredOutputMode",
    "verify_audited_response",
]

_FROZEN: Final = ConfigDict(extra="forbid", frozen=True)


class ModelProviderKind(str, Enum):
    """The provider category."""

    LOCAL = "LOCAL"
    CLOUD_OPENAI = "CLOUD_OPENAI"
    CLOUD_ANTHROPIC = "CLOUD_ANTHROPIC"
    CLOUD_CUSTOM = "CLOUD_CUSTOM"


class StructuredOutputMode(str, Enum):
    """The structured output mechanism supported by the provider."""

    RAW_JSON_PROMPT = "RAW_JSON_PROMPT"
    PROVIDER_JSON_MODE = "PROVIDER_JSON_MODE"
    PROVIDER_JSON_SCHEMA = "PROVIDER_JSON_SCHEMA"
    TOOL_CALL = "TOOL_CALL"


class ExecutionProfile(BaseModel):
    """An immutable, versioned model execution configuration."""

    model_config = _FROZEN

    provider_kind: ModelProviderKind
    provider_id: str
    model_name: str
    output_mode: StructuredOutputMode
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, gt=0)
    system_prompt_version: str | None = None

    def profile_hash(self) -> str:
        """Compute the deterministic JCS SHA-256 identity of this profile."""
        return jcs_sha256(self.model_dump(mode="json"))


class AuditedModelResponse(BaseModel):
    """A sealed, audited AI model response binding prompt, profile, and result."""

    model_config = _FROZEN

    prompt_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    profile: ExecutionProfile
    profile_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    raw_response: str
    structured_data: dict[str, Any]
    seal: EvidenceSeal

    @model_validator(mode="after")
    def validate_profile_coherence(self) -> AuditedModelResponse:
        computed_hash = self.profile.profile_hash()
        if self.profile_sha256 != computed_hash:
            msg = (
                f"profile_sha256 mismatch: stored {self.profile_sha256} does not match "
                f"actual profile hash {computed_hash}. Profile was modified or swapped."
            )
            raise ValueError(msg)
        return self

    @classmethod
    def create(
        cls,
        *,
        prompt: str,
        profile: ExecutionProfile,
        raw_response: str,
        structured_data: dict[str, Any],
    ) -> AuditedModelResponse:
        """Construct and seal an audited model response."""
        prompt_hash = jcs_sha256({"prompt": prompt})
        profile_hash = profile.profile_hash()

        payload = {
            "profile_sha256": profile_hash,
            "prompt_sha256": prompt_hash,
            "raw_response": raw_response,
            "structured_data": structured_data,
        }
        metadata = {
            "model_name": profile.model_name,
            "provider_id": profile.provider_id,
        }
        seal = seal_payload(payload, metadata=metadata)

        return cls(
            prompt_sha256=prompt_hash,
            profile=profile,
            profile_sha256=profile_hash,
            raw_response=raw_response,
            structured_data=structured_data,
            seal=seal,
        )

    def verify(
        self,
        *,
        prompt: str | None = None,
        strict: bool = False,
    ) -> VerificationResult:
        """Verify the full integrity of this response against its profile and seal."""
        return verify_audited_response(self, prompt=prompt, strict=strict)


def verify_audited_response(
    response: AuditedModelResponse,
    *,
    prompt: str | None = None,
    strict: bool = False,
) -> VerificationResult:
    """Verify the full integrity of an AuditedModelResponse.

    Checks:
    1. Recomputed profile hash from response.profile matches response.profile_sha256.
    2. Model configuration matches seal metadata (model_name and provider_id).
    3. If prompt is supplied, recomputed prompt hash matches response.prompt_sha256.
    4. Canonical payload (containing the freshly computed profile_hash) matches the seal.
    """
    computed_profile_hash = response.profile.profile_hash()
    if computed_profile_hash != response.profile_sha256:
        err = (
            f"Profile hash mismatch: profile computes to {computed_profile_hash}, "
            f"but response asserts {response.profile_sha256}. "
            "Execution profile has been swapped or modified."
        )
        if strict:
            raise IntegrityVerificationError(err)
        return VerificationResult(
            is_valid=False,
            computed_payload_hash="",
            expected_payload_hash=response.seal.payload_sha256,
            computed_seal_hash="",
            expected_seal_hash=response.seal.seal_sha256,
            error_message=err,
        )

    meta_model = response.seal.metadata.get("model_name")
    meta_provider = response.seal.metadata.get("provider_id")
    if meta_model is not None and meta_model != response.profile.model_name:
        err = (
            f"Seal metadata model mismatch: seal asserts {meta_model!r}, "
            f"profile has {response.profile.model_name!r}"
        )
        if strict:
            raise IntegrityVerificationError(err)
        return VerificationResult(
            is_valid=False,
            computed_payload_hash="",
            expected_payload_hash=response.seal.payload_sha256,
            computed_seal_hash="",
            expected_seal_hash=response.seal.seal_sha256,
            error_message=err,
        )

    if meta_provider is not None and meta_provider != response.profile.provider_id:
        err = (
            f"Seal metadata provider mismatch: seal asserts {meta_provider!r}, "
            f"profile has {response.profile.provider_id!r}"
        )
        if strict:
            raise IntegrityVerificationError(err)
        return VerificationResult(
            is_valid=False,
            computed_payload_hash="",
            expected_payload_hash=response.seal.payload_sha256,
            computed_seal_hash="",
            expected_seal_hash=response.seal.seal_sha256,
            error_message=err,
        )

    if prompt is not None:
        computed_prompt_hash = jcs_sha256({"prompt": prompt})
        if computed_prompt_hash != response.prompt_sha256:
            err = (
                f"Prompt hash mismatch: provided prompt computes to {computed_prompt_hash}, "
                f"but response asserts {response.prompt_sha256}."
            )
            if strict:
                raise IntegrityVerificationError(err)
            return VerificationResult(
                is_valid=False,
                computed_payload_hash="",
                expected_payload_hash=response.seal.payload_sha256,
                computed_seal_hash="",
                expected_seal_hash=response.seal.seal_sha256,
                error_message=err,
            )

    payload = {
        "profile_sha256": computed_profile_hash,
        "prompt_sha256": response.prompt_sha256,
        "raw_response": response.raw_response,
        "structured_data": response.structured_data,
    }

    return verify_seal(payload, response.seal, strict=strict)


class FallbackPolicy(BaseModel):
    """A fail-closed model fallback execution chain with duplicate and cycle prevention."""

    model_config = _FROZEN

    primary_profile: ExecutionProfile
    fallback_profiles: list[ExecutionProfile] = Field(default_factory=list)
    max_attempts: int = Field(default=3, gt=0, le=10)

    @model_validator(mode="after")
    def validate_no_duplicate_profiles(self) -> FallbackPolicy:
        all_hashes = [self.primary_profile.profile_hash()]
        for fb in self.fallback_profiles:
            h = fb.profile_hash()
            if h in all_hashes:
                msg = f"Duplicate or cyclic fallback profile detected: {fb.model_name} ({fb.provider_id})"
                raise ValueError(msg)
            all_hashes.append(h)

        if len(self.fallback_profiles) + 1 > self.max_attempts:
            msg = f"Total profiles ({len(self.fallback_profiles) + 1}) exceeds max_attempts ({self.max_attempts})"
            raise ValueError(msg)
        return self
