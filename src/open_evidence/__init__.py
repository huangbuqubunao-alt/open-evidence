"""Open Evidence: Content Integrity and Provenance Engine for AI Pipelines.

A lightweight, dependency-free RFC 8785 JSON Canonicalization Scheme (JCS)
and cryptographic content integrity sealing library for deterministic,
verifiable LLM pipelines.
"""

from open_evidence.contracts import (
    AuditedModelResponse,
    ExecutionProfile,
    FallbackPolicy,
    ModelProviderKind,
    StructuredOutputMode,
    verify_audited_response,
)
from open_evidence.evidence import (
    EvidenceSeal,
    IntegrityVerificationError,
    TamperedEvidenceError,
    VerificationResult,
    seal_payload,
    verify_seal,
)
from open_evidence.jcs import (
    jcs_loads_strict,
    jcs_serialize,
    jcs_sha256,
)

__version__ = "0.1.0"

__all__ = [
    "AuditedModelResponse",
    "EvidenceSeal",
    "ExecutionProfile",
    "FallbackPolicy",
    "IntegrityVerificationError",
    "ModelProviderKind",
    "StructuredOutputMode",
    "TamperedEvidenceError",
    "VerificationResult",
    "jcs_loads_strict",
    "jcs_serialize",
    "jcs_sha256",
    "seal_payload",
    "verify_audited_response",
    "verify_seal",
]
