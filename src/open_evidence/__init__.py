"""Open Evidence: Verifiable AI Evidence & Provenance Engine.

A lightweight, dependency-free RFC 8785 JSON Canonicalization Scheme (JCS)
and cryptographic evidence sealing library for deterministic, tamper-evident
LLM pipelines.
"""

from open_evidence.contracts import (
    AuditedModelResponse,
    ExecutionProfile,
    FallbackPolicy,
    ModelProviderKind,
    StructuredOutputMode,
)
from open_evidence.evidence import (
    EvidenceSeal,
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
    "ModelProviderKind",
    "StructuredOutputMode",
    "TamperedEvidenceError",
    "VerificationResult",
    "jcs_loads_strict",
    "jcs_serialize",
    "jcs_sha256",
    "seal_payload",
    "verify_seal",
]
