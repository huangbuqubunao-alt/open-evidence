# Architecture and Technical Specification

`open-evidence` is engineered as a zero-leakage, memory-pure verification library for AI-generated artifacts.

## Core Design Principles

1. **Standard Compliance (RFC 8785 & I-JSON RFC 7493)**:
   JSON serialization in standard language libraries is non-deterministic (varying whitespace, dictionary ordering, and float formatting). `open-evidence` adheres strictly to RFC 8785:
   - Floating point numbers are converted to string using ECMAScript `NumberToString` (ECMA-262 7.1.12.1).
   - Enforces I-JSON integer boundaries: integers outside `[-(2^53 - 1), 2^53 - 1]` raise `ValueError` to prevent loss of precision across language runtimes.
   - Keys are sorted by UTF-16 code units (lexicographical binary sort).
   - Duplicate keys in input JSON are rejected before object creation.
   - Unpaired Unicode surrogates are rejected at the UTF-8 encoding boundary.

2. **Deterministic Content Integrity Envelope**:
   An `EvidenceSeal` binds four critical components:
   - `schema_version`: Version marker for forward compatibility.
   - `payload_sha256`: SHA-256 digest of the canonicalized payload bytes.
   - `created_at`: Self-asserted ISO-8601 UTC timestamp string captured at seal creation time (not an RFC 3161 TSA-certified token).
   - `metadata`: Arbitrary key-value pairs (auditor ID, runtime environment, provider metadata).
   The entire preimage is canonicalized and hashed to produce `seal_sha256`. Modifying any field immediately invalidates the seal.
   *(Note: Protects canonical JSON structural integrity under RFC 8785 representation. Raw unparsed stream integrity requires raw byte sealing. Python dict/list structures remain mutable in Python memory; modify-after-seal will cause verification failure).*

3. **Cryptographic Boundaries**:
   - **Content Integrity**: Guaranteed against accidental corruption or modifications relative to a known authentic digest.
   - **Origin Authenticity**: Unkeyed SHA-256 does not autonomously authenticate the author. If non-repudiation is required, callers should sign `seal_sha256` with an asymmetric private key (e.g., Ed25519) or record it in a tamper-resistant audit log.
   - **Semantic Truth**: Hashing verifies bit-level preservation, not the factual truthfulness of model outputs.

4. **Fail-Closed Execution Profiling & Full Model Response Verification**:
   LLM applications frequently interact with multiple model providers (OpenAI, Anthropic, local models). `open-evidence` formalizes:
   - `ExecutionProfile`: Versioned configuration including provider type, model name, temperature, and structured output mode.
   - `FallbackPolicy`: An ordered fallback chain linking primary and alternative profiles. Any circular dependencies or duplicated profiles trigger immediate validation errors before runtime execution.
   - `AuditedModelResponse`: Binds the input prompt hash, full execution profile, raw response string, and structured output into an `EvidenceSeal`.
   - `verify_audited_response` / `response.verify(...)`: Complete verification entrypoint that recomputes the execution profile digest from the live profile object, verifies seal metadata consistency, validates the prompt hash, and recalculates the canonical payload seal to guarantee end-to-end model execution integrity.
