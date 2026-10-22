# Architecture and Technical Specification

`open-evidence` is engineered as a zero-leakage, memory-pure verification library for AI-generated artifacts.

## Core Design Principles

1. **Standard Compliance (RFC 8785)**:
   JSON serialization in standard language libraries is non-deterministic (varying whitespace, dictionary ordering, and float formatting). `open-evidence` adheres strictly to RFC 8785:
   - Floating point numbers are converted to string using ECMAScript `NumberToString` (ECMA-262 7.1.12.1).
   - Keys are sorted by UTF-16 code units (lexicographical binary sort).
   - Unpaired Unicode surrogates are rejected at the UTF-8 encoding boundary.

2. **Tamper-Evident Envelope**:
   An `EvidenceSeal` binds four critical components:
   - `schema_version`: Version marker for forward compatibility.
   - `payload_sha256`: SHA-256 digest of the canonicalized payload bytes.
   - `created_at`: ISO-8601 UTC timestamp.
   - `metadata`: Arbitrary key-value pairs (auditor ID, runtime environment, provider metadata).
   The entire preimage is canonicalized and hashed to produce `seal_sha256`. Modifying any field immediately invalidates the seal.

3. **Fail-Closed Execution Profiling**:
   LLM applications frequently interact with multiple model providers (OpenAI, Anthropic, local models). `open-evidence` formalizes:
   - `ExecutionProfile`: Versioned configuration including provider type, model name, temperature, and structured output mode.
   - `FallbackPolicy`: Directed graph linking primary and alternative profiles. Any circular dependencies or duplicated profiles trigger immediate validation errors before runtime execution.
