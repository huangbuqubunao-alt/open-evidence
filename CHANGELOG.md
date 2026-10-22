# Changelog

All notable changes to `open-evidence` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-22

### Added
- Standard RFC 8785 JSON Canonicalization Scheme (JCS) serializer with ECMAScript float formatting and duplicate key rejection.
- Cryptographic `EvidenceSeal` model and `seal_payload` / `verify_seal` verification engine.
- Provider-neutral `ExecutionProfile` and `AuditedModelResponse` contracts for multi-model workflows.
- Fail-closed `FallbackPolicy` with DAG cycle detection.
- Complete unit test suite covering RFC 8785 test vectors and tamper detection.
- Interactive end-to-end provenance example (`examples/verify_llm_provenance.py`).
- GitHub Actions CI workflow covering Python 3.10 through 3.13.
