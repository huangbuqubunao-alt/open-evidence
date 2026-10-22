import pytest

from open_evidence.evidence import (
    EvidenceSeal,
    TamperedEvidenceError,
    seal_payload,
    verify_seal,
)


def test_seal_and_verify_success() -> None:
    payload = {
        "analysis": "LLM generated insight",
        "confidence": 0.98,
        "sources": ["doc_123", "doc_456"],
    }
    metadata = {"model": "gpt-4o", "tenant": "prod-1"}

    seal = seal_payload(payload, metadata=metadata)
    assert isinstance(seal, EvidenceSeal)
    assert len(seal.payload_sha256) == 64
    assert len(seal.seal_sha256) == 64

    # Verify
    result = verify_seal(payload, seal, strict=True)
    assert result.is_valid is True
    assert result.error_message is None


def test_tampered_payload_detected() -> None:
    payload = {"account": "Alice", "amount": 100}
    seal = seal_payload(payload)

    # Tamper with the payload
    tampered = {"account": "Alice", "amount": 999999}

    result = verify_seal(tampered, seal, strict=False)
    assert result.is_valid is False
    assert result.error_message is not None
    assert "Payload hash mismatch" in result.error_message

    with pytest.raises(TamperedEvidenceError, match="Payload hash mismatch"):
        verify_seal(tampered, seal, strict=True)


def test_tampered_seal_metadata_detected() -> None:
    payload = {"data": "verified"}
    seal = seal_payload(payload, metadata={"auditor": "bob"})

    # Tamper with the seal metadata directly
    tampered_seal_dict = seal.model_dump()
    tampered_seal_dict["metadata"]["auditor"] = "malicious_attacker"

    result = verify_seal(payload, tampered_seal_dict, strict=False)
    assert result.is_valid is False
    assert result.error_message is not None
    assert "Seal envelope hash corrupted" in result.error_message
