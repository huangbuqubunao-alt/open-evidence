import pytest

from open_evidence.evidence import (
    EvidenceSeal,
    TamperedEvidenceError,
    seal_payload,
    validate_iso8601_utc,
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


def test_non_string_dictionary_keys_fail_closed() -> None:
    # Integer key must be rejected, not converted silently to string
    with pytest.raises(
        TypeError, match="Evidence payload dictionary keys must be strings"
    ):
        seal_payload({1: "val"})

    # Boolean key must be rejected
    with pytest.raises(
        TypeError, match="Evidence payload dictionary keys must be strings"
    ):
        seal_payload({True: "val"})

    # Collision-prone dict with both int and string keys must fail closed
    with pytest.raises(
        TypeError, match="Evidence payload dictionary keys must be strings"
    ):
        seal_payload({1: "first", "1": "second"})

    # Nested dictionary with non-string key must also fail closed
    with pytest.raises(
        TypeError, match="Evidence payload dictionary keys must be strings"
    ):
        seal_payload({"nested": {100: "bad"}})


def test_timestamp_contract_valid_iso8601_utc() -> None:
    # ISO-8601 UTC with 'Z'
    seal_z = seal_payload({"val": 1}, created_at="2026-10-22T11:55:49Z")
    assert seal_z.created_at == "2026-10-22T11:55:49Z"
    assert verify_seal({"val": 1}, seal_z).is_valid is True

    # ISO-8601 UTC with '+00:00'
    seal_offset = seal_payload({"val": 2}, created_at="2026-10-22T11:55:49+00:00")
    assert seal_offset.created_at == "2026-10-22T11:55:49+00:00"
    assert verify_seal({"val": 2}, seal_offset).is_valid is True

    # ISO-8601 UTC with fractional seconds
    seal_frac = seal_payload({"val": 3}, created_at="2026-10-22T11:55:49.123456Z")
    assert seal_frac.created_at == "2026-10-22T11:55:49.123456Z"
    assert verify_seal({"val": 3}, seal_frac).is_valid is True


def test_timestamp_contract_rejects_invalid_values() -> None:
    # Non-date arbitrary strings
    with pytest.raises(ValueError, match="Invalid ISO-8601 timestamp string"):
        seal_payload({"val": 1}, created_at="not-a-date")

    # Empty string
    with pytest.raises(ValueError, match="Timestamp must be a non-empty string"):
        seal_payload({"val": 1}, created_at="")

    # Invalid calendar date (Feb 30th)
    with pytest.raises(ValueError, match="Invalid ISO-8601 timestamp string"):
        seal_payload({"val": 1}, created_at="2026-02-30T12:00:00Z")

    # Non-UTC timezone offset (+08:00)
    with pytest.raises(ValueError, match="Timestamp timezone must be UTC"):
        seal_payload({"val": 1}, created_at="2026-10-22T19:55:49+08:00")

    # Missing timezone offset (naive datetime)
    with pytest.raises(
        ValueError, match="Timestamp must include an explicit UTC timezone"
    ):
        seal_payload({"val": 1}, created_at="2026-10-22T11:55:49")


def test_evidence_seal_model_validates_timestamp() -> None:
    # Direct model construction enforces ISO-8601 UTC validator
    with pytest.raises(ValueError, match="Invalid ISO-8601 timestamp string"):
        EvidenceSeal(
            schema_version="open-evidence/v1",
            payload_sha256="a" * 64,
            created_at="not-a-date",
            metadata={},
            seal_sha256="b" * 64,
        )


def test_validate_iso8601_utc_direct() -> None:
    assert validate_iso8601_utc("2026-10-22T11:55:49Z") == "2026-10-22T11:55:49Z"
    with pytest.raises(ValueError, match="Timestamp must be a non-empty string"):
        validate_iso8601_utc("   ")
