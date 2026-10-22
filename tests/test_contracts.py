import pytest

from open_evidence.contracts import (
    AuditedModelResponse,
    ExecutionProfile,
    FallbackPolicy,
    ModelProviderKind,
    StructuredOutputMode,
    verify_audited_response,
)
from open_evidence.evidence import IntegrityVerificationError, verify_seal


def test_audited_model_response_lifecycle() -> None:
    profile = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_OPENAI,
        provider_id="openai-main",
        model_name="o3-mini",
        output_mode=StructuredOutputMode.PROVIDER_JSON_SCHEMA,
        temperature=0.2,
    )

    response = AuditedModelResponse.create(
        prompt="Extract entities from financial disclosure.",
        profile=profile,
        raw_response='{"ticker": "AAPL", "revenue": 100}',
        structured_data={"ticker": "AAPL", "revenue": 100},
    )

    assert response.profile_sha256 == profile.profile_hash()
    assert len(response.prompt_sha256) == 64

    # Verify the seal internally matches
    verification = verify_seal(
        {
            "profile_sha256": response.profile_sha256,
            "prompt_sha256": response.prompt_sha256,
            "raw_response": response.raw_response,
            "structured_data": response.structured_data,
        },
        response.seal,
    )
    assert verification.is_valid is True


def test_fallback_policy_rejects_cycles() -> None:
    profile1 = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_OPENAI,
        provider_id="p1",
        model_name="gpt-4o",
        output_mode=StructuredOutputMode.PROVIDER_JSON_MODE,
    )
    profile2 = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_ANTHROPIC,
        provider_id="p2",
        model_name="claude-3-5-sonnet",
        output_mode=StructuredOutputMode.PROVIDER_JSON_MODE,
    )

    # Valid policy
    policy = FallbackPolicy(
        primary_profile=profile1,
        fallback_profiles=[profile2],
        max_attempts=2,
    )
    assert len(policy.fallback_profiles) == 1

    # Cycle: primary is duplicated in fallback
    with pytest.raises(ValueError, match="Duplicate or cyclic fallback profile detected"):
        FallbackPolicy(
            primary_profile=profile1,
            fallback_profiles=[profile1],
            max_attempts=2,
        )


def test_audited_model_response_verify_success() -> None:
    profile = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_OPENAI,
        provider_id="openai-main",
        model_name="o3-mini",
        output_mode=StructuredOutputMode.PROVIDER_JSON_SCHEMA,
        temperature=0.0,
    )
    prompt = "Extract entities from text."
    response = AuditedModelResponse.create(
        prompt=prompt,
        profile=profile,
        raw_response='{"key": "val"}',
        structured_data={"key": "val"},
    )

    # Full verification via method
    res1 = response.verify(prompt=prompt)
    assert res1.is_valid is True

    # Full verification without explicit prompt
    res2 = response.verify()
    assert res2.is_valid is True

    # Standalone function
    res3 = verify_audited_response(response, prompt=prompt, strict=True)
    assert res3.is_valid is True


def test_audited_model_response_detects_swapped_or_modified_profile() -> None:
    profile = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_OPENAI,
        provider_id="openai-main",
        model_name="o3-mini",
        output_mode=StructuredOutputMode.PROVIDER_JSON_SCHEMA,
        temperature=0.0,
    )
    prompt = "Extract entities."
    response = AuditedModelResponse.create(
        prompt=prompt,
        profile=profile,
        raw_response='{"ok": true}',
        structured_data={"ok": True},
    )

    tampered_profile = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_OPENAI,
        provider_id="openai-main",
        model_name="gpt-4o",  # swapped model!
        output_mode=StructuredOutputMode.PROVIDER_JSON_SCHEMA,
        temperature=0.0,
    )

    # 1. Pydantic validation fails if someone tries to instantiate with mismatched profile and profile_sha256
    with pytest.raises(ValueError, match="profile_sha256 mismatch"):
        AuditedModelResponse(
            prompt_sha256=response.prompt_sha256,
            profile=tampered_profile,
            profile_sha256=response.profile_sha256,  # asserts original profile hash
            raw_response=response.raw_response,
            structured_data=response.structured_data,
            seal=response.seal,
        )

    # 2. Even if constructed bypassing validator (e.g. model_construct), verify_audited_response detects it
    bypassed_response = AuditedModelResponse.model_construct(
        prompt_sha256=response.prompt_sha256,
        profile=tampered_profile,
        profile_sha256=response.profile_sha256,
        raw_response=response.raw_response,
        structured_data=response.structured_data,
        seal=response.seal,
    )

    # Non-strict mode returns is_valid=False with explanatory error
    res = verify_audited_response(bypassed_response)
    assert res.is_valid is False
    assert res.error_message is not None
    assert "Profile hash mismatch" in res.error_message
    assert "Execution profile has been swapped or modified" in res.error_message

    # Strict mode raises IntegrityVerificationError
    with pytest.raises(IntegrityVerificationError, match="Profile hash mismatch"):
        verify_audited_response(bypassed_response, strict=True)


def test_audited_model_response_detects_wrong_prompt() -> None:
    profile = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_OPENAI,
        provider_id="openai-main",
        model_name="o3-mini",
        output_mode=StructuredOutputMode.PROVIDER_JSON_SCHEMA,
    )
    prompt = "Original prompt"
    response = AuditedModelResponse.create(
        prompt=prompt,
        profile=profile,
        raw_response="result",
        structured_data={"result": 1},
    )

    wrong_res = response.verify(prompt="Altered prompt")
    assert wrong_res.is_valid is False
    assert wrong_res.error_message is not None
    assert "Prompt hash mismatch" in wrong_res.error_message

    with pytest.raises(IntegrityVerificationError, match="Prompt hash mismatch"):
        response.verify(prompt="Altered prompt", strict=True)


def test_audited_model_response_detects_metadata_mismatch() -> None:
    profile = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_OPENAI,
        provider_id="openai-main",
        model_name="o3-mini",
        output_mode=StructuredOutputMode.PROVIDER_JSON_SCHEMA,
    )
    response = AuditedModelResponse.create(
        prompt="prompt",
        profile=profile,
        raw_response="out",
        structured_data={},
    )

    # Tamper with seal metadata to claim a different model
    tampered_metadata = dict(response.seal.metadata)
    tampered_metadata["model_name"] = "gpt-4o"
    tampered_seal = response.seal.model_copy(update={"metadata": tampered_metadata})

    tampered_response = AuditedModelResponse.model_construct(
        prompt_sha256=response.prompt_sha256,
        profile=response.profile,
        profile_sha256=response.profile_sha256,
        raw_response=response.raw_response,
        structured_data=response.structured_data,
        seal=tampered_seal,
    )

    res = verify_audited_response(tampered_response)
    assert res.is_valid is False
    assert res.error_message is not None
    assert "Seal metadata model mismatch" in res.error_message

