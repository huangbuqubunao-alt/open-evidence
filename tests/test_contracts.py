import pytest
from open_evidence.contracts import (
    AuditedModelResponse,
    ExecutionProfile,
    FallbackPolicy,
    ModelProviderKind,
    StructuredOutputMode,
)
from open_evidence.evidence import verify_seal


def test_audited_model_response_lifecycle():
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


def test_fallback_policy_rejects_cycles():
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
