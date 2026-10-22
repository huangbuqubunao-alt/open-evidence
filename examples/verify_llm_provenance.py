"""Example: Verifying AI Model Output Provenance with open-evidence.

This runnable script demonstrates how to:
1. Define an execution profile for an LLM call.
2. Record and seal the model's structured response.
3. Export the payload and seal (e.g. for storage or audit log).
4. Verify the evidence seal on another system or downstream consumer.
5. Demonstrate automated detection of payload tampering.
"""

import json

from open_evidence import (
    AuditedModelResponse,
    ExecutionProfile,
    ModelProviderKind,
    StructuredOutputMode,
    verify_seal,
)


def main() -> None:
    print("=== Open Evidence: Provenance Walkthrough ===\n")

    # Step 1: Model Execution Profile
    profile = ExecutionProfile(
        provider_kind=ModelProviderKind.CLOUD_OPENAI,
        provider_id="openai-us-east",
        model_name="o3-mini",
        output_mode=StructuredOutputMode.PROVIDER_JSON_SCHEMA,
        temperature=0.0,
    )
    print(f"1. Created Execution Profile: {profile.model_name}")
    print(f"   Profile SHA-256 Digest: {profile.profile_hash()}\n")

    # Step 2: Simulated LLM Call & Sealing
    prompt_text = "Extract key risk factors from quarterly report."
    mock_llm_raw = '{"risk_level": "MODERATE", "primary_factor": "Supply chain disruption"}'
    mock_structured = json.loads(mock_llm_raw)

    response = AuditedModelResponse.create(
        prompt=prompt_text,
        profile=profile,
        raw_response=mock_llm_raw,
        structured_data=mock_structured,
    )
    print("2. Sealed Audited Model Response:")
    print(f"   Prompt Hash: {response.prompt_sha256}")
    print(f"   Payload Hash: {response.seal.payload_sha256}")
    print(f"   Seal Hash:    {response.seal.seal_sha256}\n")

    # Step 3: Downstream Verification
    verification = verify_seal(
        {
            "profile_sha256": response.profile_sha256,
            "prompt_sha256": response.prompt_sha256,
            "raw_response": response.raw_response,
            "structured_data": response.structured_data,
        },
        response.seal,
    )
    print(f"3. Verification Result: Valid = {verification.is_valid}")
    assert verification.is_valid, "Expected valid verification"

    # Step 4: Mutation / Tampering Detection Test
    print("\n4. Simulating In-Transit Payload Modification...")
    tampered_payload = {
        "profile_sha256": response.profile_sha256,
        "prompt_sha256": response.prompt_sha256,
        "raw_response": mock_llm_raw,
        "structured_data": {"risk_level": "LOW", "primary_factor": "Supply chain disruption"},  # Altered!
    }

    tamper_result = verify_seal(tampered_payload, response.seal)
    print(f"   Modified Payload Verification: Valid = {tamper_result.is_valid}")
    print(f"   Detection Message: {tamper_result.error_message}")
    assert not tamper_result.is_valid, "Modification should be detected!"

    print("\n=== Security Boundary Clarification ===")
    print("- Content Integrity: GUARANTEED (detects byte mismatch against authentic seal).")
    print("- Origin Authenticity: Requires anchoring the seal digest or asymmetric signing (e.g., Ed25519).")
    print("- Factual Truth: Cryptographic seals verify byte preservation, not model semantic factuality.")
    print("\n=== All Verification Checks Succeeded ===")


if __name__ == "__main__":
    main()
