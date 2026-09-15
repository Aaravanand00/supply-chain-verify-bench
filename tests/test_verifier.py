"""
Unit tests for SC-Verify deterministic ground-truth verifier.
Verifies oracle accuracy independently across all 4 benchmark scenarios.
"""

import json
import pathlib
import pytest
from verifier import verify_supply_chain, compute_expected_signature, VerificationResult

SCENARIOS_DIR = pathlib.Path(__file__).parent.parent / "scenarios"


def load_scenario(filename: str) -> dict:
    filepath = SCENARIOS_DIR / filename
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def test_clean_case_scenario():
    """Test Scenario 1: All attestations present and valid -> trusted."""
    scenario = load_scenario("clean_case.json")
    result: VerificationResult = verify_supply_chain(scenario)
    
    assert result.is_trusted is True
    assert result.verdict == "trusted"
    assert result.verdict == scenario["expected_verdict"]
    assert len(result.failed_checks) == 0


def test_broken_signature_scenario():
    """Test Scenario 2: Corrupted/tampered signature -> not trusted."""
    scenario = load_scenario("broken_signature.json")
    result: VerificationResult = verify_supply_chain(scenario)
    
    assert result.is_trusted is False
    assert result.verdict == "not trusted"
    assert result.verdict == scenario["expected_verdict"]
    assert len(result.failed_checks) > 0
    assert any("Cryptographic signature verification failed" in check for check in result.failed_checks)


def test_subtle_policy_violation_scenario():
    """Test Scenario 3: Valid signature but unauthorized signer role -> not trusted."""
    scenario = load_scenario("subtle_policy_violation.json")
    result: VerificationResult = verify_supply_chain(scenario)
    
    assert result.is_trusted is False
    assert result.verdict == "not trusted"
    assert result.verdict == scenario["expected_verdict"]
    assert len(result.failed_checks) > 0
    assert any("lacks policy role" in check for check in result.failed_checks)


def test_missing_attestation_scenario():
    """Test Scenario 4: Missing build provenance attestation -> not trusted."""
    scenario = load_scenario("missing_attestation.json")
    result: VerificationResult = verify_supply_chain(scenario)
    
    assert result.is_trusted is False
    assert result.verdict == "not trusted"
    assert result.verdict == scenario["expected_verdict"]
    assert len(result.failed_checks) > 0
    assert any("Missing required provenance attestation" in check for check in result.failed_checks)


def test_signature_helper_determinism():
    """Test helper cryptographic function determinism."""
    sig1 = compute_expected_signature("hash123", "KEY_PEM_DATA")
    sig2 = compute_expected_signature("hash123", "KEY_PEM_DATA")
    sig3 = compute_expected_signature("hash123", "KEY_PEM_DATA_DIFFERENT")
    
    assert sig1 == sig2
    assert sig1 != sig3
