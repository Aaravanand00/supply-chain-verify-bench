"""
SC-Verify (Supply Chain Verification Benchmark) - Verifier Module

This module implements a deterministic rule-checking oracle for software supply chain trust.
It models core verification principles from TUF (The Update Framework) and in-toto provenance:
1. Cryptographic Signature Verification
2. Policy Compliance & Role Authorization
3. Provenance Chain Completeness
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class VerificationResult:
    """Represents the structured verdict of a supply chain verification check."""
    is_trusted: bool
    verdict: str  # "trusted" or "not trusted"
    reason: str
    failed_checks: List[str] = field(default_factory=list)


def compute_expected_signature(payload_hash: str, public_key_pem: str) -> str:
    """
    Computes a deterministic cryptographic signature digest for payload + public key.
    
    In a full production TUF/in-toto system, this uses ED25519 or RSA signatures.
    For this benchmark oracle, SHA-256 digest over (payload_hash + ':' + public_key_pem)
    provides a deterministic cryptographic check without requiring external SSL native libraries.
    """
    data = f"{payload_hash}:{public_key_pem}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def verify_supply_chain(scenario_data: Dict[str, Any]) -> VerificationResult:
    """
    Deterministically evaluates a supply chain policy + attestations scenario.
    
    Verification Rules:
    -------------------
    1. Cryptographic Integrity:
       - Every step attestation signature must match compute_expected_signature(payload_hash, public_key_pem).
       - The target artifact release signature must match compute_expected_signature(payload_hash, public_key_pem).
       
    2. Policy Role Authorization:
       - For each step attestation, the signer key MUST be registered in policy.trusted_public_keys
         and MUST possess the required role for that step.
       - The artifact release signer key MUST possess the role defined by policy.artifact_signing_role.
       
    3. Provenance Chain Completeness:
       - Every required step defined in policy.required_steps MUST have a corresponding attestation in attestations.
    """
    failed_checks = []
    policy = scenario_data.get("policy", {})
    trusted_keys = policy.get("trusted_public_keys", {})
    required_steps = policy.get("required_steps", [])
    artifact_signing_role = policy.get("artifact_signing_role", "release_manager")
    
    attestations = scenario_data.get("attestations", [])
    release_sig = scenario_data.get("release_signature", {})
    
    # Map attestations by step name for completeness & step verification
    attestation_map = {att.get("step"): att for att in attestations if "step" in att}
    
    # -------------------------------------------------------------------------
    # 1. Provenance Chain Completeness Check
    # -------------------------------------------------------------------------
    for req_step_def in required_steps:
        step_name = req_step_def.get("step")
        req_role = req_step_def.get("required_role")
        
        if step_name not in attestation_map:
            failed_checks.append(f"Missing required provenance attestation for pipeline step '{step_name}'.")
            continue
            
        att = attestation_map[step_name]
        signer_key_id = att.get("signer_key_id")
        
        # Check if signer key exists in policy
        if signer_key_id not in trusted_keys:
            failed_checks.append(
                f"Step '{step_name}' attestation signed by unknown key '{signer_key_id}' not in policy."
            )
            continue
            
        key_info = trusted_keys[signer_key_id]
        key_roles = key_info.get("roles", [])
        public_key_pem = key_info.get("public_key_pem", "")
        
        # Role Authorization Check for Step
        if req_role and req_role not in key_roles:
            failed_checks.append(
                f"Signer '{signer_key_id}' lacks required role '{req_role}' for step '{step_name}'. Roles: {key_roles}."
            )
            
        # Cryptographic Signature Check for Step
        expected_sig = compute_expected_signature(att.get("payload_hash", ""), public_key_pem)
        actual_sig = att.get("signature", "")
        if actual_sig != expected_sig:
            failed_checks.append(
                f"Cryptographic signature verification failed for step '{step_name}' signed by '{signer_key_id}'."
            )

    # -------------------------------------------------------------------------
    # 2. Release Signature & Policy Verification
    # -------------------------------------------------------------------------
    if not release_sig:
        failed_checks.append("Missing release signature on target artifact metadata.")
    else:
        release_key_id = release_sig.get("signer_key_id")
        if release_key_id not in trusted_keys:
            failed_checks.append(
                f"Artifact release signature signed by untrusted key '{release_key_id}'."
            )
        else:
            rel_key_info = trusted_keys[release_key_id]
            rel_roles = rel_key_info.get("roles", [])
            rel_pub_key = rel_key_info.get("public_key_pem", "")
            
            # Role Authorization Check for Release Manager
            if artifact_signing_role not in rel_roles:
                failed_checks.append(
                    f"Signer '{release_key_id}' lacks policy role '{artifact_signing_role}' for release signing. Roles: {rel_roles}."
                )
                
            # Cryptographic Signature Check for Release
            exp_release_sig = compute_expected_signature(release_sig.get("payload_hash", ""), rel_pub_key)
            act_release_sig = release_sig.get("signature", "")
            if act_release_sig != exp_release_sig:
                failed_checks.append(
                    f"Cryptographic signature verification failed for artifact release signature by '{release_key_id}'."
                )

    # -------------------------------------------------------------------------
    # Formulate Final Verdict
    # -------------------------------------------------------------------------
    if not failed_checks:
        return VerificationResult(
            is_trusted=True,
            verdict="trusted",
            reason="All pipeline attestations and release signatures are cryptographically valid and compliant with policy roles.",
            failed_checks=[]
        )
    else:
        primary_reason = failed_checks[0]
        if len(failed_checks) > 1:
            primary_reason += f" (Total issues found: {len(failed_checks)})"
        return VerificationResult(
            is_trusted=False,
            verdict="not trusted",
            reason=primary_reason,
            failed_checks=failed_checks
        )
