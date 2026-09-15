# SC-Verify: Software Supply Chain Verification Benchmark

> **Proof-of-Concept Benchmark for AI Agent Security Auditing**  
> *Targeted for Research Fellowship Proposal Evaluation*

---

## Executive Summary

**SC-Verify** is a lightweight benchmark designed to evaluate whether AI agents can reliably verify software supply chain trust. Modern supply chain security frameworks—such as **TUF (The Update Framework)** and **in-toto provenance specifications**—rely on cryptographic signature verification, role-based authorization policies, and attestation chain completeness.

This repository provides:
1. **Deterministic Ground-Truth Oracle (`verifier.py`)**: A rule-checking verification engine that independently evaluates supply chain metadata against policy rules without relying on AI.
2. **Four Representative Benchmark Scenarios (`scenarios/`)**: Hand-crafted structured datasets (JSON) testing edge cases from clean releases to subtle policy violations.
3. **AI Agent Benchmark Engine (`agent_eval.py`)**: Integrates with the Gemini API (`gemini-3.6-flash`) to prompt AI agents as supply chain auditors, comparing their verdicts against the deterministic ground-truth oracle.
4. **Independent Unit Test Suite (`tests/test_verifier.py`)**: Pytest validation confirming that the ground-truth oracle functions accurately prior to any AI model invocation.

---

## Key Benchmark Scenarios

| Scenario ID | Title | Description | Ground Truth Verdict | Key Failure Trigger |
| :--- | :--- | :--- | :--- | :--- |
| `scenario_1_clean` | **Clean Supply Chain Case** | Complete build provenance chain, valid signatures, and policy-authorized signers. | `trusted` | None (All checks pass) |
| `scenario_2_broken_signature` | **Broken Signature Case** | Corrupted signature digest on the build step attestation. | `not trusted` | Cryptographic signature digest mismatch |
| `scenario_3_subtle_policy_violation` | **Subtle Policy Violation Case** | Cryptographically valid signature by a builder key signing an artifact release metadata without policy authorization. | `not trusted` | Signer key lacks required `release_manager` policy role |
| `scenario_4_missing_attestation` | **Missing Attestation Case** | Pipeline policy requires `build` and `package` steps, but the `package` provenance record is missing. | `not trusted` | Missing required pipeline step attestation |

---

## Verification Logic & Architecture

The benchmark models three core pillars of supply chain security:

```
                          ┌───────────────────────────┐
                          │   Supply Chain Metadata   │
                          └─────────────┬─────────────┘
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
┌─────────────────────────┐  ┌────────────────────┐  ┌─────────────────────────┐
│ 1. Cryptographic        │  │ 2. Role            │  │ 3. Attestation          │
│    Integrity Check      │  │    Authorization   │  │    Completeness Check   │
├─────────────────────────┤  ├────────────────────┤  ├─────────────────────────┤
│ Computes SHA-256 digest │  │ Verifies key_id in │  │ Ensures all required    │
│ over (payload + key) &  │  │ policy with valid  │  │ pipeline steps have     │
│ compares vs signature.  │  │ role permissions.  │  │ matching attestations.  │
└────────────┬────────────┘  └──────────┬─────────┘  └────────────┬────────────┘
             │                          │                         │
             └──────────────────────────┼─────────────────────────┘
                                        ▼
                          ┌───────────────────────────┐
                          │    Deterministic Verdict  │
                          │   ("trusted" / "not")     │
                          └───────────────────────────┘
```

---

## Project Structure

```
Bounty Token/
├── .env.example               # Template for setting GEMINI_API_KEY
├── .env                       # Environment configuration (ignored in version control)
├── requirements.txt           # Python dependencies
├── verifier.py                # Deterministic Ground-Truth Engine (Oracle)
├── agent_eval.py              # Benchmark execution runner (Gemini API integration)
├── benchmark_results.json     # Saved evaluation output artifact
├── scenarios/
│   ├── __init__.py
│   ├── clean_case.json
│   ├── broken_signature.json
│   ├── subtle_policy_violation.json
│   └── missing_attestation.json
├── tests/
│   ├── __init__.py
│   └── test_verifier.py       # Pytest unit tests for ground-truth verifier
└── README.md                  # Project documentation & benchmark overview
```

---

## Getting Started & Execution

### 1. Prerequisites
- Python 3.10+
- Gemini API Key

### 2. Installation
Clone the repository and install dependencies:
```bash
python -m pip install -r requirements.txt
```

### 3. Environment Configuration
Copy the `.env.example` template to `.env` and set your API key:
```bash
cp .env.example .env
```
Edit `.env` to include your valid `GEMINI_API_KEY`:
```env
GEMINI_API_KEY=AQ.Ab8RN6LF7Ehz3...
```
> **Note**: `agent_eval.py` loads `GEMINI_API_KEY` exclusively from environment variables or `.env`. No API keys are hardcoded in source code.

---

## Running Benchmark & Tests

### Step A: Run Ground-Truth Unit Tests
Before running the AI benchmark, verify that the ground-truth verifier engine functions independently:
```bash
python -m pytest -v tests/test_verifier.py
```
*Expected Output*: `5 passed in 0.08s`

### Step B: Run End-to-End AI Benchmark
Execute the AI agent evaluation against all 4 supply chain scenarios:
```bash
python agent_eval.py
```

### Sample Output Table
```text
================================================================================
                           BENCHMARK RESULTS TABLE
================================================================================
Scenario: Clean Supply Chain Case
  Ground Truth : trusted
  Model Answer : trusted
  Status       : CORRECT [PASS]
  Model Reason : All required attestations are present, cryptographic signatures are valid, and signers possess authorized policy roles.
------------------------------------------------------------
Scenario: Broken Signature Case
  Ground Truth : not trusted
  Model Answer : not trusted
  Status       : CORRECT [PASS]
  Model Reason : Cryptographic verification failed for the build attestation signature.
------------------------------------------------------------
Scenario: Subtle Policy Violation Case
  Ground Truth : not trusted
  Model Answer : not trusted
  Status       : CORRECT [PASS]
  Model Reason : The release signature was created by key 'key_builder_1', which lacks the required 'release_manager' role.
------------------------------------------------------------
Scenario: Missing Attestation Case
  Ground Truth : not trusted
  Model Answer : not trusted
  Status       : CORRECT [PASS]
  Model Reason : Required step 'package' is missing a corresponding attestation record.
------------------------------------------------------------

================================================================================
 BENCHMARK ACCURACY SCORE: 4/4 (100.0%)
================================================================================
```

---

## Fellowship Proposal Implications

This POC demonstrates that while LLMs can accurately perform high-level reasonings over software supply chain policies, deterministic verification oracles remain essential to guard against subtle hallucinations in real-world security audits. SC-Verify lays the groundwork for scaling AI supply chain auditing benchmarks across larger TUF metadata targets and multi-repository attestations.
