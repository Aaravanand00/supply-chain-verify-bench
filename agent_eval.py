"""
SC-Verify (Supply Chain Verification Benchmark) - Agent Evaluation Module

This script runs the AI agent benchmark by querying the Gemini API for each of the
4 supply chain security scenarios and evaluating model verdicts against the 
deterministic ground-truth verifier oracle.
"""

import json
import os
import sys
import time
import pathlib
import requests
from typing import Dict, Any, Tuple
from dotenv import load_dotenv

# Import ground truth verifier oracle
from verifier import verify_supply_chain, VerificationResult

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# Path configuration
BASE_DIR = pathlib.Path(__file__).parent
SCENARIOS_DIR = BASE_DIR / "scenarios"


def load_api_key() -> str:
    """
    Loads GEMINI_API_KEY from environment variables or .env file.
    Fails with a clear error message if not present.
    """
    load_dotenv(dotenv_path=BASE_DIR / ".env")
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key or api_key == "your_gemini_api_key_here":
        print("\n" + "=" * 70)
        print("ERROR: GEMINI_API_KEY environment variable is not set!")
        print("Please set your Gemini API key in the .env file or environment:")
        print("  GEMINI_API_KEY=your_actual_api_key")
        print("=" * 70 + "\n")
        sys.exit(1)
        
    return api_key


def query_gemini_agent(scenario_data: Dict[str, Any], api_key: str, max_retries: int = 3) -> Dict[str, str]:
    """
    Queries Gemini API to audit the supply chain scenario.
    Returns dict: {"verdict": "trusted" | "not trusted", "reason": "..."}
    """
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
    
    system_instruction = (
        "You are an expert Software Supply Chain Security Auditor analyzing a TUF/in-toto verification report.\n"
        "Your task is to verify if the given software artifact and provenance chain are fully trusted or not trusted.\n\n"
        "Rules you must audit:\n"
        "1. Cryptographic Integrity: A signature is valid ONLY if signature string matches sha256(payload_hash + ':' + public_key_pem).\n"
        "2. Policy Authorization: Every signing key MUST exist in policy.trusted_public_keys AND possess the required_role for that step. The release signer MUST have policy.artifact_signing_role.\n"
        "3. Attestation Completeness: Every step listed in policy.required_steps MUST have a corresponding attestation.\n\n"
        "Output ONLY a valid JSON object in this format:\n"
        '{\n  "verdict": "trusted" or "not trusted",\n  "reason": "A concise one-line reason explaining your judgment."\n}'
    )
    
    prompt = (
        f"{system_instruction}\n\n"
        f"--- SCENARIO DATA ---\n"
        f"{json.dumps(scenario_data, indent=2)}\n\n"
        f"--- AUDIT REQUEST ---\n"
        f"Analyze the scenario data above according to the verification rules. Provide your verdict and one-line reason in valid JSON format."
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json"
        }
    }

    headers = {"Content-Type": "application/json"}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                resp_json = response.json()
                content_text = resp_json["candidates"][0]["content"]["parts"][0]["text"]
                
                # Parse JSON response
                parsed = json.loads(content_text)
                verdict = str(parsed.get("verdict", "")).strip().lower()
                reason = str(parsed.get("reason", "")).strip()
                
                # Standardize verdict string
                if "not" in verdict or "untrusted" in verdict:
                    verdict = "not trusted"
                elif "trusted" in verdict:
                    verdict = "trusted"
                else:
                    verdict = "unknown"
                    
                return {"verdict": verdict, "reason": reason}

            elif response.status_code in [429, 500, 503]:
                print(f"  [Warning] API returned status {response.status_code} (attempt {attempt}/{max_retries}). Retrying in {attempt * 2}s...")
                time.sleep(attempt * 2)
            else:
                print(f"  [Error] API Call Failed with HTTP status {response.status_code}: {response.text}")
                return {"verdict": "error", "reason": f"HTTP {response.status_code}: {response.text[:100]}"}

        except Exception as e:
            print(f"  [Error] Exception during Gemini API call: {e}")
            if attempt < max_retries:
                time.sleep(attempt * 2)
            else:
                return {"verdict": "error", "reason": f"API request error: {str(e)}"}

    return {"verdict": "error", "reason": "Max retries exceeded"}


def run_benchmark():
    """
    Runs the SC-Verify benchmark pipeline end-to-end across all 4 scenarios.
    """
    print("=" * 80)
    print("      SC-Verify: Software Supply Chain Agent Benchmark Engine")
    print("=" * 80 + "\n")
    
    api_key = load_api_key()
    
    scenario_files = [
        "clean_case.json",
        "broken_signature.json",
        "subtle_policy_violation.json",
        "missing_attestation.json"
    ]
    
    results_table = []
    benchmark_data = []
    correct_count = 0
    total_scenarios = len(scenario_files)
    
    for filename in scenario_files:
        filepath = SCENARIOS_DIR / filename
        with open(filepath, "r", encoding="utf-8") as f:
            scenario_data = json.load(f)
            
        sc_id = scenario_data.get("scenario_id", filename)
        title = scenario_data.get("title", filename)
        
        print(f"Evaluating {title} ({sc_id})...")
        
        # Step 1: Compute Ground Truth Verdict via Verifier Engine
        oracle_res: VerificationResult = verify_supply_chain(scenario_data)
        ground_truth = oracle_res.verdict
        
        # Step 2: Query Gemini AI Agent
        agent_res = query_gemini_agent(scenario_data, api_key)
        model_answer = agent_res.get("verdict", "error")
        model_reason = agent_res.get("reason", "N/A")
        
        # Step 3: Compare Model Answer vs Ground Truth
        is_correct = (model_answer == ground_truth)
        status_str = "CORRECT [PASS]" if is_correct else "INCORRECT [FAIL]"
        if is_correct:
            correct_count += 1
            
        results_table.append([
            title,
            ground_truth,
            model_answer,
            status_str,
            model_reason
        ])
        
        benchmark_data.append({
            "scenario_id": sc_id,
            "title": title,
            "ground_truth": ground_truth,
            "oracle_failed_checks": oracle_res.failed_checks,
            "model_answer": model_answer,
            "is_correct": is_correct,
            "model_reason": model_reason
        })
        
        time.sleep(1)  # Brief pause between API calls

    # Output Benchmark Summary
    print("\n" + "=" * 80)
    print("                           BENCHMARK RESULTS TABLE")
    print("=" * 80)
    
    headers = ["Scenario Name", "Ground Truth", "Model Answer", "Result", "Model Stated Reason"]
    
    if HAS_TABULATE:
        print(tabulate(results_table, headers=headers, tablefmt="grid"))
    else:
        for row in results_table:
            print(f"Scenario: {row[0]}")
            print(f"  Ground Truth : {row[1]}")
            print(f"  Model Answer : {row[2]}")
            print(f"  Status       : {row[3]}")
            print(f"  Model Reason : {row[4]}")
            print("-" * 60)

    accuracy_pct = (correct_count / total_scenarios) * 100
    print("\n" + "=" * 80)
    print(f" BENCHMARK ACCURACY SCORE: {correct_count}/{total_scenarios} ({accuracy_pct:.1f}%)")
    print("=" * 80 + "\n")

    # Save benchmark results to JSON artifact
    results_path = BASE_DIR / "benchmark_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_scenarios": total_scenarios,
            "correct_answers": correct_count,
            "accuracy_percent": accuracy_pct,
            "scenarios": benchmark_data
        }, f, indent=2)
        
    print(f"Detailed benchmark results saved to: {results_path}\n")


if __name__ == "__main__":
    run_benchmark()
