import json
import os

os.makedirs('../results', exist_ok=True)

def setup_mocks():
    # 1. Mock SARIF file (CodeQL/Semgrep format)
    sarif_data = {
        "runs": [{
            "results": [
                {
                    "ruleId": "cpp/stack-buffer-overflow",
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "temp_1.c"}, "region": {"startLine": 12}}}]
                }
            ]
        }]
    }
    with open('../results/test_sample.sarif', 'w') as f:
        json.dump(sarif_data, f)

    # 2. Mock Bandit JSON file
    bandit_data = {
        "results": [
            {
                "test_id": "B105",
                "filename": "temp_2.py",
                "line_number": 45,
                "issue_severity": "HIGH"
            }
        ]
    }
    with open('../results/test_bandit.json', 'w') as f:
        json.dump(bandit_data, f)

    # 3. Bandit CWE Corrections Map (Day 3 requirement)
    corrections = {
        "B105": "CWE-259"  # Hardcoded password
    }
    with open('test_bandit_cwe_corrections.json', 'w') as f:
        json.dump(corrections, f)

    print("Mock tool outputs and CWE correction map created.")

if __name__ == "__main__":
    setup_mocks()