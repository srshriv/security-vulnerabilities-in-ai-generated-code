import os

def qa_check():
    expected_files = [
        'headline_metrics.json',
        'pillar_agreement_upset.png',
        'cwe_heatmap.png',
        'corpus_table.csv',
        'test_bandit.json',
        'test_sample.sarif'
    ]
    
    print("\n--- Day 18 Final QA: Verifying Paper Artifacts ---")
    all_exist = True
    for file in expected_files:
        path = os.path.join('../results', file)
        if os.path.exists(path):
            print(f"[x] VALIDATED: {file}")
        else:
            print(f"[ ] MISSING:   {file}")
            all_exist = False
            
    if all_exist:
        print("\nSUCCESS: All pipeline artifacts are locked! You are ready to write the paper.")
    else:
        print("\nWARNING: Missing files detected. Pipeline is not ready.")

if __name__ == "__main__":
    qa_check()