"""
synthetic_generate.py
---------------------
Generates synthetic AI code samples using temperature=0 across 4 frontier models:
  - OpenAI: GPT-4o (OPENAI_API_KEY)
  - Anthropic: Claude 3.5 / 3.7 Sonnet (ANTHROPIC_API_KEY)
  - Google: Gemini 2.5 / 1.5 Pro (GEMINI_API_KEY or GOOGLE_API_KEY)
  - DeepSeek: DeepSeek-Coder (DEEPSEEK_API_KEY)

Reads prompts from securityeval_extended.json.
Inserts outputs into corpus.db (raw_files) tagged with:
  repo_name='SYNTHETIC', ai_tool=model, search_keyword=CWE, keyword_in_comment=1
"""

import json
import sqlite3
import os
import sys
import time
import re
import argparse
import requests
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')
PROMPTS_FILE = os.path.join(BASE_DIR, 'securityeval_extended.json')

MODELS = ['gpt-4o', 'claude-sonnet', 'gemini', 'gemini-flash', 'gemini-2.5-pro', 'deepseek-coder']

SYSTEM_PROMPT = (
    "You are an expert C programmer. Generate standalone, syntactically valid C code "
    "that directly answers the user prompt. Do not output any markdown explanations, "
    "conversational filler, or commentary outside of standard in-code comments. "
    "Output only the C source code."
)


def strip_markdown(text):
    """Strips markdown code blocks (e.g. ```c ... ```) if present in LLM output."""
    if not text:
        return ""
    text = text.strip()
    match = re.search(r'```(?:c|C|cpp)?\s*\n(.*?)```', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    if text.startswith('```') and text.endswith('```'):
        lines = text.splitlines()
        return '\n'.join(lines[1:-1]).strip()
    return text


# ── Model API Handlers (temperature=0) ────────────────────────────────────── #

def call_openai_gpt4o(prompt):
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return None, "OPENAI_API_KEY not set"
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "gpt-4o",
        "temperature": 0.0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=45)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        content = resp.json()['choices'][0]['message']['content']
        return strip_markdown(content), None
    except Exception as e:
        return None, f"Network error: {e}"


def call_anthropic_claude(prompt):
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        return None, "ANTHROPIC_API_KEY not set"
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "temperature": 0.0,
        "max_tokens": 2048,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=45)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        content = resp.json()['content'][0]['text']
        return strip_markdown(content), None
    except Exception as e:
        return None, f"Network error: {e}"


def call_google_gemini(prompt):
    api_key = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
    if not api_key:
        return None, "GEMINI_API_KEY or GOOGLE_API_KEY not set"
    
    model_candidates = [
        "gemini-flash-latest",
        "gemini-3.1-flash-lite-preview",
        "gemini-2.5-flash",
        "gemini-2.5-pro"
    ]
    
    last_err = None
    for model in model_candidates:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.0}
        }
        try:
            resp = requests.post(url, json=payload, timeout=30)
            if resp.status_code == 200:
                content = resp.json()['candidates'][0]['content']['parts'][0]['text']
                return strip_markdown(content), None
            else:
                last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as e:
            last_err = f"Network error: {e}"
            
    return None, last_err


def call_deepseek_coder(prompt):
    openrouter_key = os.getenv('OPENROUTER_API_KEY')
    if openrouter_key:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {openrouter_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "deepseek/deepseek-chat",
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ]
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=45)
            if resp.status_code == 200:
                content = resp.json()['choices'][0]['message']['content']
                return strip_markdown(content), None
        except Exception:
            pass

    api_key = os.getenv('DEEPSEEK_API_KEY')
    if not api_key:
        return None, "DEEPSEEK_API_KEY / OPENROUTER_API_KEY not set"
    url = "https://api.deepseek.com/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-coder",
        "temperature": 0.0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=45)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        content = resp.json()['choices'][0]['message']['content']
        return strip_markdown(content), None
    except Exception as e:
        return None, f"Network error: {e}"


MODEL_DISPATCH = {
    'gpt-4o': call_openai_gpt4o,
    'claude-sonnet': call_anthropic_claude,
    'gemini': call_google_gemini,
    'gemini-flash': call_google_gemini,
    'gemini-2.5-pro': call_google_gemini,
    'deepseek-coder': call_deepseek_coder
}


# ── Execution Logic ───────────────────────────────────────────────────────── #

def check_keys():
    print("=== API Key Status for Synthetic Generation ===")
    keys = {
        'OPENAI_API_KEY (gpt-4o)': bool(os.getenv('OPENAI_API_KEY')),
        'ANTHROPIC_API_KEY (claude-sonnet)': bool(os.getenv('ANTHROPIC_API_KEY')),
        'GEMINI_API_KEY / GOOGLE_API_KEY (gemini-2.5-pro)': bool(os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')),
        'DEEPSEEK_API_KEY (deepseek-coder)': bool(os.getenv('DEEPSEEK_API_KEY'))
    }
    for k, present in keys.items():
        status = "READY (Present)" if present else "MISSING (Set via $env:<KEY> = '...')"
        print(f"  {k:<50}: {status}")
    print()
    available = [k for k, p in keys.items() if p]
    print(f"Total available models: {len(available)} / {len(keys)}")
    return len(available)


def run_synthetic_generation(limit=None, selected_models=None):
    if not os.path.exists(PROMPTS_FILE):
        print(f"Error: Prompts file not found at {PROMPTS_FILE}. Run extend_securityeval.py first.")
        sys.exit(1)

    with open(PROMPTS_FILE, 'r', encoding='utf-8') as f:
        prompts = json.load(f)

    if limit:
        prompts = prompts[:limit]

    if selected_models:
        models_to_run = selected_models
    else:
        # Auto-detect which models have keys configured in .env
        models_to_run = []
        if os.getenv('OPENAI_API_KEY'): models_to_run.append('gpt-4o')
        if os.getenv('ANTHROPIC_API_KEY'): models_to_run.append('claude-sonnet')
        if os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY'): models_to_run.append('gemini-2.5-pro')
        if os.getenv('DEEPSEEK_API_KEY'): models_to_run.append('deepseek-coder')
        
        if not models_to_run:
            print("Error: No API keys found in .env. Please configure at least one API key.")
            sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()

    print(f"Starting synthetic generation: {len(prompts)} prompts across {len(models_to_run)} models (parallelized).")
    print(f"Target DB: {DB_PATH}")
    print("-" * 60)

    total_inserted = 0
    total_failed = 0

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def process_prompt_model(p, model):
        prompt_id = p.get('ID', 'P_X')
        cwe = p.get('CWE', 'UNKNOWN')
        prompt_text = p.get('Prompt', '')
        file_name = f"synthetic_{model}_{cwe}_{prompt_id}.c"

        handler = MODEL_DISPATCH.get(model)
        if not handler:
            return None, f"[{model}] Unknown model dispatcher"

        # Check existing
        check_conn = sqlite3.connect(DB_PATH)
        existing = check_conn.execute(
            "SELECT id FROM raw_files WHERE repo_name='SYNTHETIC' AND file_path=?",
            (file_name,)
        ).fetchone()
        check_conn.close()

        if existing:
            return "SKIPPED", f"  [{model}] {prompt_id} ({cwe}): Already exists in DB"

        code, err = handler(prompt_text)
        if err or not code:
            return "FAILED", f"  [{model}] {prompt_id} ({cwe}): Generation failed: {err}"

        attributed_code = (
            f"// Generated by {model} (temp=0) for Security Evaluation ({cwe} / {prompt_id})\n"
            f"// Prompt Context: {p.get('Context', '')}\n\n"
            f"{code}\n"
        )
        return "SUCCESS", (file_name, cwe, model, attributed_code, prompt_id)

    tasks = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        for p in prompts:
            for model in models_to_run:
                tasks.append(executor.submit(process_prompt_model, p, model))

        for future in as_completed(tasks):
            status, res = future.result()
            if status == "SUCCESS":
                file_name, cwe, model, attributed_code, prompt_id = res
                try:
                    cursor.execute('''
                        INSERT INTO raw_files (
                            repo_name, file_path, language, search_keyword, ai_tool, file_content, keyword_in_comment
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        "SYNTHETIC",
                        file_name,
                        "C",
                        cwe,
                        model,
                        attributed_code,
                        1
                    ))
                    conn.commit()
                    total_inserted += 1
                    print(f"  [{model}] {prompt_id} ({cwe}): Generated & stored ({len(attributed_code.encode('utf-8'))} bytes)")
                except sqlite3.IntegrityError:
                    pass
            elif status == "FAILED":
                total_failed += 1
                print(res)
            elif status == "SKIPPED":
                pass

    conn.close()
    print("-" * 60)
    print(f"Synthetic generation pass completed.")
    print(f"  Total newly stored: {total_inserted}")
    print(f"  Total skipped/failed: {total_failed}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic code generator using temperature=0")
    parser.add_argument("--check-keys", action="store_true", help="Check status of all LLM API keys")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of prompts to generate")
    parser.add_argument("--models", nargs="+", choices=MODELS, help="Specific models to run")
    args = parser.parse_args()

    if args.check_keys:
        check_keys()
    else:
        run_synthetic_generation(limit=args.limit, selected_models=args.models)
