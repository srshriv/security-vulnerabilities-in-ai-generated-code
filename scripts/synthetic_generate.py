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

MODELS = ['gpt-4o', 'claude-sonnet', 'gemini-2.5-pro', 'deepseek-coder']

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
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key={api_key}"
    payload = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.0}
    }
    try:
        resp = requests.post(url, json=payload, timeout=45)
        if resp.status_code != 200:
            fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key={api_key}"
            resp = requests.post(fallback_url, json=payload, timeout=45)
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        content = resp.json()['candidates'][0]['content']['parts'][0]['text']
        return strip_markdown(content), None
    except Exception as e:
        return None, f"Network error: {e}"


def call_deepseek_coder(prompt):
    api_key = os.getenv('DEEPSEEK_API_KEY')
    if not api_key:
        return None, "DEEPSEEK_API_KEY not set"
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

    models_to_run = selected_models or MODELS

    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()

    print(f"Starting synthetic generation: {len(prompts)} prompts across {len(models_to_run)} models.")
    print(f"Target DB: {DB_PATH}")
    print("-" * 60)

    total_inserted = 0
    total_failed = 0

    for idx, p in enumerate(prompts, 1):
        prompt_id = p.get('ID', f'P_{idx}')
        cwe = p.get('CWE', 'UNKNOWN')
        prompt_text = p.get('Prompt', '')

        print(f"[{idx}/{len(prompts)}] {prompt_id} ({cwe}): {p.get('Name', '')}")

        for model in models_to_run:
            handler = MODEL_DISPATCH.get(model)
            if not handler:
                print(f"  [{model}] Unknown model dispatcher")
                continue

            # Check if this prompt & model combination already exists in DB
            file_name = f"synthetic_{model}_{cwe}_{prompt_id}.c"
            existing = cursor.execute(
                "SELECT id FROM raw_files WHERE repo_name='SYNTHETIC' AND file_path=?",
                (file_name,)
            ).fetchone()

            if existing:
                print(f"  [{model}] Already exists in DB, skipping.")
                continue

            code, err = handler(prompt_text)

            if err or not code:
                print(f"  [{model}] Generation failed: {err}")
                total_failed += 1
                continue

            # Prepend explicit attribution comment for formal tracking
            attributed_code = (
                f"// Generated by {model} (temp=0) for Security Evaluation ({cwe} / {prompt_id})\n"
                f"// Prompt Context: {p.get('Context', '')}\n\n"
                f"{code}\n"
            )

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
                1  # Always verified comment-attributed
            ))
            conn.commit()
            total_inserted += 1
            print(f"  [{model}] Generated & stored ({len(attributed_code.encode('utf-8'))} bytes)")

            time.sleep(1.0)  # Gentle API pacing

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
