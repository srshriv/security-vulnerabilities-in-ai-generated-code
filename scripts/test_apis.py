import os, requests
from dotenv import load_dotenv
load_dotenv()

from synthetic_generate import call_openai_gpt4o, call_anthropic_claude, call_google_gemini, call_deepseek_coder

prompt = 'Respond with JSON: {"verdict": "SAFE", "confidence": 0.95}'
def call_openrouter(prompt):
    key = os.getenv('OPENROUTER_API_KEY')
    if not key:
        return None, "no key"
    resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"model": "openai/gpt-4o", "messages": [{"role": "user", "content": prompt}], "temperature": 0},
        timeout=30
    )
    if resp.status_code == 200:
        return resp.json()['choices'][0]['message']['content'], None
    return None, f"HTTP {resp.status_code}: {resp.text[:200]}"

for name, fn in [('openai', call_openai_gpt4o), ('claude', call_anthropic_claude), ('gemini', call_google_gemini), ('deepseek', call_deepseek_coder), ('openrouter', call_openrouter)]:
    try:
        res, err = fn(prompt)
        print(f"{name}: res={res[:80] if res else None}, err={err}")
    except Exception as ex:
        print(f"{name}: exception={ex}")
