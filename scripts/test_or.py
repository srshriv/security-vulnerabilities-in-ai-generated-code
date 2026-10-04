import os, requests
from dotenv import load_dotenv
load_dotenv()
key = os.getenv('OPENROUTER_API_KEY')
resp = requests.post(
    'https://openrouter.ai/api/v1/chat/completions',
    headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
    json={'model': 'openai/gpt-4o', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 200, 'temperature': 0},
    timeout=30
)
print('OpenRouter status:', resp.status_code, resp.text[:200])
