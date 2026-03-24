import requests

with open("test.log", "r", encoding="utf-8") as f:
    log_content = f.read()

payload = {
    "input_type": "log",
    "content": log_content,
    "options": {
        "mask": False,
        "block_high_risk": False,
        "log_analysis": True
    }
}

response = requests.post(
    "http://localhost:8000/api/analyze",
    json=payload
)

result = response.json()

print(f"\n{'='*50}")
print(f"SUMMARY:     {result['summary']}")
print(f"RISK LEVEL:  {result['risk_level'].upper()}")
print(f"RISK SCORE:  {result['risk_score']}")
print(f"\nFINDINGS ({len(result['findings'])}):")
for f in result['findings']:
    print(f"  Line {f['line']:3d} | {f['risk'].upper():8s} | {f['type']:25s} | {str(f.get('value',''))[:60]}")
print(f"\nINSIGHTS:")
for i, insight in enumerate(result['insights'], 1):
    print(f"  {i}. {insight}")
print(f"{'='*50}")