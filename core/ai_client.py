import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from core.schemas import Finding

load_dotenv()

_client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.environ["OPENROUTER_API_KEY"],
)

_SYSTEM = (
    "You are a security analyst. You will be given a list of detected "
    "security findings from a log or document analysis. "
    "Generate exactly 4 concise, specific insights about the security "
    "implications. Each insight must reference the actual finding types "
    "and be actionable. "
    "Return ONLY a valid JSON array of 4 strings. No markdown, no preamble."
)


def get_insights(findings: list[Finding], excerpt: str = "") -> list[str]:
    if not findings:
        return ["No security findings detected in this input."]

    finding_summary = [
        {"type": f.type, "risk": f.risk, "line": f.line}
        for f in findings
    ]

    prompt = (
        f"Findings: {json.dumps(finding_summary)}\n"
        f"Log excerpt (first 300 chars): {excerpt[:300]}"
    )

    try:
        response = _client.chat.completions.create(
            model="openrouter/free",
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
        )
        text = response.choices[0].message.content.strip()
        text = text.replace("```json", "").replace("```", "").strip()
        insights = json.loads(text)
        if isinstance(insights, list):
            return [str(i) for i in insights[:5]]
        return [str(insights)]
    except Exception as e:
        return [
            f"AI analysis error: {str(e)}",
            "Manual review of flagged lines is recommended.",
        ]


def get_summary(findings: list[Finding], input_type: str) -> str:
    if not findings:
        return f"No security issues detected in {input_type} input."

    critical = sum(1 for f in findings if f.risk == "critical")
    high = sum(1 for f in findings if f.risk == "high")
    medium = sum(1 for f in findings if f.risk == "medium")
    types = list({f.type for f in findings})

    parts = []
    if critical:
        parts.append(f"{critical} critical issue(s)")
    if high:
        parts.append(f"{high} high-risk issue(s)")
    if medium:
        parts.append(f"{medium} medium issue(s)")
    if types:
        parts.append(f"types: {', '.join(types)}")

    return f"{input_type.capitalize()} contains {'; '.join(parts)}."