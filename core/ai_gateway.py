import json
import os
import re
from collections import Counter
from dataclasses import dataclass

from dotenv import load_dotenv

from core.observability import log_ai_gateway_event
from core.schemas import Finding

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - exercised via fallback tests
    OpenAI = None

load_dotenv()

_SYSTEM = (
    "You are a security analyst. You will be given a list of detected "
    "security findings from a log or document analysis. "
    "Generate exactly 4 concise, specific insights about the security "
    "implications. Each insight must reference the actual finding types "
    "and be actionable. "
    "Return ONLY a valid JSON array of 4 strings. No markdown, no preamble."
)

REDACTION_PATTERNS = [
    re.compile(r"(password|passwd|pwd)\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"(api[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{8,}", re.IGNORECASE),
    re.compile(r"(token|jwt|bearer|auth[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_.]{8,}", re.IGNORECASE),
    re.compile(r"(secret[_-]?key|client[_-]?secret|access[_-]?key)\s*[=:]\s*\S+", re.IGNORECASE),
]


@dataclass
class GatewayResult:
    insights: list[str]
    provider: str
    model: str
    used_fallback: bool
    reason: str | None = None


class OpenRouterProvider:
    name = "openrouter"

    def __init__(self):
        self._client = None
        self._error = None

    def is_available(self):
        if self._client is not None:
            return True
        if self._error is not None:
            return False

        api_key = os.getenv("OPENROUTER_API_KEY")
        if OpenAI is None:
            self._error = "openai package is not installed"
            return False
        if not api_key:
            self._error = "OPENROUTER_API_KEY is not configured"
            return False

        self._client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            timeout=float(os.getenv("AI_GATEWAY_TIMEOUT_SECONDS", "12")),
            max_retries=int(os.getenv("AI_GATEWAY_MAX_RETRIES", "1")),
        )
        return True

    @property
    def unavailable_reason(self):
        return self._error

    def generate_insights(self, prompt: str, model: str):
        if not self.is_available():
            raise RuntimeError(self._error or "provider unavailable")

        response = self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        text = response.choices[0].message.content.strip()
        text = text.replace("```json", "").replace("```", "").strip()
        parsed = json.loads(text)
        if isinstance(parsed, list):
            cleaned = [str(item).strip() for item in parsed if str(item).strip()]
            if cleaned:
                return cleaned[:4]
        raise ValueError("provider returned invalid insight payload")


class AIGateway:
    def __init__(self, provider=None, model=None):
        self.provider = provider or OpenRouterProvider()
        self.model = model or os.getenv("AI_GATEWAY_MODEL", "openrouter/free")

    def generate_insights(self, findings: list[Finding], excerpt: str = "") -> GatewayResult:
        if not findings:
            return GatewayResult(
                insights=["No security findings detected in this input."],
                provider="fallback",
                model="deterministic",
                used_fallback=True,
                reason="no_findings",
            )

        redacted_excerpt = redact_excerpt(excerpt)
        prompt = build_prompt(findings, redacted_excerpt)

        if not self.provider.is_available():
            reason = self.provider.unavailable_reason
            log_ai_gateway_event(self.provider.name, self.model, True, reason, len(findings))
            return GatewayResult(
                insights=fallback_insights(findings),
                provider="fallback",
                model="deterministic",
                used_fallback=True,
                reason=reason,
            )

        try:
            insights = self.provider.generate_insights(prompt, self.model)
            log_ai_gateway_event(self.provider.name, self.model, False, None, len(findings))
            return GatewayResult(
                insights=insights,
                provider=self.provider.name,
                model=self.model,
                used_fallback=False,
            )
        except Exception as exc:
            log_ai_gateway_event(self.provider.name, self.model, True, str(exc), len(findings))
            return GatewayResult(
                insights=fallback_insights(findings),
                provider="fallback",
                model="deterministic",
                used_fallback=True,
                reason=str(exc),
            )


def redact_excerpt(excerpt: str) -> str:
    redacted = excerpt
    for pattern in REDACTION_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}=[REDACTED]", redacted)
    return redacted[:300]


def build_prompt(findings: list[Finding], excerpt: str = "") -> str:
    finding_summary = [
        {"type": f.type, "risk": f.risk, "line": f.line}
        for f in findings
    ]
    return (
        f"Findings: {json.dumps(finding_summary)}\n"
        f"Log excerpt (first 300 chars, redacted): {excerpt}"
    )


def fallback_insights(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["No security findings detected in this input."]

    risk_counts = Counter(f.risk for f in findings)
    type_counts = Counter(f.type for f in findings)
    top_types = [type_name for type_name, _ in type_counts.most_common(2)]
    insights = []

    if risk_counts.get("critical"):
        insights.append(
            f"{risk_counts['critical']} critical finding(s) require immediate containment and credential rotation."
        )
    elif risk_counts.get("high"):
        insights.append(
            f"{risk_counts['high']} high-risk finding(s) should be triaged before the affected service is reused."
        )

    if top_types:
        insights.append(
            f"Most common finding types were {', '.join(top_types)}; review the originating workflow and remove exposed values from logs."
        )

    if any(f.type in {"brute_force", "auth_sequence_anomaly", "cross_session_breach"} for f in findings):
        insights.append(
            "Authentication anomalies were detected; investigate the source IPs, lock affected accounts, and review recent access history."
        )

    if any(f.type in {"stack_trace", "stack_trace_block", "debug_leak"} for f in findings):
        insights.append(
            "Application internals are leaking through logs; reduce verbose logging in production and scrub sensitive debug output."
        )

    if any(f.type in {"api_key", "token", "secret", "password", "connection_string"} for f in findings):
        insights.append(
            "Sensitive credentials appear in the captured data; rotate any exposed secrets and move them into a managed secret store."
        )

    return insights[:4] or ["Manual review is recommended for the detected findings."]
