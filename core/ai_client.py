from core.schemas import Finding
from core.ai_gateway import AIGateway, fallback_insights

_gateway = AIGateway()


def get_insights(findings: list[Finding], excerpt: str = "") -> list[str]:
    return _gateway.generate_insights(findings, excerpt).insights


def get_summary(findings: list[Finding], input_type: str) -> str:
    if not findings:
        return f"No security issues detected in {input_type} input."

    critical = sum(1 for f in findings if f.risk == "critical")
    high = sum(1 for f in findings if f.risk == "high")
    medium = sum(1 for f in findings if f.risk == "medium")
    types = sorted({f.type for f in findings})

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
