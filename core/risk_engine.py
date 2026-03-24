from core.schemas import Finding
from typing import Literal

WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1
}

RiskLevel = Literal["low", "medium", "high", "critical"]


def compute_risk(findings: list[Finding]) -> tuple[int, RiskLevel]:
    score = sum(WEIGHTS[f.risk] for f in findings)
    score = min(score, 20)  # cap for display

    if score >= 15:
        return score, "critical"
    elif score >= 8:
        return score, "high"
    elif score >= 4:
        return score, "medium"
    else:
        return score, "low"