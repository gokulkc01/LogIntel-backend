from core.risk_engine import compute_risk
from core.schemas import Finding

def test_high_risk_score():
    findings = [
        Finding(type="password", risk="critical", line=1),
        Finding(type="api_key", risk="high", line=2),
    ]

    score, level = compute_risk(findings)

    assert level in ["high", "critical"]