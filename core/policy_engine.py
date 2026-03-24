from fastapi import HTTPException
from core.schemas import AnalyzeOptions, Finding, AnalyzeResponse
from core.patterns import mask_value


def apply_policy(
    response: AnalyzeResponse,
    options: AnalyzeOptions
) -> AnalyzeResponse:

    # Block before masking — if blocking, we never return content
    if options.block_high_risk and response.risk_level in ("high", "critical"):
        raise HTTPException(
            status_code=403,
            detail={
                "action": "blocked",
                "reason": f"Content risk level is '{response.risk_level}'. "
                          "Blocked by policy.",
                "risk_score": response.risk_score
            }
        )

    if options.mask:
        masked_findings = []
        for f in response.findings:
            masked_findings.append(f.model_copy(update={"value": "[REDACTED]"}))
        response = response.model_copy(update={
            "findings": masked_findings,
            "action": "masked"
        })

    return response