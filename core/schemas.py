from pydantic import BaseModel
from typing import Literal, Optional


class AnalyzeOptions(BaseModel):
    mask: bool = False
    block_high_risk: bool = False
    log_analysis: bool = True
    session_id: Optional[str] = None


class AnalyzeRequest(BaseModel):
    input_type: Literal["text", "file", "sql", "chat", "log"]
    content: str
    filename: Optional[str] = None
    options: AnalyzeOptions = AnalyzeOptions()


class Finding(BaseModel):
    type: str
    risk: Literal["low", "medium", "high", "critical"]
    line: int
    value: Optional[str] = None


class AnalyzeResponse(BaseModel):
    summary: str
    content_type: str
    findings: list[Finding]
    risk_score: int
    risk_level: Literal["low", "medium", "high", "critical"]
    action: Literal["allowed", "masked", "blocked"]
    insights: list[str]
