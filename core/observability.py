import json
import logging
import time

logging.basicConfig(format="%(message)s", level=logging.INFO)
_logger = logging.getLogger("platform")

# In-memory counters for /metrics endpoint
_counters: dict[str, int] = {
    "total_requests": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "ai_gateway_requests": 0,
    "ai_gateway_fallbacks": 0,
}
_total_duration_ms: float = 0.0


def log_analysis(
    input_type: str,
    risk_level: str,
    finding_count: int,
    duration_ms: float
) -> None:
    global _total_duration_ms
    _counters["total_requests"] += 1
    _counters[risk_level] = _counters.get(risk_level, 0) + 1
    _total_duration_ms += duration_ms

    _logger.info(json.dumps({
        "event": "analysis_complete",
        "input_type": input_type,
        "risk_level": risk_level,
        "finding_count": finding_count,
        "duration_ms": round(duration_ms, 2),
        "timestamp": time.time()
    }))


def log_ai_gateway_event(
    provider: str,
    model: str,
    used_fallback: bool,
    reason: str | None,
    finding_count: int,
) -> None:
    _counters["ai_gateway_requests"] += 1
    if used_fallback:
        _counters["ai_gateway_fallbacks"] += 1

    _logger.info(json.dumps({
        "event": "ai_gateway_call",
        "provider": provider,
        "model": model,
        "used_fallback": used_fallback,
        "reason": reason,
        "finding_count": finding_count,
        "timestamp": time.time(),
    }))


def get_metrics() -> dict:
    avg = (
        round(_total_duration_ms / _counters["total_requests"], 2)
        if _counters["total_requests"] > 0 else 0
    )
    return {**_counters, "avg_duration_ms": avg}
