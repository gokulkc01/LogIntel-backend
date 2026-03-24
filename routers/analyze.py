import time
import json
import uuid
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.schemas import AnalyzeRequest, AnalyzeResponse
from core.parser import parse
from core.detector import detect
from core.log_analyzer import LogAnalyzer
from core.risk_engine import compute_risk
from core.policy_engine import apply_policy
from core.ai_client import get_insights, get_summary
from core.observability import log_analysis, get_metrics
import core.session_store as store

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

CHUNK_SIZE = 50  # lines per streaming chunk


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    start = time.time()

    # Session ID for cross-log tracking (passed via options or auto-generated)
    session_id = getattr(request.options, "session_id", None) or "default"

    lines = parse(request)

    # Single-pass detection — one LogAnalyzer instance sees all lines
    regex_findings = detect(lines, mask=request.options.mask)
    log_findings = LogAnalyzer(session_id).analyze(lines)

    # Merge without duplicates
    existing = {(f.line, f.type) for f in regex_findings}
    for f in log_findings:
        if (f.line, f.type) not in existing:
            regex_findings.append(f)

    # Cross-log anomaly detection
    store.add_session_findings(session_id, regex_findings)
    cross_anomalies = store.get_cross_log_anomalies(session_id)
    for f in cross_anomalies:
        regex_findings.append(f)

    findings = sorted(regex_findings, key=lambda f: f.line)
    risk_score, risk_level = compute_risk(findings)

    excerpt = " ".join(t for _, t in lines[:20])
    insights = get_insights(findings, excerpt)
    summary = get_summary(findings, request.input_type)

    result = AnalyzeResponse(
        summary=summary,
        content_type=request.input_type,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        action="allowed",
        insights=insights
    )

    result = apply_policy(result, request.options)

    duration_ms = (time.time() - start) * 1000
    log_analysis(request.input_type, risk_level, len(findings), duration_ms)

    return result


@router.post("/analyze/stream")
async def analyze_stream(request: AnalyzeRequest):
    """
    True SSE streaming — emits findings chunk by chunk as they are detected.
    One LogAnalyzer instance persists across all chunks to maintain state.
    """
    session_id = getattr(request.options, "session_id", None) or str(uuid.uuid4())

    async def event_generator():
        lines = parse(request)
        all_findings = []

        # KEY: single analyzer instance across ALL chunks — state persists
        analyzer = LogAnalyzer(session_id)

        for i in range(0, max(len(lines), 1), CHUNK_SIZE):
            chunk = lines[i:i + CHUNK_SIZE]
            chunk_num = i // CHUNK_SIZE + 1
            total_chunks = (len(lines) + CHUNK_SIZE - 1) // CHUNK_SIZE

            # Regex detection on this chunk
            chunk_findings = detect(chunk, mask=request.options.mask)

            # Stateful log analysis — analyzer remembers previous chunks
            log_chunk_findings = analyzer.analyze(chunk)
            existing = {(f.line, f.type) for f in chunk_findings}
            for f in log_chunk_findings:
                if (f.line, f.type) not in existing:
                    chunk_findings.append(f)

            all_findings.extend(chunk_findings)

            # Emit this chunk's findings immediately
            if chunk_findings:
                payload = {
                    "event": "findings",
                    "chunk": chunk_num,
                    "total_chunks": total_chunks,
                    "findings": [f.model_dump() for f in chunk_findings],
                    "done": False
                }
                yield f"data: {json.dumps(payload)}\n\n"
            else:
                # Emit progress even when no findings in this chunk
                yield f"data: {json.dumps({'event': 'progress', 'chunk': chunk_num, 'total_chunks': total_chunks, 'done': False})}\n\n"

        # Cross-log anomalies
        store.add_session_findings(session_id, all_findings)
        cross_anomalies = store.get_cross_log_anomalies(session_id)
        all_findings.extend(cross_anomalies)

        # Final summary event
        risk_score, risk_level = compute_risk(all_findings)
        excerpt = " ".join(t for _, t in lines[:20])
        insights = get_insights(all_findings, excerpt)
        summary = get_summary(all_findings, request.input_type)

        final = {
            "event": "complete",
            "done": True,
            "summary": summary,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "total_findings": len(all_findings),
            "insights": insights,
            "cross_log_anomalies": [f.model_dump() for f in cross_anomalies]
        }
        yield f"data: {json.dumps(final)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )


@router.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@router.get("/metrics")
async def metrics():
    return get_metrics()


@router.get("/session/{session_id}/summary")
async def session_summary(session_id: str):
    """Returns cross-log anomaly summary for a given session."""
    anomalies = store.get_cross_log_anomalies(session_id)
    return {
        "session_id": session_id,
        "cross_log_anomalies": [f.model_dump() for f in anomalies],
        "anomaly_count": len(anomalies)
    }

@router.get("/debug")
async def debug():
    """Runs the full pipeline on hardcoded input and returns intermediate results."""
    from core.parser import parse
    from core.detector import detect
    from core.log_analyzer import LogAnalyzer
    from core.schemas import AnalyzeRequest, AnalyzeOptions

    test_content = """2026-03-10 10:00:01 INFO login
email=admin@company.com
password=admin123
api_key=sk-prod-xyz123456789abc
ERROR NullPointerException at service.java:45
login failed for user admin
login failed for user admin
login failed for user admin"""

    req = AnalyzeRequest(
        input_type="log",
        content=test_content,
        options=AnalyzeOptions()
    )

    lines = parse(req)
    regex_findings = detect(lines, mask=False)
    log_findings = LogAnalyzer("debug").analyze(lines)

    return {
        "lines_parsed": len(lines),
        "lines_preview": [{"num": n, "text": t} for n, t in lines[:5]],
        "regex_findings_count": len(regex_findings),
        "regex_findings": [f.model_dump() for f in regex_findings],
        "log_findings_count": len(log_findings),
        "log_findings": [f.model_dump() for f in log_findings],
    }