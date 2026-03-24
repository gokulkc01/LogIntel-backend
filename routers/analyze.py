import time
import json
import uuid
from typing import Literal
from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.schemas import AnalyzeOptions, AnalyzeRequest, AnalyzeResponse
from core.parser import parse, parse_upload
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


def _merge_findings(base_findings, extra_findings):
    existing = {(f.line, f.type) for f in base_findings}
    for finding in extra_findings:
        if (finding.line, finding.type) not in existing:
            base_findings.append(finding)
            existing.add((finding.line, finding.type))
    return base_findings


def _build_options(
    mask: bool,
    block_high_risk: bool,
    log_analysis_enabled: bool,
    session_id: str | None,
):
    return AnalyzeOptions(
        mask=mask,
        block_high_risk=block_high_risk,
        log_analysis=log_analysis_enabled,
        session_id=session_id or None,
    )


def _analyze_lines(lines, input_type: str, options: AnalyzeOptions, session_id: str):
    regex_findings = detect(lines, mask=options.mask)
    if options.log_analysis:
        log_findings = LogAnalyzer(session_id).analyze(lines)
        _merge_findings(regex_findings, log_findings)

    store.add_session_findings(session_id, regex_findings)
    cross_anomalies = store.get_cross_log_anomalies(session_id)
    _merge_findings(regex_findings, cross_anomalies)

    findings = sorted(regex_findings, key=lambda f: f.line)
    risk_score, risk_level = compute_risk(findings)
    excerpt = " ".join(t for _, t in lines[:20])
    insights = get_insights(findings, excerpt)
    summary = get_summary(findings, input_type)

    result = AnalyzeResponse(
        summary=summary,
        content_type=input_type,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        action="allowed",
        insights=insights
    )

    return apply_policy(result, options)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    start = time.time()

    # Session ID for cross-log tracking (passed via options or auto-generated)
    session_id = getattr(request.options, "session_id", None) or "default"

    lines = parse(request)
    result = _analyze_lines(lines, request.input_type, request.options, session_id)
    risk_level = result.risk_level
    findings = result.findings

    duration_ms = (time.time() - start) * 1000
    log_analysis(request.input_type, risk_level, len(findings), duration_ms)

    return result


@router.post("/analyze/upload", response_model=AnalyzeResponse)
async def analyze_upload(
    file: UploadFile = File(...),
    input_type: Literal["text", "file", "sql", "chat", "log"] = Form(...),
    mask: bool = Form(False),
    block_high_risk: bool = Form(False),
    log_analysis_enabled: bool = Form(True, alias="log_analysis"),
    session_id: str | None = Form(None),
):
    start = time.time()
    raw_bytes = await file.read()
    options = _build_options(mask, block_high_risk, log_analysis_enabled, session_id)
    resolved_session = options.session_id or "default"
    lines = parse_upload(input_type, raw_bytes, file.filename)
    result = _analyze_lines(lines, input_type, options, resolved_session)

    duration_ms = (time.time() - start) * 1000
    log_analysis(input_type, result.risk_level, len(result.findings), duration_ms)
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
        analyzer = LogAnalyzer(session_id) if request.options.log_analysis else None

        for i in range(0, max(len(lines), 1), CHUNK_SIZE):
            chunk = lines[i:i + CHUNK_SIZE]
            chunk_num = i // CHUNK_SIZE + 1
            total_chunks = (len(lines) + CHUNK_SIZE - 1) // CHUNK_SIZE

            # Regex detection on this chunk
            chunk_findings = detect(chunk, mask=request.options.mask)

            if analyzer is not None:
                # Stateful log analysis — analyzer remembers previous chunks
                log_chunk_findings = analyzer.analyze(chunk)
                _merge_findings(chunk_findings, log_chunk_findings)

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


@router.post("/analyze/upload/stream")
async def analyze_upload_stream(
    file: UploadFile = File(...),
    input_type: Literal["text", "file", "sql", "chat", "log"] = Form(...),
    mask: bool = Form(False),
    block_high_risk: bool = Form(False),
    log_analysis_enabled: bool = Form(True, alias="log_analysis"),
    session_id: str | None = Form(None),
):
    options = _build_options(mask, block_high_risk, log_analysis_enabled, session_id)
    resolved_session = options.session_id or str(uuid.uuid4())
    raw_bytes = await file.read()

    async def event_generator():
        lines = parse_upload(input_type, raw_bytes, file.filename)
        all_findings = []
        analyzer = LogAnalyzer(resolved_session) if options.log_analysis else None

        for i in range(0, max(len(lines), 1), CHUNK_SIZE):
            chunk = lines[i:i + CHUNK_SIZE]
            chunk_num = i // CHUNK_SIZE + 1
            total_chunks = (len(lines) + CHUNK_SIZE - 1) // CHUNK_SIZE

            chunk_findings = detect(chunk, mask=options.mask)
            if analyzer is not None:
                log_chunk_findings = analyzer.analyze(chunk)
                _merge_findings(chunk_findings, log_chunk_findings)

            all_findings.extend(chunk_findings)

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
                yield f"data: {json.dumps({'event': 'progress', 'chunk': chunk_num, 'total_chunks': total_chunks, 'done': False})}\n\n"

        store.add_session_findings(resolved_session, all_findings)
        cross_anomalies = store.get_cross_log_anomalies(resolved_session)
        all_findings.extend(cross_anomalies)

        risk_score, risk_level = compute_risk(all_findings)
        excerpt = " ".join(t for _, t in lines[:20])
        insights = get_insights(all_findings, excerpt)
        summary = get_summary(all_findings, input_type)

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
