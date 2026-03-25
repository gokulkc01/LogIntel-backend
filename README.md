# LogIntel — Backend

> AI-powered security intelligence engine for log analysis, secret detection, and threat correlation.

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Module Reference](#module-reference)
- [API Design](#api-design)
- [Detection Engine](#detection-engine)
- [AI Integration](#ai-integration)
- [Advanced Features](#advanced-features)
- [Local Setup](#local-setup)
- [Deployment (Render)](#deployment-render)
- [Environment Variables](#environment-variables)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)

---

## Overview

LogIntel's backend is a stateful, multi-layer security analysis engine built with FastAPI. It accepts five input types — **log files, text, PDF, DOCX, and SQL** — runs them through a pipeline of regex detection, stateful log analysis, and AI-generated insights, then returns a structured risk assessment.

Key capabilities:

- **19 regex patterns** covering credentials, PII, SQL injection, command injection, stack traces, and encoded payloads
- **Stateful `LogAnalyzer`** with brute-force detection (sliding 5-minute window), auth sequence correlation (failed → success → API), and stack trace grouping
- **Cross-log session store** that detects anomaly patterns across multiple submissions within the same session
- **True SSE streaming** — findings are emitted chunk-by-chunk (50 lines/chunk) as they are detected, not after full analysis
- **AI gateway** with OpenRouter free tier integration and a deterministic fallback that produces actionable insights without any API dependency
- **Policy engine** supporting value masking and high-risk content blocking (HTTP 403)
- **Rate limiting** (30 req/min per IP via slowapi) and **file size guard** (10 MB via HTTP middleware)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        FastAPI App                       │
│                                                          │
│  POST /api/analyze          POST /api/analyze/stream     │
│  POST /api/analyze/upload   POST /api/analyze/upload/stream│
│  GET  /api/health           GET  /api/metrics            │
│  GET  /api/session/{id}/summary                          │
└──────────────────────┬──────────────────────────────────┘
                       │
            ┌──────────▼──────────┐
            │    Parser / Extractor│
            │  text · log · PDF   │
            │  DOCX · SQL · chat  │
            └──────────┬──────────┘
                       │  list[(line_num, text)]
          ┌────────────┼────────────┐
          │            │            │
  ┌───────▼──────┐ ┌───▼────────┐ ┌▼────────────┐
  │ Regex        │ │ Log        │ │ Session     │
  │ Detector     │ │ Analyzer   │ │ Store       │
  │ 19 patterns  │ │ stateful   │ │ cross-log   │
  └───────┬──────┘ └───┬────────┘ └┬────────────┘
          └────────────┴───────────┘
                       │  list[Finding]
            ┌──────────▼──────────┐
            │     Risk Engine      │
            │  weighted scoring    │
            │  critical/high/med/low│
            └──────────┬──────────┘
                       │
            ┌──────────▼──────────┐
            │     AI Gateway       │
            │  OpenRouter → free   │
            │  deterministic fallback│
            └──────────┬──────────┘
                       │
            ┌──────────▼──────────┐
            │    Policy Engine     │
            │  mask · block · allow│
            └──────────┬──────────┘
                       │
            ┌──────────▼──────────┐
            │   AnalyzeResponse    │
            │  JSON / SSE stream   │
            └─────────────────────┘
```

### Data flow (single request)

1. Request hits `POST /api/analyze` → validated against `AnalyzeRequest` Pydantic schema
2. **Parser** dispatches by `input_type` → returns `list[(line_num, text)]`
3. **Regex Detector** runs all 19 compiled patterns against every line → `list[Finding]`
4. **Log Analyzer** (if `log_analysis=true`) runs stateful analysis on the same lines → appends findings
5. **Session Store** checks for cross-log patterns (IP recurrence, escalating risk) → appends anomaly findings
6. **Risk Engine** weights findings → produces `risk_score` (0–20) and `risk_level`
7. **AI Gateway** sends finding summary + redacted excerpt to OpenRouter → returns 4 insights; falls back to deterministic insights on failure
8. **Policy Engine** applies masking or blocking based on `options`
9. Response returned as `AnalyzeResponse` JSON

For streaming (`/api/analyze/stream`), steps 3–4 run per 50-line chunk and findings are emitted immediately as SSE `data:` events. A **single `LogAnalyzer` instance** persists across all chunks so brute-force and sequence state is never lost between chunks.

---

## Module Reference

### `core/schemas.py`
Pydantic models that form the API contract. Everything else types against these.

| Model | Purpose |
|---|---|
| `AnalyzeRequest` | Incoming payload — `input_type`, `content`, `filename`, `options` |
| `AnalyzeOptions` | `mask`, `block_high_risk`, `log_analysis`, `session_id` |
| `Finding` | Single detection result — `type`, `risk`, `line`, `value` |
| `AnalyzeResponse` | Full response — `summary`, `findings[]`, `risk_score`, `risk_level`, `action`, `insights[]` |

### `core/patterns.py`
19 compiled regex patterns organised into categories. Each entry is a `(Pattern, RiskLevel, type_name)` tuple.

| Category | Types | Risk |
|---|---|---|
| Credentials | `password`, `api_key`, `token`, `secret`, `connection_string` | critical / high |
| PII | `email`, `phone`, `ip_address` | low |
| System leaks | `stack_trace`, `debug_leak` | medium / high |
| SQL injection | `sql_injection`, `destructive_sql`, `sql_comment_injection`, `sensitive_data_query` | critical / high |
| Auth bypass | `auth_bypass` | critical |
| Injection | `time_based_injection`, `command_injection`, `code_injection`, `encoded_payload` | critical / high |

### `core/detector.py`
Runs all patterns against parsed lines. Deduplicates by `(line_num, type)`. IPs are globally deduplicated by value across the entire file. Passwords and connection strings are always redacted regardless of the `mask` option.

### `core/log_analyzer.py`
Stateful per-request analyzer. One instance is created per request/stream and maintains:

- `_failed_attempts` — per-IP sliding window for brute-force detection (threshold: 5 in 5 min)
- `_auth_sequences` — per-IP event list for failed→success→API correlation
- `_ip_counts` — per-IP occurrence counter (threshold: 30 → `suspicious_ip` finding)
- `_in_stack` / `_stack_start` — state machine for multi-line stack trace grouping

### `core/session_store.py`
In-memory global store that survives across requests within one server session. Tracks:

- `_ip_timeline` — IP event history with 1-hour TTL
- `_session_findings` — all findings per session ID for cross-log analysis
- `_auth_state` — per-IP `{failed, success, api_used}` for breach sequence detection

Cross-log anomalies produced: `cross_log_ip_pattern` (same IP across 3+ submissions) and `escalating_risk_trend` (avg risk ≥ 3.0 across last 5 findings).

### `core/risk_engine.py`
Weights: `critical=10`, `high=5`, `medium=2`, `low=1`. Score capped at 20. Thresholds: `≥15 → critical`, `≥8 → high`, `≥4 → medium`, else `low`.

### `core/policy_engine.py`
Applied after risk scoring. `mask=true` redacts all finding values to `[REDACTED]`. `block_high_risk=true` raises HTTP 403 if `risk_level` is `high` or `critical`.

### `core/ai_client.py` + `core/ai_gateway.py`
`AIGateway` wraps `OpenRouterProvider`. On failure or unavailability it falls back to `fallback_insights()` — a deterministic function that generates actionable insights from the findings themselves without any API call. The excerpt sent to the AI is pre-redacted by `redact_excerpt()` before leaving the system.

### `core/parser.py`
Dispatches by `input_type`. Handles UTF-8 BOM, UTF-16, chardet-detected encodings, and literal `\n` strings from HTTP clients. PDF text is extracted page-by-page via PyMuPDF. DOCX paragraphs are extracted via python-docx. Legacy `.doc` files are best-effort decoded via OLE2 magic bytes.

### `core/observability.py`
Structured JSON logging per request. In-memory counters for `total_requests`, per risk-level counts, AI gateway calls/fallbacks, and average latency. Exposed at `GET /api/metrics`.

---

## API Design

### `POST /api/analyze`
Full synchronous analysis. Returns complete `AnalyzeResponse`.

```json
// Request
{
  "input_type": "log",
  "content": "2026-03-10 10:00:01 INFO password=admin123",
  "filename": "app.log",
  "options": {
    "mask": true,
    "block_high_risk": false,
    "log_analysis": true,
    "session_id": "my-session-abc"
  }
}

// Response
{
  "summary": "Log contains 1 critical issue(s); types: password",
  "content_type": "log",
  "findings": [
    { "type": "password", "risk": "critical", "line": 0, "value": "[REDACTED]" }
  ],
  "risk_score": 10,
  "risk_level": "critical",
  "action": "masked",
  "insights": [
    "Critical password exposure at line 1 — rotate immediately and add secret scanning to CI/CD."
  ]
}
```

### `POST /api/analyze/stream`
SSE streaming. Same request body as `/analyze`. Emits:

```
data: {"event":"findings","chunk":1,"total_chunks":3,"findings":[...],"done":false}
data: {"event":"progress","chunk":2,"total_chunks":3,"done":false}
data: {"event":"complete","done":true,"summary":"...","risk_score":20,"risk_level":"critical","insights":[...]}
```

### `POST /api/analyze/upload`
Multipart form upload. Fields: `file` (binary), `input_type`, `mask`, `block_high_risk`, `log_analysis`, `session_id`.

### `POST /api/analyze/upload/stream`
Multipart upload with SSE streaming response.

### `GET /api/health`
```json
{ "status": "ok", "version": "1.0.0" }
```

### `GET /api/metrics`
```json
{
  "total_requests": 42,
  "critical": 10, "high": 18, "medium": 8, "low": 6,
  "ai_gateway_requests": 42,
  "ai_gateway_fallbacks": 3,
  "avg_duration_ms": 1240.5
}
```

### `GET /api/session/{session_id}/summary`
Returns cross-log anomalies accumulated for a session.

---

## Detection Engine

### Risk weight table

| Risk Level | Weight | Example types |
|---|---|---|
| critical | 10 | password, sql_injection, command_injection, auth_bypass, brute_force |
| high | 5 | api_key, token, debug_leak, suspicious_ip, time_based_injection |
| medium | 2 | stack_trace, stack_trace_block |
| low | 1 | email, phone, ip_address |

### Brute-force detection logic

```
For each "failed login / 401 / 403" line:
  1. Parse timestamp (if present)
  2. Increment per-IP sliding window (prune entries > 5 min old)
  3. If window count ≥ 5 AND not yet reported → emit brute_force (critical)
```

### Auth sequence correlation

```
Track per-IP sequence: [failed, failed, failed, ..., success, api_use]
If failed_count ≥ 3 AND last event = success → emit auth_sequence_anomaly (critical)
If failed_count ≥ 5 AND success AND api_use → emit cross_session_breach (critical)
```

---

## AI Integration

The AI gateway sends a **structured prompt** — never raw log content:

```
System: You are a security analyst. Generate exactly 4 concise, specific insights...
        Return ONLY a valid JSON array of 4 strings.

User:   Findings: [{"type":"password","risk":"critical","line":2}, ...]
        Log excerpt (first 300 chars, redacted): 2026-03-10 INFO password=[REDACTED]...
```

The excerpt is pre-redacted by `redact_excerpt()` before being sent. This means **no raw credentials ever leave the system** even when AI integration is active.

If the OpenRouter call fails (network error, quota exceeded, invalid JSON), `fallback_insights()` generates deterministic insights from the findings list — the response always contains meaningful insights regardless of API availability.

---

## Advanced Features

### Real-time streaming
`/api/analyze/stream` processes 50 lines per chunk. A single `LogAnalyzer` instance spans all chunks so state (brute-force counters, auth sequences, stack trace tracking) is never reset between chunks. Findings are emitted immediately after each chunk — the frontend sees results before the full file is analyzed.

### Cross-log anomaly detection
Pass the same `session_id` across multiple requests to enable cross-log correlation. The session store accumulates findings and detects:
- Same IP appearing across 3+ separate log submissions → `cross_log_ip_pattern`
- Average risk level ≥ 3.0 across the last 5 findings → `escalating_risk_trend`

### Rate limiting and size guard
- 30 requests/minute per IP (slowapi token bucket)
- 10 MB payload guard via HTTP middleware (checked before body is read)
- Both return structured JSON error responses

---

## Local Setup

### Prerequisites
- Python 3.12
- An [OpenRouter](https://openrouter.ai) API key (free, no credit card)

### Steps

```bash
# 1. Clone
git clone https://github.com/gokulkc01/LogIntel-backend.git
cd LogIntel-backend

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create .env
echo OPENROUTER_API_KEY=sk-or-v1-your-key-here > .env
echo ALLOWED_ORIGINS=http://localhost:5173 >> .env

# 5. Start the server
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.
Interactive docs: `http://localhost:8000/api/docs`

### Quick smoke test

```bash
python test_api.py
```

Expected output: 7+ findings, `RISK LEVEL: CRITICAL`, 4 AI insights.

---

## Deployment (Render)

### Service settings

| Setting | Value |
|---|---|
| Runtime | Python 3.12 |
| Build command | `pip install --upgrade pip && pip install -r requirements.txt` |
| Start command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Health check path | `/` |

### Environment variables (Render dashboard)

| Variable | Value |
|---|---|
| `OPENROUTER_API_KEY` | `sk-or-v1-...` |
| `ALLOWED_ORIGINS` | `https://your-frontend.onrender.com` |
| `PYTHON_VERSION` | `3.12.8` |
| `AI_GATEWAY_MODEL` | `openrouter/free` (optional override) |
| `AI_GATEWAY_TIMEOUT_SECONDS` | `12` (optional) |

### `.python-version` file
Create this file in the repo root:
```
3.12.8
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENROUTER_API_KEY` | Yes | — | OpenRouter API key for AI insights |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173` | Comma-separated CORS origins. Use `*` for open testing |
| `AI_GATEWAY_MODEL` | No | `openrouter/free` | Model ID passed to OpenRouter |
| `AI_GATEWAY_TIMEOUT_SECONDS` | No | `12` | HTTP timeout for AI requests |
| `AI_GATEWAY_MAX_RETRIES` | No | `1` | Retry count on transient errors |

---

## Running Tests

```bash
# Install pytest
pip install pytest

# Run all tests
pytest testing/ -v

# Run a specific file
pytest testing/test_detector.py -v
pytest testing/test_log_analysis_rigorous.py -v
```

### Test coverage

| File | What it tests |
|---|---|
| `test_detector.py` | Password, API key, SQL injection, destructive SQL patterns |
| `test_log_analyzer.py` | Brute-force detection, auth sequence anomaly |
| `test_risk_engine.py` | Weighted scoring, level classification |
| `test_edge_cases.py` | Empty input, no-threat input, large input (1000 lines) |
| `test_api.py` | Full pipeline via FastAPI test client |
| `test_log_analysis_rigorous.py` | Brute-force windowing, masking, blocking, streaming state, cross-log sessions, AI gateway fallback |
| `real_attack_scenario.py` | End-to-end: failed logins + credential exposure + SQL injection |

---

## Project Structure

```
LogIntel-backend/
│
├── main.py                        # FastAPI app, CORS, rate limiter, lifespan
├── requirements.txt
├── .env.example
├── .python-version                # 3.12.8
├── runtime.txt                    # 3.12.8
├── .gitignore
│
├── routers/
│   ├── __init__.py
│   └── analyze.py                 # All routes: /analyze, /stream, /upload, /health, /metrics
│
├── core/
│   ├── __init__.py
│   ├── schemas.py                 # Pydantic models (API contract)
│   ├── patterns.py                # 19 regex patterns + mask_value()
│   ├── detector.py                # Multi-pattern line scanner
│   ├── log_analyzer.py            # Stateful brute-force / sequence / trace analyzer
│   ├── session_store.py           # Cross-request in-memory correlation store
│   ├── risk_engine.py             # Weighted score aggregation
│   ├── policy_engine.py           # Mask / block enforcement
│   ├── parser.py                  # Input dispatcher (text/log/PDF/DOCX/SQL)
│   ├── ai_client.py               # Public API: get_insights(), get_summary()
│   ├── ai_gateway.py              # OpenRouter provider + deterministic fallback
│   └── observability.py           # Structured logging + /metrics counters
│
├── testing/
│   ├── __init__.py
│   ├── conftest.py                # Fixtures: reset session store, stub AI
│   ├── test_detector.py
│   ├── test_log_analyzer.py
│   ├── test_risk_engine.py
│   ├── test_edge_cases.py
│   ├── test_api.py
│   ├── test_log_analysis_rigorous.py
│   └── real_attack_scenario.py
│
├── create_test_log.py             # Generates test.log with UTF-8 encoding
├── test_api.py                    # Quick CLI smoke test
└── test_openrouter.py             # Verifies OpenRouter key and model availability
```
