from fastapi.testclient import TestClient

import core.ai_client as ai_client
from core.ai_gateway import AIGateway, GatewayResult, build_prompt, redact_excerpt
from core.log_analyzer import LogAnalyzer
from core.parser import _from_doc
from main import app


client = TestClient(app)


def finding_types(findings):
    return {f.type for f in findings}


def test_brute_force_requires_five_minute_window():
    analyzer = LogAnalyzer()

    lines = [
        (1, "2026-03-24 10:00:00 Failed login from 10.10.10.10"),
        (2, "2026-03-24 10:01:00 Failed login from 10.10.10.10"),
        (3, "2026-03-24 10:02:00 Failed login from 10.10.10.10"),
        (4, "2026-03-24 10:03:00 Failed login from 10.10.10.10"),
        (5, "2026-03-24 10:04:00 Failed login from 10.10.10.10"),
    ]

    findings = analyzer.analyze(lines)

    assert "brute_force" in finding_types(findings)


def test_brute_force_does_not_trigger_outside_window():
    analyzer = LogAnalyzer()

    lines = [
        (1, "2026-03-24 10:00:00 Failed login from 10.10.10.10"),
        (2, "2026-03-24 10:06:00 Failed login from 10.10.10.10"),
        (3, "2026-03-24 10:12:00 Failed login from 10.10.10.10"),
        (4, "2026-03-24 10:18:00 Failed login from 10.10.10.10"),
        (5, "2026-03-24 10:24:00 Failed login from 10.10.10.10"),
    ]

    findings = analyzer.analyze(lines)

    assert "brute_force" not in finding_types(findings)


def test_suspicious_ip_threshold_detected_once():
    analyzer = LogAnalyzer()
    lines = [
        (i, f"2026-03-24 10:00:{i:02d} GET /api/orders from 172.16.0.9")
        for i in range(30)
    ]

    findings = analyzer.analyze(lines)
    suspicious = [f for f in findings if f.type == "suspicious_ip"]

    assert len(suspicious) == 1
    assert suspicious[0].risk == "high"


def test_debug_leak_and_stack_trace_are_flagged():
    analyzer = LogAnalyzer()
    lines = [
        (1, "2026-03-24 10:00:00 DEBUG password reset token issued"),
        (2, "2026-03-24 10:01:00 ERROR NullPointerException"),
        (3, "    at service.Auth.login(Auth.java:42)"),
        (4, "2026-03-24 10:01:02 INFO request complete"),
    ]

    findings = analyzer.analyze(lines)

    assert "debug_leak" in finding_types(findings)
    assert "stack_trace_block" in finding_types(findings)


def test_full_api_analysis_masks_and_blocks_as_expected():
    content = "\n".join(
        [f"2026-03-24 10:00:0{i} Failed login from 192.168.0.5" for i in range(5)]
    )

    masked = client.post("/api/analyze", json={
        "input_type": "log",
        "content": content,
        "options": {
            "mask": True,
            "block_high_risk": False,
            "log_analysis": True,
        },
    })

    assert masked.status_code == 200
    masked_data = masked.json()
    assert masked_data["action"] == "masked"
    assert all(f["value"] == "[REDACTED]" for f in masked_data["findings"])

    blocked = client.post("/api/analyze", json={
        "input_type": "log",
        "content": content,
        "options": {
            "mask": False,
            "block_high_risk": True,
            "log_analysis": True,
        },
    })

    assert blocked.status_code == 403
    assert blocked.json()["detail"]["action"] == "blocked"


def test_streaming_analysis_keeps_state_across_chunks():
    lines = [
        f"2026-03-24 10:{i // 60:02d}:{i % 60:02d} Failed login from 203.0.113.9"
        for i in range(55)
    ]
    payload = {
        "input_type": "log",
        "content": "\n".join(lines),
        "options": {
            "mask": False,
            "block_high_risk": False,
            "log_analysis": True,
        },
    }

    with client.stream("POST", "/api/analyze/stream", json=payload) as response:
        chunks = list(response.iter_text())

    assert response.status_code == 200
    body = "".join(chunks)
    assert '"event": "findings"' in body
    assert '"event": "complete"' in body
    assert '"risk_level": "critical"' in body
    assert '"type": "brute_force"' in body
    assert '"type": "suspicious_ip"' in body


def test_cross_log_session_anomalies_surface_in_followup_request():
    payloads = [
        {
            "input_type": "log",
            "content": (
                "Failed login from 198.51.100.7\n"
                "password=supersecret\n"
                "api_key=sk-prod-abcdefghij1234567890"
            ),
            "options": {
                "mask": False,
                "block_high_risk": False,
                "log_analysis": True,
                "session_id": "rigorous-session",
            },
        },
        {
            "input_type": "log",
            "content": (
                "Failed login from 198.51.100.7\n"
                "SELECT * FROM users WHERE username='admin' OR '1'='1'\n"
                "password=anothersecret"
            ),
            "options": {
                "mask": False,
                "block_high_risk": False,
                "log_analysis": True,
                "session_id": "rigorous-session",
            },
        },
        {
            "input_type": "log",
            "content": (
                "GET /api/admin from 198.51.100.7\n"
                "DROP TABLE users\n"
                "api_key=sk-prod-zyxwvutsrq9876543210"
            ),
            "options": {
                "mask": False,
                "block_high_risk": False,
                "log_analysis": True,
                "session_id": "rigorous-session",
            },
        },
    ]

    for payload in payloads:
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200

    summary = client.get("/api/session/rigorous-session/summary")

    assert summary.status_code == 200
    data = summary.json()
    anomaly_types = {item["type"] for item in data["cross_log_anomalies"]}
    assert "cross_log_ip_pattern" in anomaly_types
    assert "escalating_risk_trend" in anomaly_types


def test_log_analysis_option_disables_stateful_analyzer():
    content = "\n".join(
        [f"2026-03-24 10:00:0{i} Failed login from 192.168.0.5" for i in range(5)]
    )

    response = client.post("/api/analyze", json={
        "input_type": "log",
        "content": content,
        "options": {
            "mask": False,
            "block_high_risk": False,
            "log_analysis": False,
        },
    })

    assert response.status_code == 200
    findings = response.json()["findings"]
    finding_types = {finding["type"] for finding in findings}
    assert "brute_force" not in finding_types


def test_multipart_upload_analysis_handles_log_file():
    content = "\n".join(
        [f"2026-03-24 10:00:0{i} Failed login from 192.168.0.5" for i in range(5)]
    ).encode("utf-8")

    response = client.post(
        "/api/analyze/upload",
        data={
            "input_type": "log",
            "mask": "false",
            "block_high_risk": "false",
            "log_analysis": "true",
        },
        files={"file": ("attack.log", content, "text/plain")},
    )

    assert response.status_code == 200
    finding_types = {finding["type"] for finding in response.json()["findings"]}
    assert "brute_force" in finding_types


def test_multipart_stream_upload_handles_log_file():
    content = "\n".join(
        f"2026-03-24 10:{i // 60:02d}:{i % 60:02d} Failed login from 203.0.113.9"
        for i in range(55)
    ).encode("utf-8")

    with client.stream(
        "POST",
        "/api/analyze/upload/stream",
        data={
            "input_type": "log",
            "mask": "false",
            "block_high_risk": "false",
            "log_analysis": "true",
        },
        files={"file": ("attack.log", content, "text/plain")},
    ) as response:
        body = "".join(response.iter_text())

    assert response.status_code == 200
    assert '"event": "complete"' in body
    assert '"type": "brute_force"' in body


def test_ai_client_fallback_insights_are_actionable(monkeypatch):
    monkeypatch.setattr(
        ai_client,
        "_gateway",
        type("FallbackGateway", (), {
            "generate_insights": staticmethod(
                lambda findings, excerpt="": GatewayResult(
                    insights=[
                        "Sensitive credentials appear in the captured data; rotate any exposed secrets and move them into a managed secret store.",
                        "Application internals are leaking through logs; reduce verbose logging in production and scrub sensitive debug output.",
                    ],
                    provider="fallback",
                    model="deterministic",
                    used_fallback=True,
                    reason="forced test fallback",
                )
            )
        })(),
    )

    findings = [
        ai_client.Finding(type="password", risk="critical", line=1, value="password=secret"),
        ai_client.Finding(type="stack_trace_block", risk="medium", line=2, value="trace"),
    ]

    insights = ai_client.get_insights(findings, "password=secret")

    assert insights
    joined = " ".join(insights).lower()
    assert "rotate" in joined or "review" in joined
    assert "logging" in joined or "credential" in joined


def test_legacy_doc_parsing_returns_safe_message_for_unreadable_content():
    unreadable_doc = "0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAA"

    lines = _from_doc(unreadable_doc)

    assert lines
    assert "DOC parse warning" in lines[0][1]


def test_ai_gateway_redacts_secrets_before_provider_prompt():
    excerpt = "password=admin123 api_key=sk-secret-value token=abc123456789"

    redacted = redact_excerpt(excerpt)
    prompt = build_prompt(
        [ai_client.Finding(type="password", risk="critical", line=1, value="password=admin123")],
        redacted,
    )

    assert "admin123" not in redacted
    assert "sk-secret-value" not in redacted
    assert "abc123456789" not in redacted
    assert "[REDACTED]" in prompt


def test_ai_gateway_uses_provider_when_available():
    class FakeProvider:
        name = "fake-provider"
        unavailable_reason = None

        def is_available(self):
            return True

        def generate_insights(self, prompt, model):
            assert "[REDACTED]" in prompt
            assert model == "fake-model"
            return ["Provider insight 1", "Provider insight 2"]

    gateway = AIGateway(provider=FakeProvider(), model="fake-model")
    findings = [ai_client.Finding(type="api_key", risk="high", line=1, value="api_key=abc")]

    result = gateway.generate_insights(findings, "api_key=abc123456789")

    assert result.provider == "fake-provider"
    assert result.used_fallback is False
    assert result.insights == ["Provider insight 1", "Provider insight 2"]


def test_ai_gateway_falls_back_when_provider_unavailable():
    class UnavailableProvider:
        name = "fake-provider"
        unavailable_reason = "not configured"

        def is_available(self):
            return False

    gateway = AIGateway(provider=UnavailableProvider(), model="fake-model")
    findings = [ai_client.Finding(type="password", risk="critical", line=1, value="password=secret")]

    result = gateway.generate_insights(findings, "password=secret")

    assert result.used_fallback is True
    assert result.reason == "not configured"
    assert any("rotate" in item.lower() for item in result.insights)
