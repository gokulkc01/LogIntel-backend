from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock
from core.schemas import Finding

# Global in-memory store — survives across requests within one server session
_lock = Lock()

# ip -> list of {"timestamp": datetime, "event": str, "risk": str}
_ip_timeline: dict[str, list[dict]] = defaultdict(list)

# session_id -> list of Finding (cross-log correlation)
_session_findings: dict[str, list[Finding]] = defaultdict(list)

# ip -> {"failed": int, "success": bool, "api_used": bool}
_auth_state: dict[str, dict] = defaultdict(
    lambda: {"failed": 0, "success": False, "api_used": False}
)

WINDOW = timedelta(hours=1)


def record_event(ip: str, event: str, risk: str) -> None:
    with _lock:
        _ip_timeline[ip].append({
            "timestamp": datetime.now(),
            "event": event,
            "risk": risk
        })
        # Prune events older than window
        cutoff = datetime.now() - WINDOW
        _ip_timeline[ip] = [
            e for e in _ip_timeline[ip]
            if e["timestamp"] > cutoff
        ]


def record_auth_event(ip: str, event_type: str) -> None:
    """Track failed login → success → API usage sequence."""
    with _lock:
        state = _auth_state[ip]
        if event_type == "failed":
            state["failed"] += 1
        elif event_type == "success":
            state["success"] = True
        elif event_type == "api_use":
            state["api_used"] = True


def check_breach_sequence(ip: str) -> str | None:
    """
    Detect: failed_logins > 5 → success → API usage
    Returns a breach description or None.
    """
    with _lock:
        state = _auth_state.get(ip)
        if not state:
            return None
        if state["failed"] >= 5 and state["success"]:
            if state["api_used"]:
                return (
                    f"Possible account breach: {state['failed']} failed logins "
                    f"followed by successful auth and API usage from {ip}"
                )
            return (
                f"Suspicious auth pattern: {state['failed']} failed logins "
                f"followed by successful login from {ip}"
            )
    return None


def add_session_findings(session_id: str, findings: list[Finding]) -> None:
    with _lock:
        _session_findings[session_id].extend(findings)


def get_cross_log_anomalies(session_id: str) -> list[Finding]:
    """
    Compare current session findings against all previous findings
    in the same session to detect cross-log patterns.
    """
    with _lock:
        all_findings = _session_findings.get(session_id, [])

    anomalies: list[Finding] = []
    if not all_findings:
        return anomalies

    # Count repeated IPs across logs
    from collections import Counter
    ip_counts = Counter(
        f.value.split()[0] if f.value else ""
        for f in all_findings
        if f.type in ("suspicious_ip", "ip_address")
    )
    for ip, count in ip_counts.items():
        if ip and count >= 3:
            anomalies.append(Finding(
                type="cross_log_ip_pattern",
                risk="high",
                line=0,
                value=f"IP {ip} appeared across {count} separate log submissions"
            ))

    # Detect escalating risk across logs
    risk_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if len(all_findings) >= 5:
        recent = all_findings[-5:]
        avg_risk = sum(risk_order[f.risk] for f in recent) / len(recent)
        if avg_risk >= 3.0:
            anomalies.append(Finding(
                type="escalating_risk_trend",
                risk="critical",
                line=0,
                value="Risk level has been consistently high/critical across recent submissions"
            ))

    return anomalies


def get_ip_summary(ip: str) -> dict:
    with _lock:
        return {
            "ip": ip,
            "event_count": len(_ip_timeline.get(ip, [])),
            "auth_state": dict(_auth_state.get(ip, {}))
        }