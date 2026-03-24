from collections import defaultdict
from datetime import datetime, timedelta
import re
from core.schemas import Finding
import core.session_store as store

TIMESTAMP_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
)
FAILED_AUTH_RE = re.compile(
    r'(failed.?login|authentication.?failed|invalid.?password|'
    r'wrong.?password|unauthorized|401|403|access.?denied)',
    re.IGNORECASE
)
SUCCESS_AUTH_RE = re.compile(
    r'(login.?success|authenticated|logged.?in|200 OK.*auth)',
    re.IGNORECASE
)
API_USE_RE = re.compile(
    r'(api.?call|GET /api|POST /api|api.?request)',
    re.IGNORECASE
)
IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
STACK_START_RE = re.compile(
    r'(Exception|Traceback|Error:|FATAL|CRITICAL)',
    re.IGNORECASE
)
DEBUG_SENSITIVE_RE = re.compile(
    r'\bDEBUG\b.{0,80}(password|token|secret|key|auth)',
    re.IGNORECASE
)
SQL_INJECTION_RE = re.compile(
    r"(union.*select|or\s+1=1|drop\s+table|--)",
    re.IGNORECASE
)

BRUTE_THRESHOLD = 5
BRUTE_WINDOW = timedelta(minutes=5)
IP_FREQ_THRESHOLD = 30


class LogAnalyzer:
    """
    Stateful analyzer — maintains context across the entire log.
    One instance per request. Tracks brute-force, sequences, stack traces.
    """

    def __init__(self, session_id: str = "default"):
        self.session_id = session_id
        self._failed_attempts: dict[str, list[datetime]] = defaultdict(list)
        self._ip_counts: dict[str, int] = defaultdict(int)
        self._reported_brute: set[str] = set()
        self._reported_ip: set[str] = set()
        self._in_stack = False
        self._stack_start = 0
        # Correlation state: track sequences per IP
        self._auth_sequences: dict[str, list[str]] = defaultdict(list)

    def analyze(self, lines: list[tuple[int, str]]) -> list[Finding]:
        findings: list[Finding] = []

        for line_num, text in lines:
            ip = self._extract_ip(text)
            ts = self._parse_timestamp(text)
            
            # --- IP frequency ---
            if ip:
                self._ip_counts[ip] += 1
                store.record_event(ip, "seen", "low")

                if (self._ip_counts[ip] >= IP_FREQ_THRESHOLD
                        and ip not in self._reported_ip):
                    self._reported_ip.add(ip)
                    findings.append(Finding(
                        type="suspicious_ip",
                        risk="high",
                        line=line_num,
                        value=f"{ip} appeared {self._ip_counts[ip]}+ times"
                    ))
            #---SQL -----
            if SQL_INJECTION_RE.search(text):
               findings.append(Finding(
               type="sql_injection",
               risk="critical",
               line=line_num,
               value="SQL injection pattern detected"
                ))        

            # --- Auth event correlation (failed → success → API) ---
            if FAILED_AUTH_RE.search(text):
                key = ip or "unknown"
                now = ts or datetime.now()
                self._failed_attempts[key].append(now)
                self._failed_attempts[key] = [
                    t for t in self._failed_attempts[key]
                    if now - t <= BRUTE_WINDOW
                ]
                self._auth_sequences[key].append("failed")
                if ip:
                    store.record_auth_event(ip, "failed")

                count = len(self._failed_attempts[key])
                if count >= BRUTE_THRESHOLD and key not in self._reported_brute:
                    self._reported_brute.add(key)
                    findings.append(Finding(
                        type="brute_force",
                        risk="critical",
                        line=line_num,
                        value=f"{count} failed attempts in 5 min from {key}"
                    ))

            elif SUCCESS_AUTH_RE.search(text):
                key = ip or "unknown"
                self._auth_sequences[key].append("success")
                if ip:
                    store.record_auth_event(ip, "success")

                # Correlation: failed_logins → success = possible breach
                seq = self._auth_sequences[key]
                failed_before = seq.count("failed")
                if failed_before >= 3 and seq[-1] == "success":
                    findings.append(Finding(
                        type="auth_sequence_anomaly",
                        risk="critical",
                        line=line_num,
                        value=(
                            f"Successful login after {failed_before} failures "
                            f"from {key} — possible credential stuffing or breach"
                        )
                    ))
                    # Also check global breach pattern
                    breach = store.check_breach_sequence(key)
                    if breach:
                        findings.append(Finding(
                            type="cross_session_breach",
                            risk="critical",
                            line=line_num,
                            value=breach
                        ))

            elif API_USE_RE.search(text) and ip:
                self._auth_sequences[ip].append("api_use")
                store.record_auth_event(ip, "api_use")

            # --- Debug mode leak ---
            if DEBUG_SENSITIVE_RE.search(text):
                findings.append(Finding(
                    type="debug_leak",
                    risk="high",
                    line=line_num,
                    value="DEBUG log contains sensitive field name"
                ))

            # --- Stack trace state machine ---
            if STACK_START_RE.search(text) and not self._in_stack:
                self._in_stack = True
                self._stack_start = line_num

            elif self._in_stack:
                if not text.strip() or (
                    TIMESTAMP_RE.match(text) and not text.strip().startswith(" ")
                ):
                    findings.append(Finding(
                        type="stack_trace_block",
                        risk="medium",
                        line=self._stack_start,
                        value=f"Stack trace lines {self._stack_start}–{line_num}"
                    ))
                    self._in_stack = False

        # Close any open stack trace at end of input
        if self._in_stack:
            findings.append(Finding(
                type="stack_trace_block",
                risk="medium",
                line=self._stack_start,
                value=f"Stack trace from line {self._stack_start} to end of log"
            ))

        return findings

    def _parse_timestamp(self, text: str) -> datetime | None:
        m = TIMESTAMP_RE.search(text)
        if not m:
            return None
        try:
            return datetime.strptime(
                m.group(1).replace("T", " "), "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            return None

    def _extract_ip(self, text: str) -> str | None:
        m = IP_RE.search(text)
        return m.group(0) if m else None