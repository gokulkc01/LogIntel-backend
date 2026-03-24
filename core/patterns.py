import re
from typing import Literal

RiskLevel = Literal["low", "medium", "high", "critical"]

PATTERNS: list[tuple[re.Pattern, RiskLevel, str]] = [

    # ── Credentials ──
    (
        re.compile(r'(password|passwd|pwd)\s*[=:]\s*\S+', re.IGNORECASE),
        "critical",
        "password"
    ),
    (
        re.compile(
            r'(sk-[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z\-_]{35}|'
            r'api[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9\-_]{16,})',
            re.IGNORECASE
        ),
        "high",
        "api_key"
    ),
    (
        re.compile(
            r'(token|jwt|bearer|auth[_-]?token)\s*[=:]\s*["\']?[a-zA-Z0-9\-_.]{16,}',
            re.IGNORECASE
        ),
        "high",
        "token"
    ),
    (
        re.compile(
            r'(secret[_-]?key|client[_-]?secret|access[_-]?key)\s*[=:]\s*\S+',
            re.IGNORECASE
        ),
        "high",
        "secret"
    ),
    (
        re.compile(
            r'(mongodb(\+srv)?://|postgresql://|mysql://|redis://)[^\s\'"]{8,}',
            re.IGNORECASE
        ),
        "critical",
        "connection_string"
    ),

    # ── PII ──
    (
        re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "low",
        "email"
    ),
    (
        re.compile(r'\b(\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{4})\b'),
        "low",
        "phone"
    ),
    (
        re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        "low",
        "ip_address"
    ),

    # ── System leaks ──
    (
        re.compile(
            r'(Exception|Traceback|NullPointerException|'
            r'StackOverflowError|at \w+\.\w+\(.*:\d+\))',
            re.IGNORECASE
        ),
        "medium",
        "stack_trace"
    ),
    (
        re.compile(r'\bDEBUG\b.{0,80}(password|token|secret|key)', re.IGNORECASE),
        "high",
        "debug_leak"
    ),

    # ── SQL Injection ──
    (
        re.compile(r"(\bor\b\s+1\s*=\s*1|\bunion\b.{0,40}\bselect\b)", re.IGNORECASE),
        "critical",
        "sql_injection"
    ),
    (
        re.compile(r"\b(drop\s+table|truncate\s+table|delete\s+from)\b", re.IGNORECASE),
        "critical",
        "destructive_sql"
    ),
    (
        re.compile(r"select\s+.{0,60}\s+from\s+.{0,40}--", re.IGNORECASE),
        "high",
        "sql_comment_injection"
    ),
    (
        re.compile(r"(select\s+.{0,60}(password|ssn|credit|token).{0,30}\s+from)", re.IGNORECASE),
        "high",
        "sensitive_data_query"
    ),

    # ── Auth bypass ──
    (
        re.compile(r"(admin'?\s*--|'\s*or\s*'1'\s*=\s*'1)", re.IGNORECASE),
        "critical",
        "auth_bypass"
    ),

    # ── Injection attacks ──
    (
        re.compile(r"\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(", re.IGNORECASE),
        "high",
        "time_based_injection"
    ),
    (
        re.compile(r"(;|\|\||&&)\s*(rm|wget|curl|bash|sh)\b", re.IGNORECASE),
        "critical",
        "command_injection"
    ),
    (
        re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
        "high",
        "code_injection"
    ),
    (
        re.compile(r"\bbase64_decode\s*\(|\batob\s*\(", re.IGNORECASE),
        "high",
        "encoded_payload"
    ),
]


def mask_value(value: str) -> str:
    if len(value) <= 4:
        return "[REDACTED]"
    return value[:4] + "[REDACTED]"