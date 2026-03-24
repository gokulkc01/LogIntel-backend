from core.detector import detect

def test_password_detection():
    lines = [(1, "password=admin123")]
    findings = detect(lines)

    assert any(f.type == "password" for f in findings)


def test_api_key_detection():
    lines = [(1, "api_key=sk-abc12345678901234567890")]
    findings = detect(lines)

    assert any(f.type == "api_key" for f in findings)


def test_multiple_secrets_in_one_line():
    lines = [(1, "password=admin api_key=sk-xyz token=abc1234567890123")]
    findings = detect(lines)

    assert len(findings) >= 2


def test_sql_injection_detection():
    lines = [(1, "SELECT * FROM users WHERE username='admin' OR '1'='1'")]
    findings = detect(lines)

    assert any(f.type in ["sql_injection", "auth_bypass"] for f in findings)


def test_destructive_sql():
    lines = [(1, "DROP TABLE users")]
    findings = detect(lines)

    assert any(f.type == "destructive_sql" for f in findings)