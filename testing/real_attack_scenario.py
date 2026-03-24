def test_real_attack_scenario():
    from core.detector import detect
    from core.log_analyzer import LogAnalyzer

    lines = [
        (1, "Failed login from 192.168.1.1"),
        (2, "Failed login from 192.168.1.1"),
        (3, "Failed login from 192.168.1.1"),
        (4, "Login success from 192.168.1.1"),
        (5, "api_key=sk-prod-xyz12345678901234567890"),
        (6, "SELECT * FROM users WHERE username='admin' OR '1'='1'")
    ]

    findings = detect(lines)
    analyzer = LogAnalyzer()
    findings += analyzer.analyze(lines)

    assert len(findings) > 3