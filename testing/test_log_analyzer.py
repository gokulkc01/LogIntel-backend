from core.log_analyzer import LogAnalyzer

def test_brute_force_detection():
    analyzer = LogAnalyzer()
    
    lines = [
        (1, "Failed login from 192.168.1.1"),
        (2, "Failed login from 192.168.1.1"),
        (3, "Failed login from 192.168.1.1"),
        (4, "Failed login from 192.168.1.1"),
        (5, "Failed login from 192.168.1.1"),
        (6, "Failed login from 192.168.1.1"),
    ]

    findings = analyzer.analyze(lines)

    assert any(f.type == "brute_force" for f in findings)


def test_auth_sequence_attack():
    analyzer = LogAnalyzer()

    lines = [
        (1, "Failed login from 10.0.0.1"),
        (2, "Failed login from 10.0.0.1"),
        (3, "Failed login from 10.0.0.1"),
        (4, "Login success from 10.0.0.1"),
    ]

    findings = analyzer.analyze(lines)

    assert any(f.type == "auth_sequence_anomaly" for f in findings)