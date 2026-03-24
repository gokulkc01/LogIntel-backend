from core.detector import detect

def test_empty_input():
    lines = []
    findings = detect(lines)
    assert findings == []


def test_no_threat():
    lines = [(1, "Server started successfully")]
    findings = detect(lines)
    assert len(findings) == 0


def test_large_input():
    lines = [(i, "password=admin123") for i in range(1000)]
    findings = detect(lines)

    assert len(findings) > 0