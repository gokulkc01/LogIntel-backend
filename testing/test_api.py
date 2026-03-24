from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_full_analysis():
    response = client.post("/api/analyze", json={
        "input_type": "log",
        "content": "password=admin123 api_key=sk-xyz12345678901234567890",
        "options": {}
    })

    assert response.status_code == 200
    data = response.json()

    assert data["risk_level"] in ["high", "critical"]
    assert len(data["findings"]) > 0