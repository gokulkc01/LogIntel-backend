import pytest

import core.session_store as store


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    store._ip_timeline.clear()
    store._session_findings.clear()
    store._auth_state.clear()

    monkeypatch.setattr(
        "routers.analyze.get_insights",
        lambda findings, excerpt="": [
            f"stub insight for {len(findings)} finding(s)"
        ],
    )
