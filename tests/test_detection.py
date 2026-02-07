import json
from pathlib import Path
from app.services.detection import detect_incidents

def test_brute_force_incident_fields():
    # Use a minimal, deterministic input that triggers brute-force
    events = [
        {
            "timestamp": f"2025-12-21T06:00:{str(i*10).zfill(2)}Z",
            "event_type": "login_attempt",
            "result": "failure",
            "reason": "bad_password",
            "source_ip": "203.0.113.10",
            "username": "alice",
            "source": "auth_service"
        }
        for i in range(6)
    ]
    incidents = detect_incidents(events)
    assert incidents, "No incidents detected"
    for inc in incidents:
        assert isinstance(inc.get("summary"), str)
        assert inc["summary"].startswith("Brute-force authentication activity detected (MITRE ")
        assert isinstance(inc.get("recommended_actions"), list)
        assert all(isinstance(a, str) for a in inc["recommended_actions"])
        assert len(inc["recommended_actions"]) == 4
        ev = inc.get("evidence", {})
        for k in ["window_start", "window_end", "counts", "timeline", "events"]:
            assert k in ev
