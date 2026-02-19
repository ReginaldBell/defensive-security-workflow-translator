import json
from pathlib import Path
from app.services.detection import detect_incidents

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_events(name: str):
    path = REPO_ROOT / name
    return json.loads(path.read_text(encoding="utf-8"))


def _event(
    ts: str,
    ip: str,
    user: str,
    result: str = "failure",
    event_type: str = "login_attempt",
):
    return {
        "timestamp": ts,
        "source_ip": ip,
        "username": user,
        "event_type": event_type,
        "result": result,
        "reason": "bad_password",
        "source": "test",
    }


def _assert_bruteforce_snapshot(
    inc: dict,
    *,
    expected_evidence_count: int,
    expected_observed: int,
) -> None:
    assert inc.get("type") == "brute_force"
    assert inc["mitre"]["tactic"] == "Credential Access"
    assert inc["mitre"]["technique"] == "T1110"
    assert inc["mitre"]["technique_name"] == "Brute Force"
    assert isinstance(inc.get("summary"), str)
    assert inc["summary"].startswith("Brute-force authentication activity detected (MITRE ")
    assert isinstance(inc.get("recommended_actions"), list)
    assert all(isinstance(a, str) for a in inc["recommended_actions"])
    assert len(inc["recommended_actions"]) == 4

    evidence = inc.get("evidence", {})
    for k in ["window_start", "window_end", "counts", "timeline", "events"]:
        assert k in evidence

    assert isinstance(inc["confidence"], float)
    assert inc["confidence"] == 0.70
    assert inc["evidence_count"] == expected_evidence_count
    assert inc["evidence"]["counts"]["failures"] == expected_evidence_count
    assert set(inc["affected_entities"]) == {"203.0.113.10", "alice"}

    expl = inc.get("explanation")
    assert expl is not None
    assert expl["threshold"] == 5
    assert expl["observed"] == expected_observed
    assert expl["window"] == "60s"
    assert expl["trigger_field"] == "username"


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
    assert len(incidents) == 1
    _assert_bruteforce_snapshot(
        incidents[0],
        expected_evidence_count=6,
        expected_observed=5,
    )
    assert incidents[0]["source_count"] >= 1


def test_bruteforce_trigger_file_emits_bruteforce():
    events = _load_events("trigger_bruteforce.json")
    incidents = detect_incidents(events)
    assert len(incidents) == 1
    _assert_bruteforce_snapshot(
        incidents[0],
        expected_evidence_count=6,
        expected_observed=5,
    )


def test_bruteforce_7_trigger_includes_count_7():
    events = _load_events("trigger_bruteforce_7.json")
    incidents = detect_incidents(events)
    assert len(incidents) == 1
    _assert_bruteforce_snapshot(
        incidents[0],
        expected_evidence_count=7,
        expected_observed=5,
    )


def test_cred_abuse_trigger_emits_credential_abuse():
    events = _load_events("trigger_credabuse.json")
    incidents = detect_incidents(events)
    cred = [inc for inc in incidents if inc.get("type") == "credential_abuse"]
    assert cred, "Expected credential abuse incident"

    inc = cred[0]
    assert inc["mitre"]["tactic"] == "Credential Access"
    assert inc["mitre"]["technique"] == "T1110.003"
    assert inc["mitre"]["technique_name"] == "Password Spraying"
    assert inc.get("severity") == "high"
    assert isinstance(inc["confidence"], float)
    assert inc["confidence"] == 0.90
    counts = inc.get("evidence", {}).get("counts", {})
    assert counts.get("failures") == len(events)
    assert counts.get("distinct_users") == 5

    # Explainability
    expl = inc.get("explanation")
    assert expl is not None
    assert expl["threshold"] == 8  # CRED_ABUSE_FAILURE_THRESHOLD
    assert expl["observed"] == len(events)
    assert expl["trigger_field"] == "source_ip"

    # Affected entities include the IP and all distinct users
    assert "203.0.113.99" in inc["affected_entities"]
    assert len(inc["affected_entities"]) >= 6  # 1 IP + 5 users


def test_bruteforce_below_threshold_no_incident():
    events = [
        _event(f"2025-12-21T06:00:{str(i*10).zfill(2)}Z", "203.0.113.10", "alice")
        for i in range(4)
    ]
    incidents = detect_incidents(events)
    assert not incidents


def test_bruteforce_out_of_window_no_incident():
    events = [
        _event("2025-12-21T06:00:00Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:01:10Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:02:20Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:03:30Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:04:40Z", "203.0.113.10", "alice"),
    ]
    incidents = detect_incidents(events)
    assert not incidents


def test_mixed_success_does_not_trigger_bruteforce():
    events = [
        _event("2025-12-21T06:00:00Z", "203.0.113.10", "alice", "failure"),
        _event("2025-12-21T06:00:10Z", "203.0.113.10", "alice", "failure"),
        _event("2025-12-21T06:00:20Z", "203.0.113.10", "alice", "failure"),
        _event("2025-12-21T06:00:30Z", "203.0.113.10", "alice", "failure"),
        _event("2025-12-21T06:00:40Z", "203.0.113.10", "alice", "success"),
        _event("2025-12-21T06:00:50Z", "203.0.113.10", "alice", "success"),
    ]
    incidents = detect_incidents(events)
    assert not incidents


def test_cred_abuse_distinct_users_below_threshold():
    events = [
        _event("2025-12-21T06:10:00Z", "203.0.113.99", "u1"),
        _event("2025-12-21T06:10:05Z", "203.0.113.99", "u2"),
        _event("2025-12-21T06:10:10Z", "203.0.113.99", "u3"),
        _event("2025-12-21T06:10:15Z", "203.0.113.99", "u4"),
        _event("2025-12-21T06:10:20Z", "203.0.113.99", "u1"),
        _event("2025-12-21T06:10:25Z", "203.0.113.99", "u2"),
        _event("2025-12-21T06:10:30Z", "203.0.113.99", "u3"),
        _event("2025-12-21T06:10:35Z", "203.0.113.99", "u4"),
    ]
    incidents = detect_incidents(events)
    assert not incidents


def test_cred_abuse_failures_below_threshold():
    events = [
        _event("2025-12-21T06:20:00Z", "203.0.113.99", "u1"),
        _event("2025-12-21T06:20:05Z", "203.0.113.99", "u2"),
        _event("2025-12-21T06:20:10Z", "203.0.113.99", "u3"),
        _event("2025-12-21T06:20:15Z", "203.0.113.99", "u4"),
        _event("2025-12-21T06:20:20Z", "203.0.113.99", "u5"),
        _event("2025-12-21T06:20:25Z", "203.0.113.99", "u1"),
        _event("2025-12-21T06:20:30Z", "203.0.113.99", "u2"),
    ]
    incidents = detect_incidents(events)
    assert not incidents


def test_window_boundary_thresholds_are_correct():
    below_threshold = [
        _event(f"2025-12-21T06:00:{str(i*10).zfill(2)}Z", "203.0.113.10", "alice")
        for i in range(4)
    ]
    assert detect_incidents(below_threshold) == []

    on_boundary = [
        _event(f"2025-12-21T06:00:{str(i*10).zfill(2)}Z", "203.0.113.10", "alice")
        for i in range(5)
    ]
    incidents = detect_incidents(on_boundary)
    brute_force = [inc for inc in incidents if inc.get("type") == "brute_force"]
    assert len(brute_force) == 1
    assert brute_force[0]["evidence_count"] == 5
    assert brute_force[0]["explanation"]["observed"] == 5

    outside_boundary = [
        _event("2025-12-21T06:00:00Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:15Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:30Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:45Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:01:01Z", "203.0.113.10", "alice"),
    ]
    assert detect_incidents(outside_boundary) == []


def test_cross_window_separation_emits_two_distinct_bruteforce_incidents():
    events = [
        _event("2025-12-21T06:00:00Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:10Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:20Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:30Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:40Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:01:05Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:01:10Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:01:20Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:01:30Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:01:40Z", "203.0.113.10", "alice"),
    ]
    incidents = detect_incidents(events)
    brute_force = [inc for inc in incidents if inc.get("type") == "brute_force"]
    assert len(brute_force) == 2
    assert brute_force[0]["incident_id"] != brute_force[1]["incident_id"]
    assert brute_force[0]["evidence"]["window_start"] != brute_force[1]["evidence"]["window_start"]


def test_suppression_integrity_single_incident_with_full_evidence():
    events = [
        _event(f"2025-12-21T06:00:{str(i*3).zfill(2)}Z", "203.0.113.10", "alice")
        for i in range(20)
    ]
    incidents = detect_incidents(events)
    brute_force = [inc for inc in incidents if inc.get("type") == "brute_force"]
    assert len(brute_force) == 1
    inc = brute_force[0]
    assert inc["evidence_count"] == 20
    assert inc["evidence"]["counts"]["failures"] == 20
    assert inc["explanation"]["observed"] == 5
    assert len({item["incident_id"] for item in incidents}) == len(incidents)


def test_mixed_noise_only_emits_expected_incident():
    events = [
        _event("2025-12-21T06:00:00Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:10Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:20Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:30Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:40Z", "203.0.113.10", "alice"),
        _event("2025-12-21T06:00:50Z", "203.0.113.10", "alice", result="success"),
        _event("2025-12-21T06:00:55Z", "203.0.113.10", "alice", result="success"),
        _event("2025-12-21T06:00:12Z", "203.0.113.10", "alice", event_type="file_access"),
        _event("2025-12-21T06:00:18Z", "203.0.113.10", "alice", event_type="file_access"),
        _event("2025-12-21T06:00:02Z", "203.0.113.200", "noise1"),
        _event("2025-12-21T06:00:22Z", "203.0.113.200", "noise1"),
        _event("2025-12-21T06:00:42Z", "203.0.113.200", "noise1"),
    ]
    incidents = detect_incidents(events)
    brute_force = [inc for inc in incidents if inc.get("type") == "brute_force"]
    assert len(brute_force) == 1
    inc = brute_force[0]
    assert inc["subject"]["source_ip"] == "203.0.113.10"
    assert inc["subject"]["username"] == "alice"
    assert inc["evidence_count"] == 5
