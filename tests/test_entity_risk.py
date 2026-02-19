from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.schemas.incident_new import IncidentNew
from app.services import entity_risk as entity_risk_service


def _ts(base: datetime, seconds: int = 0) -> str:
    return (base + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _incident(
    incident_id: str,
    *,
    incident_type: str,
    source_ip: str,
    username: str,
    affected_entities: list[str],
    last_seen: str,
) -> IncidentNew:
    technique = "T1110.003" if incident_type == "credential_abuse" else "T1110"
    return IncidentNew(
        incident_id=incident_id,
        type=incident_type,
        mitre_technique=technique,
        severity="high",
        confidence=0.9,
        first_seen=last_seen,
        last_seen=last_seen,
        affected_entities=affected_entities,
        evidence_count=8,
        source_count=1,
        summary="risk test incident",
        recommended_actions=["investigate"],
        explanation={
            "threshold": 5,
            "observed": 5,
            "window": "60s",
            "trigger_field": "username",
        },
        subject={"source_ip": source_ip, "username": username},
        evidence={
            "window_start": last_seen,
            "window_end": last_seen,
            "counts": {"failures": 8},
            "timeline": [],
            "events": [],
        },
    )


def _row(rows: list[dict], *, entity_type: str, entity_id: str) -> dict:
    for item in rows:
        if item["entity_type"] == entity_type and item["entity_id"] == entity_id:
            return item
    raise AssertionError(f"Missing row for {entity_type}:{entity_id}")


def test_entity_risk_accumulates_by_detection_type(monkeypatch):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ts = _ts(base)

    brute_force = _incident(
        "inc_risk_001",
        incident_type="brute_force",
        source_ip="203.0.113.10",
        username="alice",
        affected_entities=["203.0.113.10", "alice"],
        last_seen=ts,
    )
    cred_abuse = _incident(
        "inc_risk_002",
        incident_type="credential_abuse",
        source_ip="203.0.113.10",
        username="multiple_accounts",
        affected_entities=["203.0.113.10", "alice", "bob", "charlie", "dave", "eve"],
        last_seen=ts,
    )

    monkeypatch.setattr(entity_risk_service, "_utcnow", lambda: base)
    entity_risk_service.rehydrate([brute_force, cred_abuse])
    rows = entity_risk_service.build_entity_risk_rows([brute_force, cred_abuse])

    source_ip_row = _row(rows, entity_type="source_ip", entity_id="203.0.113.10")
    assert source_ip_row["risk_score"] == 35.0

    alice_row = _row(rows, entity_type="username", entity_id="alice")
    assert alice_row["risk_score"] == 35.0
    assert alice_row["total_incidents"] == 2


def test_entity_risk_decays_over_time(monkeypatch):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    incident = _incident(
        "inc_risk_decay_001",
        incident_type="brute_force",
        source_ip="203.0.113.10",
        username="alice",
        affected_entities=["203.0.113.10", "alice"],
        last_seen=_ts(base),
    )

    monkeypatch.setattr(entity_risk_service, "_utcnow", lambda: base)
    entity_risk_service.rehydrate([incident])

    half_life_later = base + timedelta(hours=24)
    monkeypatch.setattr(entity_risk_service, "_utcnow", lambda: half_life_later)
    rows = entity_risk_service.build_entity_risk_rows([incident])

    source_ip_row = _row(rows, entity_type="source_ip", entity_id="203.0.113.10")
    assert 4.9 <= float(source_ip_row["risk_score"]) <= 5.1
