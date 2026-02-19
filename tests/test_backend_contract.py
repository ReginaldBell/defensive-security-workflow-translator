from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from app.routes import incidents as incidents_route
from app.routes import entity_risk as entity_risk_route
from app.routes import ingest as ingest_route
from app.routes import metrics as metrics_route
from app.routes import retrieval as retrieval_route
from app.schemas.api_contract import (
    IncidentListResponse,
    EntityRiskResponse,
    IngestResponse,
    MetricsResponse,
    RunsIncidentsResponse,
    RunsMetaResponse,
    RunsNormalizedResponse,
)
from app.schemas.incident_new import IncidentNew
from app.services import incident_store


class _DummyRequest:
    def __init__(self, body):
        self._body = body

    async def json(self):
        return self._body


def _sample_bruteforce_events() -> list[dict]:
    return [
        {
            "timestamp": f"2025-12-21T06:00:{str(i*10).zfill(2)}Z",
            "event_type": "login_attempt",
            "result": "failure",
            "reason": "bad_password",
            "source_ip": "203.0.113.10",
            "username": "alice",
            "source": "auth_service",
        }
        for i in range(5)
    ]


def _sample_incident() -> IncidentNew:
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return IncidentNew(
        incident_id="inc_contract_001",
        type="brute_force",
        mitre_technique="T1110",
        severity="low",
        confidence=0.70,
        first_seen=ts,
        last_seen=ts,
        affected_entities=["203.0.113.10", "alice"],
        evidence_count=5,
        source_count=1,
        summary="contract test",
        recommended_actions=["review logs"],
        explanation={
            "threshold": 5,
            "observed": 5,
            "window": "60s",
            "trigger_field": "username",
        },
        subject={"source_ip": "203.0.113.10", "username": "alice"},
        evidence={
            "window_start": ts,
            "window_end": ts,
            "counts": {"failures": 5},
            "timeline": [],
            "events": [],
        },
    )


def test_ingest_response_contract_is_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store, "_STORE_PATH", tmp_path / "runs" / "incidents.json")
    monkeypatch.setattr(incident_store, "_incidents_by_id", {})
    monkeypatch.setattr(incident_store, "_loaded", False)
    incident_store.load_store()

    payload = {"events": _sample_bruteforce_events(), "source": "qa", "schema_version": "v1"}
    response = asyncio.run(ingest_route.ingest_events(_DummyRequest(payload)))

    validated = IngestResponse.model_validate(response)
    assert set(response.keys()) == {
        "run_id",
        "event_count",
        "normalization_status",
        "detection_status",
        "incident_count",
        "incidents",
    }
    assert validated.event_count == 5
    assert validated.incident_count == len(validated.incidents)


def test_retrieval_response_contracts_are_stable(tmp_path, monkeypatch):
    runs_root = tmp_path / "runs"
    run_dir = runs_root / "run-contract"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "meta.json").write_text(
        json.dumps({"created_at": "2026-01-01T00:00:00Z", "event_count": 1}),
        encoding="utf-8",
    )

    monkeypatch.setattr(retrieval_route, "RUNS_DIR", runs_root)

    meta = retrieval_route.get_meta("run-contract")
    normalized = retrieval_route.get_normalized("run-contract")
    incidents = retrieval_route.get_incidents("run-contract")

    RunsMetaResponse.model_validate(meta)
    RunsNormalizedResponse.model_validate(normalized)
    RunsIncidentsResponse.model_validate(incidents)

    assert normalized["event_count"] == 0
    assert incidents["incident_count"] == 0


def test_incidents_response_contract_is_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store, "_STORE_PATH", tmp_path / "runs" / "incidents.json")
    monkeypatch.setattr(incident_store, "_incidents_by_id", {})
    monkeypatch.setattr(incident_store, "_loaded", False)
    incident_store.load_store()
    incident_store.upsert_incident(_sample_incident())

    response = incidents_route.list_incidents()
    validated = IncidentListResponse.model_validate(response)

    assert validated.incident_count == 1
    assert validated.incidents[0].incident_id == "inc_contract_001"
    assert isinstance(validated.incidents[0].is_stale, bool)


def test_metrics_response_contract_is_stable():
    response = metrics_route.get_metrics()
    validated = MetricsResponse.model_validate(response)
    assert validated.runs_total >= 0


def test_entity_risk_response_contract_is_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store, "_STORE_PATH", tmp_path / "runs" / "incidents.json")
    monkeypatch.setattr(incident_store, "_incidents_by_id", {})
    monkeypatch.setattr(incident_store, "_loaded", False)
    incident_store.load_store()
    incident_store.upsert_incident(_sample_incident())

    response = entity_risk_route.get_entity_risk()
    validated = EntityRiskResponse.model_validate(response)

    assert validated.decay_half_life_hours > 0
    assert "brute_force" in validated.increment_weights
    assert len(validated.entities) >= 1
