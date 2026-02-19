from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict

from app.schemas.event_models_new import NormalizedEventNew
from app.schemas.incident_new import IncidentNew


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LifecycleIncidentResponse(IncidentNew):
    is_stale: bool


class IngestResponse(_ContractModel):
    run_id: str
    event_count: int
    normalization_status: Literal["pending", "success", "failed"]
    detection_status: Literal["pending", "success", "failed"]
    incident_count: int
    incidents: List[LifecycleIncidentResponse]


class RunsMetaResponse(_ContractModel):
    created_at: str
    event_count: int
    envelope_source: Optional[str] = None
    schema_version: Optional[str] = None


class RunsNormalizedResponse(_ContractModel):
    event_count: int
    events: List[NormalizedEventNew]
    message: Optional[str] = None


class RunsIncidentsResponse(_ContractModel):
    incident_count: int
    incidents: List[IncidentNew]
    message: Optional[str] = None


class IncidentListResponse(_ContractModel):
    incident_count: int
    incidents: List[LifecycleIncidentResponse]


class IncidentPatchRequest(_ContractModel):
    status: Literal["acknowledged", "closed"]
    resolution_reason: Optional[str] = None


class EntityRiskItem(_ContractModel):
    entity_type: Literal["username", "source_ip"]
    entity_id: str
    risk_score: float
    total_incidents: int
    open_incidents: int
    highest_confidence: float
    last_seen: Optional[str] = None


class EntityRiskResponse(_ContractModel):
    generated_at: str
    decay_half_life_hours: float
    increment_weights: Dict[str, float]
    entities: List[EntityRiskItem]


class MetricsResponse(_ContractModel):
    events_ingested_total: int
    normalized_success_total: int
    telemetry_rejected_total: int
    missing_required_total: int
    events_by_source: Dict[str, int]
    incidents_total: Dict[str, int]
    runs_total: int
    incidents_created_total: int
    incidents_updated_total: int
    incidents_reopened_total: int
    incidents_closed_total: int
