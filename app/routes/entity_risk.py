from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from app.schemas.api_contract import EntityRiskResponse
from app.services import entity_risk as entity_risk_service
from app.services import incident_store

router = APIRouter(prefix="/entity-risk", tags=["entity-risk"])


@router.get("/", response_model=EntityRiskResponse)
def get_entity_risk():
    incidents = incident_store.list_incidents()
    rows = entity_risk_service.build_entity_risk_rows(incidents)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "decay_half_life_hours": entity_risk_service.DECAY_HALF_LIFE_HOURS,
        "increment_weights": entity_risk_service.RISK_INCREMENT_BY_TYPE,
        "entities": rows,
    }
