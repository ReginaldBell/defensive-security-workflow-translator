from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services import incident_store
from app.schemas.api_contract import (
    IncidentListResponse,
    IncidentPatchRequest,
    LifecycleIncidentResponse,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/", response_model=IncidentListResponse)
def list_incidents():
    incidents = incident_store.list_incidents()
    return {
        "incident_count": len(incidents),
        "incidents": [incident_store.incident_to_response(inc) for inc in incidents],
    }


@router.get("/{incident_id}", response_model=LifecycleIncidentResponse)
def get_incident(incident_id: str):
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_store.incident_to_response(incident)


@router.patch("/{incident_id}", response_model=LifecycleIncidentResponse)
def patch_incident(incident_id: str, payload: IncidentPatchRequest):
    try:
        incident = incident_store.transition_incident(
            incident_id=incident_id,
            status=payload.status,
            resolution_reason=payload.resolution_reason,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Incident not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return incident_store.incident_to_response(incident)
