from fastapi import APIRouter, HTTPException
from pathlib import Path
import json

router = APIRouter(prefix="/runs", tags=["retrieval"])
RUNS_DIR = Path("runs")

def get_run_path(run_id: str) -> Path:
    """Validate run_id and return path, raise 404 if not found."""
    if ".." in run_id or "/" in run_id or "\\" in run_id:
        raise HTTPException(status_code=400, detail="Invalid run_id format")
    
    path = RUNS_DIR / run_id
    if not path.exists() or not path.is_dir():
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    return path

@router.get("/")
def list_runs():
    """List all available run IDs."""
    if not RUNS_DIR.exists():
        return []
    return sorted([d.name for d in RUNS_DIR.iterdir() if d.is_dir()])

@router.get("/{run_id}/meta")
def get_meta(run_id: str):
    """Get metadata for a specific run (created_at, event_count)."""
    path = get_run_path(run_id) / "meta.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Metadata not found for this run")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading metadata: {str(e)}")

@router.get("/{run_id}/normalized")
def get_normalized(run_id: str):
    """Get normalized events for a specific run."""
    path = get_run_path(run_id) / "normalized.json"
    if not path.exists():
        return {"message": "Normalized events not yet generated", "events": []}
    try:
        events = json.loads(path.read_text(encoding="utf-8"))
        return {"event_count": len(events) if isinstance(events, list) else 0, "events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading normalized events: {str(e)}")

@router.get("/{run_id}/incidents")
def get_incidents(run_id: str):
    """Get detected incidents for a specific run."""
    path = get_run_path(run_id) / "incidents.json"
    if not path.exists():
        return {"message": "Incidents not yet generated", "incidents": []}
    try:
        incidents = json.loads(path.read_text(encoding="utf-8"))
        return {"incident_count": len(incidents) if isinstance(incidents, list) else 0, "incidents": incidents}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading incidents: {str(e)}")
