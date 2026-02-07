from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from uuid import uuid4
from datetime import datetime
import json
import os
import logging
from pathlib import Path
from app.services.normalization import normalize_run
from app.services.detection import detect_run

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])

RUNS_DIR = "runs"


@router.post("/")
def ingest_events(events: List[Dict[str, Any]]):
    if not events:
        raise HTTPException(status_code=400, detail="No events provided")

    run_id = f"run-{uuid4().hex}"
    run_path = os.path.join(RUNS_DIR, run_id)
    os.makedirs(run_path, exist_ok=True)

    raw_path = os.path.join(run_path, "raw.json")
    meta_path = os.path.join(run_path, "meta.json")

    with open(raw_path, "w") as f:
        json.dump(events, f, indent=2)

    meta = {
        "created_at": datetime.utcnow().isoformat(),
        "event_count": len(events)
    }

    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Created run {run_id} with {len(events)} raw events")

    # Phase 2: Generate normalized artifacts (best effort, does not affect response)
    normalization_status = "pending"
    try:
        normalize_run(run_id=run_id, runs_root=Path("runs"))
        logger.info(f"Successfully normalized run {run_id}")
        normalization_status = "success"
    except Exception as e:
        logger.error(f"Normalization failed for {run_id}: {str(e)}")
        normalization_status = "failed"

    # Phase 3: Generate detection artifacts (best effort, does not affect response)
    detection_status = "pending"
    try:
        detect_run(run_id=run_id, runs_root=Path("runs"))
        logger.info(f"Successfully detected incidents for run {run_id}")
        detection_status = "success"
    except Exception as e:
        logger.error(f"Detection failed for {run_id}: {str(e)}")
        detection_status = "failed"

    return {
        "run_id": run_id,
        "event_count": len(events),
        "normalization_status": normalization_status,
        "detection_status": detection_status
    }