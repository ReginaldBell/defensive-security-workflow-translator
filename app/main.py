from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from app.routes.entity_risk import router as entity_risk_router
from app.routes.ingest import router as ingest_router
from app.routes.incidents import router as incidents_router
from app.routes.retrieval import router as retrieval_router
from app.routes.metrics import router as metrics_router
from pathlib import Path
import logging

from app.services.mapping_loader import load_mappings as _load_mappings
from app.services.entity_risk import rehydrate as _rehydrate_entity_risk
from app.services.incident_store import load_store as _load_incident_store
from app.services.incident_store import list_incidents as _list_incidents
from app.services.metrics import rehydrate as _rehydrate_metrics

logger = logging.getLogger(__name__)

# Warm the mapping loader cache at startup — surfaces bad config immediately
# rather than on the first ingest request.
try:
    _load_mappings()
except RuntimeError as _e:
    logger.error(f"Field mapping config failed to load at startup: {_e}")

app = FastAPI(title="SecureWatch Engine")

# Enable CORS for frontend testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router)
app.include_router(incidents_router)
app.include_router(entity_risk_router)
app.include_router(retrieval_router)
app.include_router(metrics_router)

# Load persistent incident lifecycle state from runs/incidents.json.
try:
    _load_incident_store()
except Exception as _e:
    logger.warning(f"Incident store rehydration failed: {_e}")

# Build in-memory entity risk state from persisted incidents.
try:
    _rehydrate_entity_risk(_list_incidents())
except Exception as _e:
    logger.warning(f"Entity risk rehydration failed: {_e}")

# Rehydrate metrics counters from existing run artifacts
try:
    _rehydrate_metrics(Path("runs"))
except Exception as _e:
    logger.warning(f"Metrics rehydration failed: {_e}")

@app.get("/health")
def health():
    return {"ok": True}

# Serve the dashboard as static files
dashboard_path = Path(__file__).parent.parent / "dashboard" / "dist"
if dashboard_path.exists():
    app.mount("/", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")
