from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from app.routes.ingest import router as ingest_router
from app.routes.retrieval import router as retrieval_router
from pathlib import Path

app = FastAPI(title="Defensive Security Workflow Translator")

# Enable CORS for frontend testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router)
app.include_router(retrieval_router)

@app.get("/health")
def health():
    return {"ok": True}

# Serve the dashboard as static files
dashboard_path = Path(__file__).parent.parent / "dashboard" / "dist"
if dashboard_path.exists():
    app.mount("/", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")