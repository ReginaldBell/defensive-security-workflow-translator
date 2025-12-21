from fastapi import FastAPI
from app.routes.ingest import router as ingest_router

app = FastAPI(title="Defensive Security Workflow Translator")

app.include_router(ingest_router)

@app.get("/health")
def health():
    return {"ok": True}
