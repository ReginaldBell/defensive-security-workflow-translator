from fastapi import APIRouter
from app.services import metrics as metrics_service
from app.schemas.api_contract import MetricsResponse

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/", response_model=MetricsResponse)
def get_metrics():
    return metrics_service.get_metrics()
