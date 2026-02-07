from pydantic import BaseModel
from typing import Optional

class NormalizedEventNew(BaseModel):
    timestamp: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str = "login_attempt"
    result: str  # "failure" | "success"
    reason: Optional[str] = None
    user_agent: Optional[str] = None
    source: str = "auth_service"
