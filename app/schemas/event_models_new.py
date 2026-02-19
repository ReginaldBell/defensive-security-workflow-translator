from pydantic import BaseModel
from typing import Optional

# Locked canonical field list — do not add fields without updating normalization,
# detection, and the ingest schema contract (dashboard/public/schema.json).
CANONICAL_FIELDS = [
    "timestamp",    # ISO 8601 UTC — required
    "source_ip",    # originating IP address — optional
    "username",     # authenticated principal — optional
    "event_type",   # action category, e.g. "login_attempt" — required
    "result",       # "success" | "failure" — required
    "reason",       # failure reason / error message — optional
    "user_agent",   # HTTP user-agent string — optional
    "source",       # log source system name — optional
    "raw_source",   # original raw log line (JSON-serialized) — optional, for audit
]


class NormalizedEventNew(BaseModel):
    timestamp: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str = "login_attempt"
    result: str  # "failure" | "success"
    reason: Optional[str] = None
    user_agent: Optional[str] = None
    source: str = "auth_service"
    raw_source: Optional[str] = None  # serialized original log line for audit trail
