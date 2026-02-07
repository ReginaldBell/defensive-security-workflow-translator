from pydantic import BaseModel
from typing import List, Dict, Any

class IncidentEvidenceNew(BaseModel):
    window_start: str
    window_end: str
    counts: Dict[str, int]
    timeline: List[Dict[str, Any]]
    events: List[Dict[str, Any]]

class IncidentSubjectNew(BaseModel):
    source_ip: str
    username: str

class IncidentNew(BaseModel):
    incident_id: str
    type: str  # "brute_force" | "credential_abuse"
    mitre_technique: str = "T1110"
    severity: str  # medium | high | critical
    confidence: str  # low | medium | high
    summary: str
    recommended_actions: List[str]
    subject: IncidentSubjectNew
    evidence: IncidentEvidenceNew
