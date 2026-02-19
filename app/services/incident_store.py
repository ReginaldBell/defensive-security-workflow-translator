from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from app.schemas.incident_new import IncidentNew
from app.services import entity_risk as entity_risk_service
from app.services import metrics as metrics_service

logger = logging.getLogger(__name__)

_STORE_PATH = Path("runs") / "incidents.json"
_STALE_AFTER = timedelta(minutes=5)

_lock = threading.Lock()
_incidents_by_id: Dict[str, IncidentNew] = {}
_loaded = False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso8601(value: str) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1] + "+00:00")
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _max_timestamp(a: str, b: str) -> str:
    da = _parse_iso8601(a)
    db = _parse_iso8601(b)
    if da and db:
        return a if da >= db else b
    if db and not da:
        return b
    if da and not db:
        return a
    return a if a >= b else b


def _min_timestamp(a: str, b: str) -> str:
    da = _parse_iso8601(a)
    db = _parse_iso8601(b)
    if da and db:
        return a if da <= db else b
    if db and not da:
        return b
    if da and not db:
        return a
    return a if a <= b else b


def _copy_incident(incident: IncidentNew) -> IncidentNew:
    return IncidentNew.model_validate(incident.model_dump(mode="json"))


def _is_stale(last_seen: str, now: Optional[datetime] = None) -> bool:
    seen = _parse_iso8601(last_seen)
    if seen is None:
        return False
    reference = now or _utcnow()
    return (reference - seen) > _STALE_AFTER


def incident_to_response(incident: IncidentNew) -> dict:
    out = incident.model_dump(mode="json")
    out["is_stale"] = _is_stale(incident.last_seen)
    return out


def _safe_metric_increment(counter_name: str) -> None:
    try:
        metrics_service.increment_counter(counter_name)
    except Exception as exc:
        logger.warning(f"Incident metric increment failed for {counter_name}: {exc}")


def _safe_entity_risk_record(incident: IncidentNew) -> None:
    try:
        entity_risk_service.record_incident(incident)
    except Exception as exc:
        logger.warning(f"Entity risk update failed for {incident.incident_id}: {exc}")


def _load_store_locked() -> None:
    global _incidents_by_id, _loaded

    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not _STORE_PATH.exists():
        _STORE_PATH.write_text("[]", encoding="utf-8")

    try:
        raw = json.loads(_STORE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(f"Failed reading {_STORE_PATH}; starting empty: {exc}")
        raw = []

    if not isinstance(raw, list):
        raw = []

    index: Dict[str, IncidentNew] = {}
    for item in raw:
        try:
            incident = IncidentNew.model_validate(item)
        except Exception:
            continue
        index[incident.incident_id] = incident

    _incidents_by_id = index
    _loaded = True


def _ensure_loaded_locked() -> None:
    if not _loaded:
        _load_store_locked()


def _save_store_locked() -> None:
    items = [
        _incidents_by_id[key].model_dump(mode="json")
        for key in sorted(_incidents_by_id.keys())
    ]
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STORE_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")


def _merge_sources(existing: IncidentNew, incoming: IncidentNew) -> int:
    merged_sources: Set[str] = set()
    merged_events = list(existing.evidence.events) + list(incoming.evidence.events)
    for event in merged_events:
        if not isinstance(event, dict):
            continue
        source = event.get("source")
        if isinstance(source, str) and source:
            merged_sources.add(source)
    if merged_sources:
        return len(merged_sources)
    return max(existing.source_count, incoming.source_count)


def _merge_incident(existing: IncidentNew, incoming: IncidentNew, now: datetime) -> IncidentNew:
    merged = existing.model_copy(deep=True)

    merged.first_seen = _min_timestamp(existing.first_seen, incoming.first_seen)
    merged.last_seen = _max_timestamp(existing.last_seen, incoming.last_seen)
    merged.evidence_count = existing.evidence_count + incoming.evidence_count
    merged.affected_entities = sorted(
        set(existing.affected_entities).union(set(incoming.affected_entities))
    )
    merged.source_count = _merge_sources(existing, incoming)
    merged.updated_at = now

    merged.evidence.window_start = _min_timestamp(
        existing.evidence.window_start,
        incoming.evidence.window_start,
    )
    merged.evidence.window_end = _max_timestamp(
        existing.evidence.window_end,
        incoming.evidence.window_end,
    )
    merged.evidence.timeline = list(existing.evidence.timeline) + list(incoming.evidence.timeline)
    merged.evidence.events = list(existing.evidence.events) + list(incoming.evidence.events)

    counts = dict(existing.evidence.counts)
    incoming_counts = dict(incoming.evidence.counts)
    if "failures" in counts or "failures" in incoming_counts:
        counts["failures"] = merged.evidence_count
    if "distinct_users" in counts or "distinct_users" in incoming_counts:
        distinct_users = set()
        for event in merged.evidence.events:
            if not isinstance(event, dict):
                continue
            username = event.get("username")
            if isinstance(username, str) and username:
                distinct_users.add(username)
        if distinct_users:
            counts["distinct_users"] = len(distinct_users)
    merged.evidence.counts = counts

    merged.severity = incoming.severity
    merged.confidence = incoming.confidence
    merged.summary = incoming.summary
    merged.recommended_actions = incoming.recommended_actions
    merged.explanation = incoming.explanation
    merged.subject = incoming.subject

    return merged


def load_store() -> None:
    with _lock:
        _load_store_locked()


def save_store() -> None:
    with _lock:
        _ensure_loaded_locked()
        _save_store_locked()


def get_incident(incident_id: str) -> Optional[IncidentNew]:
    with _lock:
        _ensure_loaded_locked()
        incident = _incidents_by_id.get(incident_id)
        return _copy_incident(incident) if incident else None


def list_incidents() -> List[IncidentNew]:
    with _lock:
        _ensure_loaded_locked()
        return [_copy_incident(_incidents_by_id[key]) for key in sorted(_incidents_by_id.keys())]


def upsert_incident(incident: IncidentNew) -> IncidentNew:
    with _lock:
        _ensure_loaded_locked()

        now = _utcnow()
        incoming = _copy_incident(incident)
        existing = _incidents_by_id.get(incoming.incident_id)

        if existing is None:
            incoming.status = "open"
            incoming.resolution_reason = None
            incoming.created_at = now
            incoming.updated_at = now
            _incidents_by_id[incoming.incident_id] = incoming
            _save_store_locked()
            _safe_metric_increment("incidents_created_total")
            _safe_entity_risk_record(incoming)
            return _copy_incident(incoming)

        merged = _merge_incident(existing, incoming, now)

        if existing.status == "closed":
            merged.status = "open"
            merged.resolution_reason = None
            merged.created_at = existing.created_at
            _incidents_by_id[merged.incident_id] = merged
            _save_store_locked()
            _safe_metric_increment("incidents_reopened_total")
            _safe_entity_risk_record(merged)
            return _copy_incident(merged)

        merged.status = existing.status
        merged.resolution_reason = existing.resolution_reason
        merged.created_at = existing.created_at
        _incidents_by_id[merged.incident_id] = merged
        _save_store_locked()
        _safe_metric_increment("incidents_updated_total")
        return _copy_incident(merged)


def transition_incident(
    incident_id: str,
    status: str,
    resolution_reason: Optional[str] = None,
) -> IncidentNew:
    with _lock:
        _ensure_loaded_locked()

        existing = _incidents_by_id.get(incident_id)
        if existing is None:
            raise KeyError(incident_id)

        valid_transitions = {
            "open": {"acknowledged"},
            "acknowledged": {"closed"},
            "closed": set(),
        }
        allowed = valid_transitions.get(existing.status, set())
        if status not in allowed:
            raise ValueError(f"Invalid transition: {existing.status} -> {status}")

        updated = existing.model_copy(deep=True)
        updated.status = status
        updated.updated_at = _utcnow()
        if status == "closed":
            updated.resolution_reason = resolution_reason
            _safe_metric_increment("incidents_closed_total")

        _incidents_by_id[incident_id] = updated
        _save_store_locked()
        return _copy_incident(updated)
