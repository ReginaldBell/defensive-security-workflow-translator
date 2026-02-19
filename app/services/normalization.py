from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.event_models_new import NormalizedEventNew as NormalizedEvent
from app.services.mapping_loader import get_field_aliases, get_reject_types

_TELEMETRY_SENTINEL = object()  # unique identity — returned only on telemetry rejection

# Kept for backward compatibility; delegates to the _default profile in the YAML config.
# Prefer mapping_loader.get_reject_types() for new code.
TELEMETRY_EVENT_TYPES: frozenset = get_reject_types(None)


def _coerce_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            return None

    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s[:-1]).replace(tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _first_str(d: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _map_raw_to_normalized_dict(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Bootstrap: extract source using _default aliases to select a profile,
    # then use the profile's aliases for all other fields.
    source = _first_str(raw, get_field_aliases(None, "source"))

    # Timestamp: iterate profile aliases and coerce the first hit.
    ts_raw = None
    for alias in get_field_aliases(source, "timestamp"):
        val = raw.get(alias)
        if val is not None:
            ts_raw = val
            break
    ts = _coerce_timestamp(ts_raw)
    if ts is None:
        return None

    source_ip  = _first_str(raw, get_field_aliases(source, "source_ip"))
    username   = _first_str(raw, get_field_aliases(source, "username"))
    event_type = _first_str(raw, get_field_aliases(source, "event_type"))
    result     = _first_str(raw, get_field_aliases(source, "result"))
    reason     = _first_str(raw, get_field_aliases(source, "reason"))
    user_agent = _first_str(raw, get_field_aliases(source, "user_agent"))

    # Reject known non-auth telemetry before any further processing.
    if event_type is not None and event_type.lower() in get_reject_types(source):
        return _TELEMETRY_SENTINEL  # type: ignore[return-value]

    # Required minimum for auth telemetry normalization:
    # timestamp + event_type + result must exist to support downstream detections.
    if event_type is None or result is None:
        return None

    # source_ip/username can be null-ish in some telemetry; keep them as empty string? NO.
    # Keep them as None only if schema allows optional; otherwise drop invalid.
    # We validate with the locked schema below.
    candidate = {
        "timestamp": ts,
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "result": result,
        "reason": reason,
        "user_agent": user_agent,
        "source": source,
        "raw_source": json.dumps(raw, separators=(",", ":")),
    }

    try:
        obj = NormalizedEvent(**candidate)
        return obj.model_dump()
    except Exception:
        return None


def normalize_events(raw_events: Any) -> Tuple[List[Dict[str, Any]], int]:
    """Normalize a list of raw event dicts.

    Returns (normalized_events, telemetry_rejected_count).
    """
    if not isinstance(raw_events, list):
        return [], 0

    normalized: List[Tuple[datetime, Dict[str, Any]]] = []
    telemetry_count = 0

    for item in raw_events:
        if not isinstance(item, dict):
            continue
        nd = _map_raw_to_normalized_dict(item)
        if nd is _TELEMETRY_SENTINEL:
            telemetry_count += 1
            continue
        if nd is None:
            continue

        ts = nd.get("timestamp")
        dt = _parse_ts_for_sort(ts)
        if dt is None:
            continue

        normalized.append((dt, nd))

    normalized.sort(key=lambda x: x[0])

    return [x[1] for x in normalized], telemetry_count


def _parse_ts_for_sort(ts: Any) -> Optional[datetime]:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def normalize_run(run_id: str, runs_root: Path) -> Dict[str, int]:
    run_dir = runs_root / run_id
    raw_path = run_dir / "raw.json"
    out_path = run_dir / "normalized.json"

    if not raw_path.exists():
        return {"raw": 0, "normalized": 0, "dropped": 0, "telemetry_rejected": 0}

    raw_obj = json.loads(raw_path.read_text(encoding="utf-8"))
    normalized, telemetry_rejected = normalize_events(raw_obj)

    out_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")

    raw_count = len(raw_obj) if isinstance(raw_obj, list) else 0
    norm_count = len(normalized)
    other_dropped = max(raw_count - norm_count - telemetry_rejected, 0)
    return {
        "raw": raw_count,
        "normalized": norm_count,
        "dropped": other_dropped,
        "telemetry_rejected": telemetry_rejected,
    }
