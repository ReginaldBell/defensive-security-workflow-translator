from __future__ import annotations

import hashlib
import json
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from app.schemas.event_models_new import NormalizedEventNew as NormalizedEvent
from app.schemas.incident_new import IncidentNew as Incident


MITRE_T1110 = "T1110"

WINDOW_SECONDS = 60
BRUTE_FORCE_FAILURE_THRESHOLD = 5
CRED_ABUSE_DISTINCT_USER_THRESHOLD = 5
CRED_ABUSE_FAILURE_THRESHOLD = 8


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _stable_incident_id(seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"inc_{h[:24]}"


def _is_failure(ev: Dict[str, Any]) -> bool:
    r = ev.get("result")
    return isinstance(r, str) and r.lower() == "failure"


def _severity_and_confidence(count: int) -> Tuple[str, int]:
    if count >= 20:
        return ("high", 95)
    if count >= 10:
        return ("medium", 85)
    return ("low", 70)


def _window_bounds(window: Deque[Tuple[datetime, Dict[str, Any]]]) -> Tuple[str, str]:
    start = window[0][0].isoformat().replace("+00:00", "Z")
    end = window[-1][0].isoformat().replace("+00:00", "Z")
    return start, end


def _event_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ev in events:
        out.append(
            {
                "timestamp": ev.get("timestamp"),
                "event_type": ev.get("event_type"),
                "result": ev.get("result"),
                "reason": ev.get("reason"),
            }
        )
    return out


def detect_incidents(normalized_events: Any) -> List[Dict[str, Any]]:
    if not isinstance(normalized_events, list):
        return []

    # Validate + ensure deterministic ordering
    validated: List[Tuple[datetime, Dict[str, Any]]] = []
    for item in normalized_events:
        if not isinstance(item, dict):
            continue
        try:
            ev_obj = NormalizedEvent(**item)
            ev = ev_obj.model_dump()
        except Exception:
            continue

        ts = ev.get("timestamp")
        if not isinstance(ts, str):
            continue
        dt = _parse_ts(ts)
        if dt is None:
            continue
        validated.append((dt, ev))

    validated.sort(key=lambda x: x[0])

    # Sliding window over failures only
    win: Deque[Tuple[datetime, Dict[str, Any]]] = deque()
    out_incidents: List[Dict[str, Any]] = []

    emitted: set[str] = set()

    window_delta = timedelta(seconds=WINDOW_SECONDS)

    for dt, ev in validated:
        if not _is_failure(ev):
            continue

        win.append((dt, ev))
        cutoff = dt - window_delta
        while win and win[0][0] < cutoff:
            win.popleft()


        # Build aggregates in the current window
        failures_by_pair: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        failures_by_ip: Dict[str, List[Dict[str, Any]]] = {}

        for _, e in win:
            ip = e.get("source_ip")
            user = e.get("username")
            if not isinstance(ip, str) or not ip:
                continue
            if not isinstance(user, str) or not user:
                continue

            failures_by_ip.setdefault(ip, []).append(e)
            failures_by_pair.setdefault((ip, user), []).append(e)



        # 1) Brute force: same ip+username
        for (ip, user), events in failures_by_pair.items():
            count = len(events)
            if count < BRUTE_FORCE_FAILURE_THRESHOLD:
                continue

            start_ts, end_ts = _window_bounds(win)
            seed = f"brute_force|{ip}|{user}|{start_ts}|{end_ts}|{count}"
            incident_id = _stable_incident_id(seed)
            if incident_id in emitted:
                continue
            emitted.add(incident_id)

            sev, conf = _severity_and_confidence(count)

            incident = {
                "incident_id": incident_id,
                "type": "brute_force",
                "mitre_technique": MITRE_T1110,
                "severity": sev,
                "confidence": str(conf),
                "summary": f"Possible brute-force against '{user}' from {ip}: {count} failed logins within {WINDOW_SECONDS}s.",
                "recommended_actions": [
                    "Review authentication logs for the affected account and source IP.",
                    "Check if the account exists and whether any successful logins followed.",
                    "Consider temporary rate-limiting, account lockout, or IP blocking per policy.",
                    "If unauthorized access is suspected, reset credentials and review MFA status."
                ],
                "subject": {"source_ip": ip, "username": user},
                "evidence": {
                    "window_start": start_ts,
                    "window_end": end_ts,
                    "counts": {"failures": count},
                    "timeline": _event_timeline(events),
                    "events": events,
                },
            }

            print("ATTEMPTING INCIDENT:", incident)
            try:
                obj = Incident(**incident)
                out_incidents.append(obj.model_dump())
            except Exception as e:
                print("INCIDENT ERROR:", e)
                continue

        # 2) Credential abuse: same ip targeting many usernames
        for ip, events in failures_by_ip.items():
            usernames = sorted({e.get("username") for e in events if isinstance(e.get("username"), str) and e.get("username")})
            distinct_users = len(usernames)
            count = len(events)

            if distinct_users < CRED_ABUSE_DISTINCT_USER_THRESHOLD:
                continue
            if count < CRED_ABUSE_FAILURE_THRESHOLD:
                continue

            start_ts, end_ts = _window_bounds(win)
            seed = f"credential_abuse|{ip}|{start_ts}|{end_ts}|{distinct_users}|{count}"
            incident_id = _stable_incident_id(seed)
            if incident_id in emitted:
                continue
            emitted.add(incident_id)

            sev, conf = _severity_and_confidence(count)

            incident = {
                "incident_id": incident_id,
                "type": "credential_abuse",
                "mitre_technique": MITRE_T1110,
                "severity": sev,
                "confidence": str(conf),
                "summary": f"Possible credential stuffing from {ip}: {count} failures across {distinct_users} usernames within {WINDOW_SECONDS}s.",
                "recommended_actions": [
                    "Review authentication logs for repeated failures across multiple accounts.",
                    "Check for related successful logins from the same source IP.",
                    "Consider blocking or challenging the source IP per policy.",
                    "If confirmed, notify identity/security teams and review exposed credential sources."
                ],
                "subject": {"source_ip": ip, "username": None},
                "evidence": {
                    "window_start": start_ts,
                    "window_end": end_ts,
                    "counts": {"failures": count, "distinct_usernames": distinct_users, "usernames": usernames},
                    "timeline": _event_timeline(events),
                    "events": events,
                },
            }

            try:
                obj = Incident(**incident)
                out_incidents.append(obj.model_dump())
            except Exception:
                continue

    # Final deterministic ordering
    out_incidents.sort(key=lambda x: x.get("incident_id", ""))
    return out_incidents


def detect_run(run_id: str, runs_root: Path) -> Dict[str, int]:
    run_dir = runs_root / run_id
    in_path = run_dir / "normalized.json"
    out_path = run_dir / "incidents.json"

    if not in_path.exists():
        out_path.write_text("[]", encoding="utf-8")
        return {"normalized": 0, "incidents": 0}

    normalized = json.loads(in_path.read_text(encoding="utf-8"))
    incidents = detect_incidents(normalized)

    out_path.write_text(json.dumps(incidents, indent=2), encoding="utf-8")

    n_count = len(normalized) if isinstance(normalized, list) else 0
    i_count = len(incidents)
    return {"normalized": n_count, "incidents": i_count}
