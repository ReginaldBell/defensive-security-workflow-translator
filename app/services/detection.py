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
MITRE_T1110_003 = "T1110.003"
MITRE_TACTIC_CREDENTIAL_ACCESS = "Credential Access"
MITRE_TECHNIQUE_BRUTE_FORCE = "Brute Force"
MITRE_TECHNIQUE_PASSWORD_SPRAYING = "Password Spraying"

WINDOW_SECONDS = 60
BRUTE_FORCE_FAILURE_THRESHOLD = 5
CRED_ABUSE_DISTINCT_USER_THRESHOLD = 5
CRED_ABUSE_FAILURE_THRESHOLD = 8

def _phase4_summary(incident: dict) -> str:
    technique = incident.get("mitre_technique", "T1110")
    subject = incident.get("subject") or {}
    evidence = incident.get("evidence") or {}
    counts = evidence.get("counts") or {}

    username = subject.get("username", "unknown")
    source_ip = subject.get("source_ip", "unknown")
    failures = counts.get("failures", 0)
    ws = evidence.get("window_start", "unknown")
    we = evidence.get("window_end", "unknown")

    return (
        f"Brute-force authentication activity detected (MITRE {technique}): "
        f"{failures} failed login attempts against user '{username}' from source IP {source_ip} "
        f"during {ws}–{we}, exceeding brute-force threshold."
    )


def _phase4_summary_cred_abuse(incident: dict) -> str:
    """Generate summary for credential abuse (password spraying) incidents."""
    subject = incident.get("subject") or {}
    evidence = incident.get("evidence") or {}
    counts = evidence.get("counts") or {}

    source_ip = subject.get("source_ip", "unknown")
    failures = counts.get("failures", 0)
    distinct_users = counts.get("distinct_users", 0)
    ws = evidence.get("window_start", "unknown")
    we = evidence.get("window_end", "unknown")

    return (
        f"Potential Credential Abuse detected (MITRE T1110.003 - Password Spraying): "
        f"{failures} failed login attempts across {distinct_users} distinct accounts "
        f"from source IP {source_ip} during {ws}–{we}. "
        "This pattern is indicative of compromised credentials or unauthorized access attempts."
    )


def _phase4_recommended_actions() -> list[str]:
    return [
        "Validate whether the source IP and login pattern are expected for this user (VPNs, known locations, automation).",
        "Review authentication activity before and after the detection window to identify escalation or successful access.",
        "Assess account controls (lockout behavior, MFA enforcement) and confirm whether the user experienced authentication issues.",
        "If activity is unauthorized, follow response policy: reset credentials, revoke active sessions, and apply network controls as appropriate."
    ]


def _phase4_apply_explainability(incident: dict) -> dict:
    incident["summary"] = _phase4_summary(incident)
    incident["recommended_actions"] = _phase4_recommended_actions()
    return incident


def _phase4_apply_explainability_cred_abuse(incident: dict) -> dict:
    incident["summary"] = _phase4_summary_cred_abuse(incident)
    incident["recommended_actions"] = _phase4_recommended_actions()
    return incident


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


def _is_auth_event(ev: Dict[str, Any]) -> bool:
    event_type = ev.get("event_type")
    if not isinstance(event_type, str):
        return False
    normalized = event_type.strip().lower()
    return (
        "login" in normalized
        or "auth" in normalized
        or normalized in {"signin", "sign_in", "sign-in"}
    )


def _severity_and_confidence(count: int) -> Tuple[str, float]:
    if count >= 20:
        return ("high", 0.95)
    if count >= 10:
        return ("medium", 0.85)
    return ("low", 0.70)


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
                "username": ev.get("username"),
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

    # Sliding window over failures only (used by credential abuse detector)
    win: Deque[Tuple[datetime, Dict[str, Any]]] = deque()
    out_incidents: List[Dict[str, Any]] = []

    emitted: set[str] = set()
    incident_index_by_id: Dict[str, int] = {}

    window_delta = timedelta(seconds=WINDOW_SECONDS)
    brute_force_windows: Dict[Tuple[str, str], Deque[Tuple[datetime, Dict[str, Any]]]] = {}
    active_bruteforce: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for dt, ev in validated:
        if not _is_failure(ev) or not _is_auth_event(ev):
            continue

        # Brute-force state machine: one active incident per (ip, username)
        # per 60-second detection window anchored to the incident start.
        ip = ev.get("source_ip")
        user = ev.get("username")
        if isinstance(ip, str) and ip and isinstance(user, str) and user:
            pair = (ip, user)
            pair_window = brute_force_windows.setdefault(pair, deque())
            active_state = active_bruteforce.get(pair)

            if active_state is not None:
                start_dt = active_state["start_dt"]
                if (dt - start_dt) > window_delta:
                    active_bruteforce.pop(pair, None)
                    pair_window.clear()
                    active_state = None

            pair_window.append((dt, ev))
            while pair_window and (dt - pair_window[0][0]) > window_delta:
                pair_window.popleft()

            if active_state is None and len(pair_window) >= BRUTE_FORCE_FAILURE_THRESHOLD:
                start_dt = pair_window[0][0]
                start_ts = start_dt.isoformat().replace("+00:00", "Z")
                end_ts = dt.isoformat().replace("+00:00", "Z")
                entities = sorted([ip, user])
                seed = f"brute_force|{'|'.join(entities)}|{start_ts}"
                incident_id = _stable_incident_id(seed)
                if incident_id in emitted:
                    active_bruteforce[pair] = {"incident_id": incident_id, "start_dt": start_dt}
                    continue

                evidence_events = [item[1] for item in pair_window]
                evidence_count = len(evidence_events)
                sev, conf = _severity_and_confidence(evidence_count)

                incident = {
                    "incident_id": incident_id,
                    "type": "brute_force",
                    "mitre_technique": MITRE_T1110,
                    "mitre": {
                        "tactic": MITRE_TACTIC_CREDENTIAL_ACCESS,
                        "technique": MITRE_T1110,
                        "technique_name": MITRE_TECHNIQUE_BRUTE_FORCE,
                    },
                    "severity": sev,
                    "confidence": conf,
                    "first_seen": start_ts,
                    "last_seen": end_ts,
                    "affected_entities": entities,
                    "evidence_count": evidence_count,
                    "source_count": len({e.get("source") for e in evidence_events if e.get("source")}),
                    "summary": "",
                    "recommended_actions": [],
                    "explanation": {
                        "threshold": BRUTE_FORCE_FAILURE_THRESHOLD,
                        "observed": BRUTE_FORCE_FAILURE_THRESHOLD,
                        "window": f"{WINDOW_SECONDS}s",
                        "trigger_field": "username",
                    },
                    "subject": {"source_ip": ip, "username": user},
                    "evidence": {
                        "window_start": start_ts,
                        "window_end": end_ts,
                        "counts": {"failures": evidence_count},
                        "timeline": _event_timeline(evidence_events),
                        "events": evidence_events,
                    },
                }

                incident = _phase4_apply_explainability(incident)
                try:
                    obj = Incident(**incident)
                    dumped = obj.model_dump(exclude_unset=True)
                    out_incidents.append(dumped)
                    emitted.add(incident_id)
                    incident_index_by_id[incident_id] = len(out_incidents) - 1
                    active_bruteforce[pair] = {"incident_id": incident_id, "start_dt": start_dt}
                except Exception:
                    pass

            elif active_state is not None:
                incident_id = active_state["incident_id"]
                incident_idx = incident_index_by_id.get(incident_id)
                if incident_idx is not None:
                    incident = out_incidents[incident_idx]
                    evidence_events = incident.get("evidence", {}).get("events", [])
                    evidence_events.append(ev)
                    evidence_count = len(evidence_events)

                    sev, conf = _severity_and_confidence(evidence_count)
                    end_ts = dt.isoformat().replace("+00:00", "Z")

                    incident["last_seen"] = end_ts
                    incident["severity"] = sev
                    incident["confidence"] = conf
                    incident["evidence_count"] = evidence_count
                    incident["source_count"] = len({e.get("source") for e in evidence_events if e.get("source")})
                    incident["evidence"]["window_end"] = end_ts
                    incident["evidence"]["counts"]["failures"] = evidence_count
                    incident["evidence"]["timeline"] = _event_timeline(evidence_events)
                    incident["explanation"]["observed"] = BRUTE_FORCE_FAILURE_THRESHOLD
                    incident = _phase4_apply_explainability(incident)
                    out_incidents[incident_idx] = incident

        win.append((dt, ev))
        cutoff = dt - window_delta
        while win and win[0][0] < cutoff:
            win.popleft()

        # Build aggregates in the current window
        failures_by_ip: Dict[str, List[Dict[str, Any]]] = {}

        for _, e in win:
            ip = e.get("source_ip")
            user = e.get("username")
            if not isinstance(ip, str) or not ip:
                continue
            if not isinstance(user, str) or not user:
                continue

            failures_by_ip.setdefault(ip, []).append(e)

        # Credential Abuse: same IP, multiple distinct usernames
        for ip, events in failures_by_ip.items():
            distinct_users = {e.get("username") for e in events if e.get("username")}
            count = len(events)

            if len(distinct_users) >= CRED_ABUSE_DISTINCT_USER_THRESHOLD and count >= CRED_ABUSE_FAILURE_THRESHOLD:
                start_ts, end_ts = _window_bounds(win)
                entities = sorted([ip] + sorted(distinct_users))
                seed = f"credential_abuse|{'|'.join(entities)}|{start_ts}"
                incident_id = _stable_incident_id(seed)

                if incident_id in emitted:
                    continue
                emitted.add(incident_id)

                # Severity based on distinct user count
                sev = "critical" if len(distinct_users) > 15 else "high"

                incident = {
                    "incident_id": incident_id,
                    "type": "credential_abuse",
                    "mitre_technique": MITRE_T1110_003,
                    "mitre": {
                        "tactic": MITRE_TACTIC_CREDENTIAL_ACCESS,
                        "technique": MITRE_T1110_003,
                        "technique_name": MITRE_TECHNIQUE_PASSWORD_SPRAYING,
                    },
                    "severity": sev,
                    "confidence": 0.90,
                    "first_seen": start_ts,
                    "last_seen": end_ts,
                    "affected_entities": entities,
                    "evidence_count": count,
                    "source_count": len({e.get("source") for e in events if e.get("source")}),
                    "summary": "",
                    "recommended_actions": [],
                    "explanation": {
                        "threshold": CRED_ABUSE_FAILURE_THRESHOLD,
                        "observed": count,
                        "window": f"{WINDOW_SECONDS}s",
                        "trigger_field": "source_ip",
                    },
                    "subject": {"source_ip": ip, "username": "multiple_accounts"},
                    "evidence": {
                        "window_start": start_ts,
                        "window_end": end_ts,
                        "counts": {
                            "failures": count,
                            "distinct_users": len(distinct_users)
                        },
                        "timeline": _event_timeline(events),
                        "events": events,
                    },
                }

                incident = _phase4_apply_explainability_cred_abuse(incident)
                try:
                    obj = Incident(**incident)
                    out_incidents.append(obj.model_dump(exclude_unset=True))
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
