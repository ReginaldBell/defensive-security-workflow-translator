#!/usr/bin/env python
import argparse
import json
import sys
from datetime import datetime, timezone


def _first(obj, keys):
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return None


def _parse_timestamp(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Heuristic: >1e12 looks like ms
        if value > 1_000_000_000_000:
            value = value / 1000.0
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        v = value.strip()
        # Try epoch string
        if v.isdigit():
            return _parse_timestamp(int(v))
        # Try ISO-ish formats
        try:
            if v.endswith("Z"):
                v = v.replace("Z", "+00:00")
            dt = datetime.fromisoformat(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return None
    return None


def _normalize_result(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "success" if value else "failure"
    if isinstance(value, (int, float)):
        return "success" if value != 0 else "failure"
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"success", "succeeded", "ok", "true", "allowed", "permit", "pass"}:
            return "success"
        if v in {"failure", "failed", "fail", "denied", "error", "false", "invalid", "blocked"}:
            return "failure"
    return None


def translate_event(ev):
    ts_raw = _first(ev, ["timestamp", "time", "@timestamp", "ts"])
    result_raw = _first(ev, ["result", "outcome", "status", "success"])
    ts = _parse_timestamp(ts_raw)
    result = _normalize_result(result_raw)
    if not ts or not result:
        return None

    return {
        "timestamp": ts,
        "source_ip": _first(ev, ["source_ip", "ip", "client_ip", "src_ip", "remote_ip"]),
        "username": _first(ev, ["username", "user", "user_id", "account", "principal", "login"]),
        "event_type": _first(ev, ["event_type", "type", "action", "event"]) or "login_attempt",
        "result": result,
        "reason": _first(ev, ["reason", "failure_reason", "error", "message"]),
        "user_agent": _first(ev, ["user_agent", "ua"]),
        "source": _first(ev, ["source", "system", "vendor"]) or "auth_service",
    }


def main():
    parser = argparse.ArgumentParser(description="Translate generic auth logs into SecureWatch schema.")
    parser.add_argument("input", help="Path to JSON array of events")
    parser.add_argument("-o", "--output", help="Output file (defaults to stdout)")
    args = parser.parse_args()

    try:
        data = json.loads(open(args.input, "r", encoding="utf-8").read())
    except Exception as exc:
        print(f"Failed to read JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(data, list):
        print("Input must be a JSON array", file=sys.stderr)
        return 2

    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        translated = translate_event(item)
        if translated:
            out.append(translated)

    payload = json.dumps(out, indent=2)
    if args.output:
        open(args.output, "w", encoding="utf-8").write(payload)
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
