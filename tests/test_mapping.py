"""
tests/test_mapping.py

Regression tests for the configurable field mapping system.
Covers:
  1. _default profile completeness (all CANONICAL_FIELDS present)
  2. Alias resolution for source_ip, username, and timestamp
  3. Telemetry rejection (heartbeat, health_check pass through → rejected)
  4. Valid auth events are NOT rejected
  5. Unknown source falls back to _default
  6. Okta profile: ipAddress resolves to source_ip end-to-end
  7. Snapshot: trigger_bruteforce.json → same incidents through full pipeline
  8. Snapshot: trigger_credabuse.json → same incidents through full pipeline
  9. validate_mappings() catches bad config
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from app.schemas.event_models_new import CANONICAL_FIELDS
from app.services.mapping_loader import (
    get_field_aliases,
    get_reject_types,
    load_mappings,
    validate_mappings,
)
from app.services.normalization import normalize_events
from app.services.detection import detect_incidents

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_trigger(name: str) -> List[Dict[str, Any]]:
    return json.loads((REPO_ROOT / name).read_text(encoding="utf-8"))


def _full_pipeline(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """normalize_events → detect_incidents, return incidents."""
    normalized, _rejected = normalize_events(raw_events)
    return detect_incidents(normalized)


# ---------------------------------------------------------------------------
# 1. _default profile must cover all CANONICAL_FIELDS (except raw_source)
# ---------------------------------------------------------------------------

def test_default_mapping_covers_all_canonical_fields():
    mappings = load_mappings()
    default = mappings["_default"]
    fields_to_check = [f for f in CANONICAL_FIELDS if f != "raw_source"]

    missing = [f for f in fields_to_check if not default.get(f)]
    assert not missing, f"_default profile missing aliases for: {missing}"


# ---------------------------------------------------------------------------
# 2a. source_ip aliases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alias", ["source_ip", "ip", "client_ip", "src_ip", "remote_ip"])
def test_default_source_ip_alias_present(alias: str):
    assert alias in get_field_aliases(None, "source_ip"), \
        f"'{alias}' not found in _default source_ip aliases"


# ---------------------------------------------------------------------------
# 2b. username aliases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alias", ["username", "user", "user_id", "account", "principal"])
def test_default_username_alias_present(alias: str):
    assert alias in get_field_aliases(None, "username"), \
        f"'{alias}' not found in _default username aliases"


# ---------------------------------------------------------------------------
# 2c. timestamp aliases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alias", ["timestamp", "time", "@timestamp", "ts"])
def test_default_timestamp_alias_present(alias: str):
    assert alias in get_field_aliases(None, "timestamp"), \
        f"'{alias}' not found in _default timestamp aliases"


# ---------------------------------------------------------------------------
# 3. Telemetry rejection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("event_type", ["heartbeat", "health_check", "ping", "metric", "keepalive"])
def test_telemetry_event_type_is_rejected(event_type: str):
    events = [{
        "timestamp": "2025-12-21T06:00:00Z",
        "event_type": event_type,
        "result": "success",
        "source_ip": "10.0.0.1",
    }]
    normalized, rejected = normalize_events(events)
    assert normalized == [], f"event_type='{event_type}' should be rejected"
    assert rejected == 1


# ---------------------------------------------------------------------------
# 4. Valid auth events pass through
# ---------------------------------------------------------------------------

def test_login_attempt_is_not_rejected():
    events = [{
        "timestamp": "2025-12-21T06:00:00Z",
        "event_type": "login_attempt",
        "result": "failure",
        "source_ip": "10.0.0.1",
        "username": "bob",
        "source": "auth_service",
    }]
    normalized, rejected = normalize_events(events)
    # This validates normalization acceptance only; suppression is a detection concern.
    assert len(normalized) == 1
    assert rejected == 0
    assert detect_incidents(normalized) == []


# ---------------------------------------------------------------------------
# 5. Unknown source falls back to _default
# ---------------------------------------------------------------------------

def test_unknown_source_aliases_match_default():
    unknown = get_field_aliases("completely_unknown_xyz", "source_ip")
    default = get_field_aliases(None, "source_ip")
    assert unknown == default


def test_unknown_source_reject_types_match_default():
    assert get_reject_types("completely_unknown_xyz") == get_reject_types(None)


# ---------------------------------------------------------------------------
# 6. Okta profile: ipAddress resolves to source_ip end-to-end
# ---------------------------------------------------------------------------

def test_okta_first_source_ip_alias_is_ipAddress():
    aliases = get_field_aliases("okta", "source_ip")
    assert aliases, "Okta profile must define source_ip aliases"
    assert aliases[0] == "ipAddress", \
        f"Expected first okta source_ip alias to be 'ipAddress', got '{aliases[0]}'"


def test_okta_event_ipAddress_normalizes_to_source_ip():
    events = [{
        "timestamp": "2025-12-21T06:00:00Z",
        "eventType": "user.session.start",
        "result": "failure",
        "ipAddress": "192.168.1.55",
        "login": "alice@example.com",
        "source": "okta",
    }]
    normalized, rejected = normalize_events(events)
    assert rejected == 0
    assert len(normalized) == 1
    assert normalized[0]["source_ip"] == "192.168.1.55"
    assert normalized[0]["username"] == "alice@example.com"


# ---------------------------------------------------------------------------
# 7. Snapshot: trigger_bruteforce.json → brute_force incident
# ---------------------------------------------------------------------------

def test_snapshot_bruteforce_full_pipeline():
    raw = _load_trigger("trigger_bruteforce.json")
    incidents = _full_pipeline(raw)

    assert len(incidents) == 1, "Expected single deduplicated brute-force incident"
    inc = incidents[0]

    assert inc["type"] == "brute_force"
    assert inc["confidence"] == 0.70
    assert inc["evidence_count"] == 6
    assert inc["evidence"]["counts"]["failures"] == 6
    assert set(inc["affected_entities"]) == {"203.0.113.10", "alice"}

    explanation = inc["explanation"]
    assert explanation["threshold"] == 5
    assert explanation["observed"] == 5
    assert explanation["window"] == "60s"
    assert explanation["trigger_field"] == "username"


# ---------------------------------------------------------------------------
# 8. Snapshot: trigger_credabuse.json → credential_abuse incident
# ---------------------------------------------------------------------------

def test_snapshot_credabuse_full_pipeline():
    raw = _load_trigger("trigger_credabuse.json")
    incidents = _full_pipeline(raw)

    cred = [i for i in incidents if i["type"] == "credential_abuse"]
    assert cred, "Expected credential_abuse incident from trigger_credabuse.json"

    counts = cred[0]["evidence"]["counts"]
    assert counts["failures"] == len(raw)
    assert counts["distinct_users"] == 5


# ---------------------------------------------------------------------------
# 9. validate_mappings() catches bad config
# ---------------------------------------------------------------------------

def test_validate_mappings_passes_on_good_config():
    mappings = load_mappings()
    errors = validate_mappings(mappings)
    assert not errors, f"Good config reported errors: {errors}"


def test_validate_mappings_catches_missing_default():
    errors = validate_mappings({"okta": {"source_ip": ["ipAddress"]}})
    assert any("_default" in e for e in errors)


def test_validate_mappings_catches_empty_alias_list():
    bad = {
        "_default": {
            "timestamp": [],          # empty — should fail
            "source_ip": ["source_ip"],
            "username": ["username"],
            "event_type": ["event_type"],
            "result": ["result"],
            "reason": ["reason"],
            "user_agent": ["user_agent"],
            "source": ["source"],
        }
    }
    errors = validate_mappings(bad)
    assert any("timestamp" in e for e in errors)
