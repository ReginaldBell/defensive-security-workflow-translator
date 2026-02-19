"""
app/services/mapping_loader.py

Loads and caches field alias mappings from config/field_mappings.yaml.
Profile names correspond to the value of the 'source' field in incoming events.
Unknown sources fall back to the _default profile.

CLI validation:
    python -m app.services.mapping_loader --validate
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# ---------------------------------------------------------------------------
# Module-level cache — populated on first call, avoids repeated disk I/O.
# ---------------------------------------------------------------------------
_CACHE: Optional[Dict[str, Any]] = None

_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "field_mappings.yaml"
)

# Canonical fields that every _default profile must cover (raw_source is
# constructed internally and never appears in source logs).
_REQUIRED_CANONICAL_FIELDS = [
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "result",
    "reason",
    "user_agent",
    "source",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_mappings(force_reload: bool = False) -> Dict[str, Any]:
    """Load and cache the field mappings config.

    Reads MAPPING_CONFIG_PATH env var if set, otherwise uses the bundled
    config/field_mappings.yaml. Raises RuntimeError on missing or malformed
    config.
    """
    global _CACHE
    if _CACHE is not None and not force_reload:
        return _CACHE

    config_path_str = os.environ.get("MAPPING_CONFIG_PATH")
    config_path = Path(config_path_str) if config_path_str else _DEFAULT_CONFIG_PATH

    if not config_path.exists():
        raise RuntimeError(
            f"Field mappings config not found at: {config_path}. "
            "Set MAPPING_CONFIG_PATH env var to override the default location."
        )

    with config_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise RuntimeError(
            f"Field mappings config at {config_path} must be a YAML mapping at the top level."
        )

    _CACHE = data
    return _CACHE


def get_field_aliases(source: Optional[str], field: str) -> List[str]:
    """Return the ordered alias list for a canonical field within a profile.

    Falls back to _default if the source profile is unknown or the field
    is not defined in the profile.
    """
    mappings = load_mappings()
    profile = mappings.get(source, {}) if source else {}
    aliases = profile.get(field)

    if not aliases:
        default = mappings.get("_default", {})
        aliases = default.get(field, [])

    return list(aliases) if isinstance(aliases, list) else []


def get_reject_types(source: Optional[str]) -> frozenset:
    """Return the frozenset of event_type values to reject for this source.

    Falls back to _default reject types if the profile has none.
    """
    mappings = load_mappings()
    profile = mappings.get(source, {}) if source else {}
    reject = profile.get("_reject_event_types")

    if not reject:
        default = mappings.get("_default", {})
        reject = default.get("_reject_event_types", [])

    return frozenset(str(r) for r in reject)


# ---------------------------------------------------------------------------
# Validation logic (used by both the CLI and tests)
# ---------------------------------------------------------------------------

def validate_mappings(mappings: Dict[str, Any]) -> List[str]:
    """Validate the loaded mappings dict. Returns a list of error strings.

    Rules:
    - _default profile must exist.
    - Every field in _REQUIRED_CANONICAL_FIELDS must appear in _default
      with a non-empty list of aliases.
    - No profile may have an empty alias list for any field it defines.
    - _reject_event_types, if present, must be a non-empty list.
    """
    errors: List[str] = []

    if "_default" not in mappings:
        errors.append("Missing required '_default' profile.")
        return errors  # can't validate further without _default

    default = mappings["_default"]

    for field in _REQUIRED_CANONICAL_FIELDS:
        aliases = default.get(field)
        if not aliases:
            errors.append(f"_default profile is missing aliases for required field '{field}'.")
        elif not isinstance(aliases, list) or len(aliases) == 0:
            errors.append(f"_default profile has an empty alias list for field '{field}'.")

    for profile_name, profile in mappings.items():
        if not isinstance(profile, dict):
            errors.append(f"Profile '{profile_name}' must be a YAML mapping, got {type(profile).__name__}.")
            continue
        for field, aliases in profile.items():
            if field == "_reject_event_types":
                if not isinstance(aliases, list) or len(aliases) == 0:
                    errors.append(
                        f"Profile '{profile_name}': _reject_event_types must be a non-empty list."
                    )
            else:
                if not isinstance(aliases, list) or len(aliases) == 0:
                    errors.append(
                        f"Profile '{profile_name}': field '{field}' has an empty alias list."
                    )

    return errors


# ---------------------------------------------------------------------------
# CLI entry point: python -m app.services.mapping_loader --validate
# ---------------------------------------------------------------------------

def _main() -> None:
    if "--validate" not in sys.argv:
        print("Usage: python -m app.services.mapping_loader --validate", file=sys.stderr)
        sys.exit(1)

    try:
        mappings = load_mappings(force_reload=True)
    except RuntimeError as exc:
        print(f"FAIL  Config load error: {exc}", file=sys.stderr)
        sys.exit(1)

    errors = validate_mappings(mappings)

    profiles = [k for k in mappings if not k.startswith("_")]
    print(f"Profiles found: {', '.join(profiles) or '(none)'}")
    print(f"Required canonical fields checked: {', '.join(_REQUIRED_CANONICAL_FIELDS)}")

    if errors:
        for err in errors:
            print(f"FAIL  {err}", file=sys.stderr)
        sys.exit(1)

    print("OK    All checks passed.")


if __name__ == "__main__":
    _main()
