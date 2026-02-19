# SecureWatch Engine

![Dashboard Screenshot](dashboard/src/images/SecureWatch.png)

A deterministic security event processing pipeline that ingests heterogeneous authentication logs, normalizes them through configurable field mappings, applies sliding-window threat detection with MITRE ATT&CK classification, and manages the full incident lifecycle with entity-level risk scoring.

---

## Architecture

```
                  ┌──────────────────────────────────┐
                  │         Log Sources               │
                  │  Okta  ·  Windows  ·  Generic JSON│
                  └──────────────┬───────────────────┘
                                 │  POST /ingest/
                                 ▼
               ┌─────────────────────────────────────┐
               │         Normalization Layer          │
               │  YAML-driven field mapping           │
               │  Timestamp coercion (epoch → ISO)    │
               │  Telemetry rejection filter           │
               │  Pydantic v2 schema enforcement       │
               └──────────────┬──────────────────────┘
                              │  Sorted chronologically
                              ▼
               ┌─────────────────────────────────────┐
               │         Detection Engine             │
               │  60s sliding window (deque-based)    │
               │  Rule 1: Brute-force (T1110)         │
               │  Rule 2: Password spraying (T1110.003)│
               │  Deterministic incident IDs (SHA-256) │
               │  Incident merging & deduplication     │
               └──────────────┬──────────────────────┘
                              │
                    ┌─────────┼──────────┐
                    ▼         ▼          ▼
          ┌──────────┐ ┌──────────┐ ┌──────────────┐
          │ Incident │ │  Entity  │ │   Metrics    │
          │ Store    │ │  Risk    │ │   Counters   │
          │ (JSON)   │ │  Scoring │ │              │
          └────┬─────┘ └────┬─────┘ └──────┬───────┘
               │            │              │
               ▼            ▼              ▼
          ┌──────────────────────────────────────┐
          │           REST API (FastAPI)          │
          │  /incidents/  /entity-risk/  /metrics/│
          └──────────────────┬───────────────────┘
                             │
                             ▼
          ┌──────────────────────────────────────┐
          │        React + Vite Dashboard         │
          │  Tailwind CSS  ·  Lucide icons        │
          └──────────────────────────────────────┘
```

## Detection Rules

### Brute-Force Detection (MITRE T1110)

| Parameter | Value |
|-----------|-------|
| Window | 60 seconds (sliding) |
| Trigger | ≥5 failed logins from same `source_ip` against same `username` |
| Grouping | `(source_ip, username)` pairs |
| Severity | Low (5-9), Medium (10-19), High (≥20) |
| Confidence | 70% / 85% / 95% (scaled by attempt count) |

### Credential Abuse / Password Spraying (MITRE T1110.003)

| Parameter | Value |
|-----------|-------|
| Window | 60 seconds (sliding) |
| Trigger | ≥8 failures from same `source_ip` across ≥5 distinct usernames |
| Grouping | `source_ip` only |
| Severity | High (5-15 users), Critical (>15 users) |
| Confidence | 90% (fixed) |

Both rules produce deterministic incident IDs via SHA-256 hashing of detection parameters, ensuring identical inputs always yield identical output.

Configurable thresholds in [detection.py](app/services/detection.py):

```python
WINDOW_SECONDS = 60
BRUTE_FORCE_FAILURE_THRESHOLD = 5
CRED_ABUSE_DISTINCT_USER_THRESHOLD = 5
CRED_ABUSE_FAILURE_THRESHOLD = 8
```

## MITRE ATT&CK Mapping

Every incident is automatically annotated with structured MITRE metadata:

| Rule | Tactic | Technique | Sub-technique |
|------|--------|-----------|---------------|
| Brute-force | Credential Access | T1110 | -- |
| Password spraying | Credential Access | T1110.003 | Password Spraying |

Incidents include a `mitre` object with `tactic`, `technique`, and `technique_name` fields, populated via Pydantic model validators at creation time.

## Entity Risk Model

Risk scores are maintained per entity (`source_ip` or `username`) using weighted accumulation with exponential decay:

| Detection type | Weight |
|---------------|--------|
| Brute-force incident | +10.0 |
| Credential abuse incident | +25.0 |

**Decay**: 24-hour half-life using `score * exp(-ln(2)/24 * hours_elapsed)`.

Scores are thread-safe (protected by module-level lock) and rehydrated from persisted incidents on startup. The `GET /entity-risk/` endpoint returns `risk_score`, `total_incidents`, `open_incidents`, `highest_confidence`, and `last_seen` per entity.

## Incident Lifecycle

Incidents follow a managed state machine with persistence to `runs/incidents.json`:

```
    ┌──────┐    acknowledge    ┌──────────────┐    close    ┌────────┐
    │ open ├──────────────────►│ acknowledged ├────────────►│ closed │
    └──┬───┘                   └──────────────┘             └───┬────┘
       │                                                        │
       │◄───────────────── auto-reopen on new evidence ─────────┘
```

**Merging behavior** when the same `incident_id` is upserted:
- Time bounds extended (`first_seen` → earliest, `last_seen` → latest)
- Evidence counts summed, entity sets unioned
- Timeline and event lists concatenated
- Closed incidents automatically reopen if new evidence arrives

## Normalization & Field Mapping

Field mapping is driven by [config/field_mappings.yaml](config/field_mappings.yaml) with per-source profiles:

| Profile | Source | Notable mappings |
|---------|--------|------------------|
| `_default` | Generic JSON | Standard aliases (`source_ip`, `ip`, `client_ip`, etc.) |
| `okta` | Okta logs | `ipAddress` → `source_ip`, `published` → `timestamp`, `outcome.result` (dot-notation) |
| `windows_security` | Windows Event Log | `IpAddress` → `source_ip`, `SubjectUserName` → `username`, rejects EventID 4672/4634 |

### Canonical fields

| Field | Required | Aliases (default profile) |
|-------|----------|---------------------------|
| `timestamp` | Yes | `timestamp`, `time`, `@timestamp`, `ts` |
| `source_ip` | No | `source_ip`, `ip`, `client_ip`, `src_ip`, `remote_ip` |
| `username` | No | `username`, `user`, `user_id`, `account`, `principal` |
| `event_type` | Yes | `event_type`, `type`, `action`, `event` |
| `result` | Yes | `result`, `outcome`, `status` |
| `reason` | No | `reason`, `error`, `message`, `failure_reason` |
| `user_agent` | No | `user_agent`, `ua`, `agent` |
| `source` | No | `source`, `provider`, `log_source`, `system` |

**Telemetry rejection**: Events with types matching `heartbeat`, `health_check`, `ping`, `keepalive`, `metrics`, etc. are automatically dropped.

Validate mappings: `python -m app.services.mapping_loader --validate`

## API Contract

| Method | Endpoint | Response model | Description |
|--------|----------|----------------|-------------|
| `POST` | `/ingest/` | `IngestResponse` | Ingest raw events, returns run ID and incident count |
| `GET` | `/runs/` | `List[str]` | List all processing run IDs |
| `GET` | `/runs/{run_id}/meta` | `RunsMetaResponse` | Run metadata (timestamp, event count) |
| `GET` | `/runs/{run_id}/normalized` | `RunsNormalizedResponse` | Normalized events for a run |
| `GET` | `/runs/{run_id}/incidents` | `RunsIncidentsResponse` | Detected incidents for a run |
| `GET` | `/incidents/` | `IncidentListResponse` | All incidents across runs |
| `GET` | `/incidents/{id}` | `LifecycleIncidentResponse` | Single incident with `is_stale` flag |
| `PATCH` | `/incidents/{id}` | `LifecycleIncidentResponse` | Transition incident status |
| `GET` | `/entity-risk/` | `EntityRiskResponse` | Decayed per-entity risk scores |
| `GET` | `/metrics/` | `MetricsResponse` | Operational counters and breakdowns |
| `GET` | `/health` | `{"ok": true}` | Health check |

Response models are defined in [api_contract.py](app/schemas/api_contract.py). The contract is snapshot-tested in CI -- any unintentional change to the OpenAPI spec fails the build.

### Contract lock (CI)

The GitHub Actions workflow [openapi-contract.yml](.github/workflows/openapi-contract.yml) enforces API stability:

1. Starts the FastAPI app
2. Fetches `/openapi.json`
3. Canonicalizes JSON (sorted keys, stable formatting)
4. Diffs against committed snapshot at `openapi/openapi.snapshot.json`
5. Fails on any diff

Regenerate after intentional changes:

```bash
python scripts/export_openapi_snapshot.py
```

## Test Coverage

| Test suite | File | What it validates |
|-----------|------|-------------------|
| Detection | [test_detection.py](tests/test_detection.py) | Brute-force triggering, threshold boundaries (4 vs 5), 60s window logic, suppression/dedup, credential abuse, dynamic severity/confidence, MITRE mapping, snapshot tests |
| Incident lifecycle | [test_incident_lifecycle.py](tests/test_incident_lifecycle.py) | Status transitions (open → acknowledged → closed), merging, auto-reopen, persistence round-trip, timestamp management |
| Entity risk | [test_entity_risk.py](tests/test_entity_risk.py) | Accumulation by type (+10/+25), 24h half-life decay, entity aggregation, confidence tracking, open incident counts |
| Field mapping | [test_mapping.py](tests/test_mapping.py) | Default profile completeness, alias resolution, telemetry rejection, Okta profile, unknown source fallback, config validation |
| API contract | [test_backend_contract.py](tests/test_backend_contract.py) | Response schema validation against Pydantic models |
| Frontend contract | [test_frontend_contract_fidelity.py](tests/test_frontend_contract_fidelity.py) | Dashboard data alignment with backend schemas |

```bash
pytest tests/ -v
```

## Quickstart

### Prerequisites

- Python 3.10+
- Node.js 18+ (for dashboard)

### Backend

```bash
python -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\activate         # Windows

pip install -r requirements.txt
uvicorn app.main:main --reload --port 8000
```

### Dashboard

```bash
cd dashboard
npm install
npm run build    # Production build (served by FastAPI at /)
npm run dev      # Development server on :5173
```

### Ingest events

```bash
curl -X POST http://localhost:8000/ingest/ \
  -H "Content-Type: application/json" \
  -d '[
    {"timestamp":"2025-12-21T05:00:00Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","reason":"bad_password","source":"demo"},
    {"timestamp":"2025-12-21T05:00:01Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","reason":"bad_password","source":"demo"},
    {"timestamp":"2025-12-21T05:00:02Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","reason":"bad_password","source":"demo"},
    {"timestamp":"2025-12-21T05:00:03Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","reason":"bad_password","source":"demo"},
    {"timestamp":"2025-12-21T05:00:04Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","reason":"bad_password","source":"demo"}
  ]'
```

Response:

```json
{
  "run_id": "run-073d148ae4d443099bfbc064dcd0c1c9",
  "event_count": 5,
  "normalization_status": "success",
  "detection_status": "success",
  "incident_count": 1,
  "incidents": [...]
}
```

### Retrieve results

```bash
curl http://localhost:8000/runs/                          # List runs
curl http://localhost:8000/runs/{run_id}/incidents        # Incidents for a run
curl http://localhost:8000/incidents/                      # All incidents
curl http://localhost:8000/entity-risk/                    # Risk scores
curl http://localhost:8000/metrics/                        # Operational metrics
```

## Incident Structure

```json
{
  "incident_id": "inc_a1b2c3d4e5f67890abcdef12",
  "type": "brute_force",
  "status": "open",
  "severity": "low",
  "confidence": "70",
  "mitre": {
    "tactic": "Credential Access",
    "technique": "T1110",
    "technique_name": "Brute Force"
  },
  "summary": "Brute-force authentication activity detected (MITRE T1110): 5 failed login attempts against user 'alice' from source IP 203.0.113.10 during 2025-12-21T05:00:00Z\u20132025-12-21T05:00:04Z, exceeding brute-force threshold.",
  "recommended_actions": [
    "Validate whether the source IP and login pattern are expected for this user.",
    "Review authentication activity before and after the detection window.",
    "Assess account controls (lockout behavior, MFA enforcement).",
    "If unauthorized, follow response policy: reset credentials, revoke sessions, apply network controls."
  ],
  "affected_entities": ["203.0.113.10", "alice"],
  "evidence": {
    "window_start": "2025-12-21T05:00:00Z",
    "window_end": "2025-12-21T05:00:04Z",
    "counts": { "failures": 5 },
    "timeline": ["..."],
    "events": ["..."]
  },
  "first_seen": "2025-12-21T05:00:00Z",
  "last_seen": "2025-12-21T05:00:04Z"
}
```

## Project Structure

```
defensive-translator/
├── app/
│   ├── main.py                    # FastAPI entry point, mounts dashboard static files
│   ├── routes/
│   │   ├── ingest.py              # POST /ingest/ - event ingestion pipeline
│   │   ├── retrieval.py           # GET /runs/* - artifact retrieval
│   │   ├── incidents.py           # GET|PATCH /incidents/* - lifecycle management
│   │   ├── entity_risk.py         # GET /entity-risk/ - risk scoring
│   │   └── metrics.py             # GET /metrics/ - operational counters
│   ├── services/
│   │   ├── normalization.py       # Field mapping, timestamp coercion, validation
│   │   ├── detection.py           # Sliding window rules, incident generation
│   │   ├── incident_store.py      # Stateful persistence, merging, transitions
│   │   ├── entity_risk.py         # Weighted scoring with exponential decay
│   │   ├── metrics.py             # Thread-safe counter aggregation
│   │   └── mapping_loader.py      # YAML config loader with validation
│   └── schemas/
│       ├── event_models_new.py    # NormalizedEventNew (Pydantic v2)
│       ├── incident_new.py        # IncidentNew with MITRE fields
│       └── api_contract.py        # Response envelope models
├── config/
│   └── field_mappings.yaml        # Source-specific field alias profiles
├── dashboard/                     # React 19 + Vite + Tailwind CSS
│   ├── src/
│   │   ├── SecurityWorkflow.jsx   # Main dashboard component
│   │   └── components/            # SocWorkflowTable, etc.
│   └── dist/                      # Production build (mounted by FastAPI)
├── tests/                         # Pytest suite (6 modules)
├── scripts/
│   ├── export_openapi_snapshot.py # Regenerate OpenAPI contract snapshot
│   ├── canonicalize_json.py       # Deterministic JSON for CI diffs
│   └── translate_generic_json.py  # CLI helper for non-standard logs
├── openapi/
│   └── openapi.snapshot.json      # Committed API contract snapshot
├── .github/workflows/
│   └── openapi-contract.yml       # CI: contract-breaking change detection
├── runs/                          # Run artifacts (raw, normalized, incidents per run)
└── requirements.txt               # FastAPI, Pydantic v2, PyYAML, uvicorn
```

## Data Pipeline

Each `POST /ingest/` creates a run directory under `runs/{run_id}/` containing:

| Artifact | Description |
|----------|-------------|
| `raw.json` | Original ingested events (audit trail) |
| `meta.json` | Run metadata: timestamp, event count |
| `normalized.json` | Events mapped to canonical schema |
| `incidents.json` | Detected incidents with full evidence |

## Startup Behavior

On boot, the application:
1. Loads and validates `config/field_mappings.yaml` (fails fast on errors)
2. Rehydrates the incident store from `runs/incidents.json`
3. Rebuilds entity risk scores from persisted incidents
4. Restores metrics counters from run artifacts

## Security

- **Path traversal protection**: Run ID validation rejects `..`, `/`, and `\` characters
- **Input validation**: Pydantic v2 models enforce strict schema compliance
- **Deterministic IDs**: SHA-256 hashing prevents incident ID collision or prediction
- **Thread safety**: All shared state protected by module-level locks
- **CORS**: Configurable for production deployment

## License

This project is for educational and defensive security purposes.
