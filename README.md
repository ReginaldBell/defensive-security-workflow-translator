# Defensive Translator

A security event processing and threat detection system that ingests authentication logs from various sources, normalizes them into a common schema, and detects brute-force and credential abuse patterns with explainable incident reports.

## Overview

Defensive Translator is a FastAPI-based security automation platform designed to:
- **Ingest** authentication logs from diverse sources (SIEM, cloud providers, applications)
- **Normalize** heterogeneous log formats into a unified event schema
- **Detect** brute-force attacks and credential abuse (password spraying) using sliding window analysis
- **Generate** explainable security incidents with MITRE ATT&CK technique mappings and actionable remediation steps

The system provides both a REST API for programmatic access and a React-based dashboard for visualization and investigation.

## Architecture

```
┌─────────────────┐
│  Log Sources    │  (Various formats: JSON logs, SIEM exports, etc.)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Ingestion API  │  POST /ingest/
│  (FastAPI)      │  - Accepts raw events
└────────┬────────┘  - Creates run artifacts
         │
         ▼
┌─────────────────┐
│  Normalization  │  - Maps diverse fields (timestamp, source_ip, username, etc.)
│  Service        │  - Validates schema compliance
└────────┬────────┘  - Sorts chronologically
         │
         ▼
┌─────────────────┐
│  Detection      │  - Sliding window analysis (60-second windows)
│  Service        │  - Brute-force detection (≥5 failures/user)
└────────┬────────┘  - Credential abuse detection (≥5 users, ≥8 failures)
         │
         ▼
┌─────────────────┐
│  Incidents      │  - Deterministic incident IDs (SHA-256 based)
│  (Explainable)  │  - MITRE ATT&CK technique mapping (T1110, T1110.003)
└────────┬────────┘  - Severity scoring and confidence levels
         │
         ▼
┌─────────────────┐
│  Retrieval API  │  GET /runs/, /runs/{id}/normalized, /runs/{id}/incidents
│  & Dashboard    │  - React + Vite frontend
└─────────────────┘  - Real-time incident investigation
```

## Features

### 1. Flexible Log Ingestion
- Accepts arbitrary JSON arrays of authentication events
- Tolerant field mapping: supports common field name variations
  - Timestamps: `timestamp`, `time`, `@timestamp`, `ts`
  - Source IPs: `source_ip`, `ip`, `client_ip`, `src_ip`, `remote_ip`
  - Usernames: `username`, `user`, `user_id`, `account`, `principal`
  - Event types: `event_type`, `type`, `action`, `event`
  - Results: `result`, `outcome`, `status`
- Automatic timestamp normalization to ISO 8601 UTC format

### 2. Event Normalization
**Input**: Heterogeneous log formats
**Output**: Standardized schema ([event_models_new.py:4-12](app/schemas/event_models_new.py#L4-L12))
```json
{
  "timestamp": "2025-12-21T05:00:00Z",
  "source_ip": "203.0.113.10",
  "username": "alice",
  "event_type": "login_attempt",
  "result": "failure",
  "reason": "bad_password",
  "user_agent": "Mozilla/5.0",
  "source": "auth_service"
}
```

### 3. Threat Detection

#### Brute-Force Detection (MITRE T1110)
- **Trigger**: ≥5 failed login attempts from the same source IP against the same username within 60 seconds
- **Severity**: Dynamic (low: 5-9 attempts, medium: 10-19, high: ≥20)
- **Confidence**: Scaled by attempt count (70-95%)

#### Credential Abuse Detection (MITRE T1110.003 - Password Spraying)
- **Trigger**: ≥8 failed login attempts from the same source IP across ≥5 distinct usernames within 60 seconds
- **Severity**: High (≥5 users), Critical (≥15 users)
- **Confidence**: 90%

### 4. Explainable Incidents
All incidents include:
- **Deterministic IDs**: SHA-256 based on detection parameters (IP, username, window, counts)
- **Human-readable summary**: Generated from templates ([detection.py:36-60](app/services/detection.py#L36-L60))
- **Recommended actions**: 4-step investigation and response guide
- **Complete evidence**: Window bounds, event counts, full event timeline with timestamps

Example incident structure:
```json
{
  "incident_id": "inc_a1b2c3d4e5f67890abcdef12",
  "type": "brute_force",
  "mitre_technique": "T1110",
  "severity": "high",
  "confidence": "95",
  "summary": "Brute-force authentication activity detected (MITRE T1110): 20 failed login attempts against user 'alice' from source IP 203.0.113.10 during 2025-12-21T05:00:00Z–2025-12-21T05:00:59Z, exceeding brute-force threshold.",
  "recommended_actions": [
    "Validate whether the source IP and login pattern are expected for this user (VPNs, known locations, automation).",
    "Review authentication activity before and after the detection window to identify escalation or successful access.",
    "Assess account controls (lockout behavior, MFA enforcement) and confirm whether the user experienced authentication issues.",
    "If activity is unauthorized, follow response policy: reset credentials, revoke active sessions, and apply network controls as appropriate."
  ],
  "subject": {
    "source_ip": "203.0.113.10",
    "username": "alice"
  },
  "evidence": {
    "window_start": "2025-12-21T05:00:00Z",
    "window_end": "2025-12-21T05:00:59Z",
    "counts": { "failures": 20 },
    "timeline": [...],
    "events": [...]
  }
}
```

## Installation

### Prerequisites
- Python 3.8+
- Node.js 16+ (for dashboard)

### Backend Setup
```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Run FastAPI server
uvicorn app.main:main --reload --port 8000
```

### Dashboard Setup
```bash
cd dashboard
npm install
npm run dev  # Development server
npm run build  # Production build
```

## Usage

### 1. Ingest Events
```bash
curl -X POST http://localhost:8000/ingest/ \
  -H "Content-Type: application/json" \
  -d @sample.json
```

**Response:**
```json
{
  "run_id": "run-073d148ae4d443099bfbc064dcd0c1c9",
  "event_count": 2,
  "normalization_status": "success",
  "detection_status": "success"
}
```

### 2. List All Runs
```bash
curl http://localhost:8000/runs/
```

### 3. Retrieve Normalized Events
```bash
curl http://localhost:8000/runs/{run_id}/normalized
```

### 4. Retrieve Detected Incidents
```bash
curl http://localhost:8000/runs/{run_id}/incidents
```

### 5. View Dashboard
Navigate to `http://localhost:8000/` (after building dashboard with `npm run build`)

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/ingest/` | Ingest raw authentication events |
| `GET` | `/runs/` | List all processing runs |
| `GET` | `/runs/{run_id}/meta` | Get run metadata (timestamp, event count) |
| `GET` | `/runs/{run_id}/normalized` | Get normalized events for a run |
| `GET` | `/runs/{run_id}/incidents` | Get detected incidents for a run |
| `GET` | `/health` | Health check endpoint |

## Data Pipeline

Each ingestion creates a **run** with the following artifacts in `runs/{run_id}/`:

1. **raw.json**: Original ingested events
2. **meta.json**: Run metadata (timestamp, event count)
3. **normalized.json**: Events normalized to common schema
4. **incidents.json**: Detected security incidents with evidence

## Detection Parameters

Configurable thresholds in [detection.py:19-22](app/services/detection.py#L19-L22):

```python
WINDOW_SECONDS = 60                      # Sliding window size
BRUTE_FORCE_FAILURE_THRESHOLD = 5        # Min failures for brute-force
CRED_ABUSE_DISTINCT_USER_THRESHOLD = 5   # Min distinct users for cred abuse
CRED_ABUSE_FAILURE_THRESHOLD = 8         # Min total failures for cred abuse
```

## Testing

```bash
# Run tests
pytest tests/

# Run specific test
pytest tests/test_detection.py -v
```

**Test Coverage**: Validates deterministic incident generation, schema compliance, and evidence completeness ([test_detection.py](tests/test_detection.py)).

## Project Structure

```
defensive-translator/
├── app/
│   ├── main.py                 # FastAPI application entry point
│   ├── routes/
│   │   ├── ingest.py           # Event ingestion endpoint
│   │   └── retrieval.py        # Run retrieval endpoints
│   ├── services/
│   │   ├── normalization.py    # Log normalization logic
│   │   └── detection.py        # Threat detection algorithms
│   └── schemas/
│       ├── event_models_new.py # Normalized event schema
│       └── incident_new.py     # Incident schema
├── dashboard/                  # React + Vite frontend
├── runs/                       # Processing run artifacts
├── tests/                      # Pytest test suite
├── requirements.txt            # Python dependencies
└── README.md
```

## Technical Highlights

### Deterministic Design
- **Reproducible incident IDs**: Same input always generates same incident ID
- **Template-based summaries**: Consistent explanations for identical detection patterns
- **Sorted processing**: Events processed in chronological order

### Performance Optimizations
- **Sliding window algorithm**: O(n) time complexity for event processing
- **Deque-based windowing**: Efficient memory usage for temporal aggregation
- **Schema validation**: Early rejection of malformed events

### Security Considerations
- **Path traversal protection**: Run ID validation prevents directory traversal attacks ([retrieval.py:8-16](app/routes/retrieval.py#L8-L16))
- **Input validation**: Pydantic models enforce strict schema compliance
- **CORS configuration**: Configurable for production environments

## Development Phases

**Phase 1-2**: Core ingestion and normalization pipeline
**Phase 3**: Brute-force and credential abuse detection
**Phase 4**: Deterministic explainability with MITRE ATT&CK mappings ✅

## License

This project is for educational and defensive security purposes.
