import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, Filter, Search, Upload } from 'lucide-react';
import securewatchLogo from './images/SecureWatch.png';

const API_BASE = 'http://localhost:8000';

const STATUS_BADGES = {
  open: 'bg-green-600 text-white',
  acknowledged: 'bg-yellow-500 text-black',
  closed: 'bg-gray-500 text-white'
};

const TYPE_LABELS = {
  brute_force: 'Brute Force',
  credential_abuse: 'Credential Abuse'
};

const defaultMitreMapping = (incidentType, mitreTechnique) => {
  if (incidentType === 'credential_abuse') {
    return {
      tactic: 'Credential Access',
      technique: 'T1110.003',
      technique_name: 'Password Spraying'
    };
  }
  return {
    tactic: 'Credential Access',
    technique: mitreTechnique || 'T1110',
    technique_name: 'Brute Force'
  };
};

const SAMPLE_DATASETS = [
  { value: 'fixtures/sample-bruteforce.json', label: 'Brute Force Sample' },
  { value: 'fixtures/sample-credential-abuse.json', label: 'Credential Abuse Sample' },
  { value: 'fixtures/sample-mixed-noise.json', label: 'Mixed Noise Sample' }
];

const SEVERITY_WEIGHTS = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

const normalizeSeverity = (value) => (typeof value === 'string' ? value.toLowerCase() : '');
const formatTimestamp = (value) => (typeof value === 'string' ? value.replace('T', ' ').replace('Z', '') : '');
const toTimestampMs = (value) => {
  if (typeof value !== 'string' || !value) return 0;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
};
const formatUtcTimestamp = (value) => {
  if (typeof value !== 'string' || !value) return 'N/A';
  const parsed = toTimestampMs(value);
  if (!parsed) return formatTimestamp(value);
  return new Date(parsed).toISOString().replace('T', ' ').replace('Z', ' UTC');
};
const formatConfidencePercent = (value) => {
  const num = Number(value);
  return Number.isFinite(num) ? `${(num * 100).toFixed(0)}%` : '0%';
};
const computeRollingRiskScore = (entityIncidents) => {
  if (!Array.isArray(entityIncidents) || entityIncidents.length === 0) return 0;
  const nowMs = Date.now();
  const rawScore = entityIncidents.reduce((total, inc) => {
    const confidence = Number(inc.confidence);
    const confidenceWeight = Number.isFinite(confidence) ? Math.min(Math.max(confidence, 0), 1) : 0;
    const severityWeight = SEVERITY_WEIGHTS[inc.severity] || 1;
    const statusWeight = inc.status === 'open' ? 1.3 : inc.status === 'acknowledged' ? 1 : 0.6;
    const seenMs = toTimestampMs(inc.last_seen || inc.first_seen || inc.timestamp);
    const ageHours = seenMs > 0 ? Math.max(0, (nowMs - seenMs) / 3600000) : 0;
    const decay = Math.exp(-ageHours / (24 * 7));
    return total + (confidenceWeight * severityWeight * statusWeight * decay);
  }, 0);
  return Math.min(100, Math.round(rawScore * 30));
};

const mapIncident = (incident) => ({
  ...incident,
  id: incident.incident_id,
  typeLabel: TYPE_LABELS[incident.type] || incident.type,
  severity: normalizeSeverity(incident.severity),
  timestamp: formatTimestamp(incident.last_seen || incident?.evidence?.window_end || incident.first_seen),
  user: incident?.subject?.username || 'unknown',
  sourceIp: incident?.subject?.source_ip || 'unknown',
  confidenceText: formatConfidencePercent(incident.confidence),
  mitre: incident?.mitre || defaultMitreMapping(incident.type, incident.mitre_technique),
  explanation: incident.explanation || {},
  affected: Array.isArray(incident.affected_entities) ? incident.affected_entities : [],
  events: Array.isArray(incident?.evidence?.events) ? incident.evidence.events : []
});

export default function SecurityWorkflow() {
  const [runs, setRuns] = useState([]);
  const [selectedRun, setSelectedRun] = useState('');
  const [runMeta, setRunMeta] = useState(null);
  const [normalizedCount, setNormalizedCount] = useState(0);
  const [incidentCount, setIncidentCount] = useState(0);
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [expandedId, setExpandedId] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [loadingSample, setLoadingSample] = useState(false);
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState({ severity: '', status: '' });
  const [activeView, setActiveView] = useState('incidents');
  const [entityView, setEntityView] = useState('username');
  const [selectedSample, setSelectedSample] = useState(SAMPLE_DATASETS[0].value);
  const fileInputRef = useRef(null);

  const loadRuns = async () => {
    const res = await fetch(`${API_BASE}/runs/`);
    if (!res.ok) throw new Error('Failed to load runs');
    const data = await res.json();
    setRuns(Array.isArray(data) ? data : []);
  };

  const loadIncidents = async () => {
    const res = await fetch(`${API_BASE}/incidents/`);
    if (!res.ok) throw new Error('Failed to load incident registry');
    const payload = await res.json();
    setIncidentCount(typeof payload.incident_count === 'number' ? payload.incident_count : 0);
    setIncidents((Array.isArray(payload.incidents) ? payload.incidents : []).map(mapIncident));
  };

  const loadRunContext = async (runId) => {
    if (!runId) return;
    setSelectedRun(runId);
    setLoading(true);
    try {
      const [metaRes, normalizedRes, incidentsRes] = await Promise.all([
        fetch(`${API_BASE}/runs/${runId}/meta`),
        fetch(`${API_BASE}/runs/${runId}/normalized`),
        fetch(`${API_BASE}/incidents/`)
      ]);
      const meta = metaRes.ok ? await metaRes.json() : null;
      const normalized = normalizedRes.ok ? await normalizedRes.json() : { event_count: 0 };
      const registry = incidentsRes.ok ? await incidentsRes.json() : { incident_count: 0, incidents: [] };
      setRunMeta(meta);
      setNormalizedCount(typeof normalized.event_count === 'number' ? normalized.event_count : 0);
      setIncidentCount(typeof registry.incident_count === 'number' ? registry.incident_count : 0);
      setIncidents((Array.isArray(registry.incidents) ? registry.incidents : []).map(mapIncident));
      setSelected(new Set());
      setError('');
    } catch {
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const patchSelected = async (targetStatus) => {
    if (!selected.size) return;
    setLoading(true);
    try {
      await Promise.all([...selected].map(async (id) => {
        const payload = targetStatus === 'closed'
          ? { status: 'closed', resolution_reason: 'closed_from_ui' }
          : { status: 'acknowledged' };
        const res = await fetch(`${API_BASE}/incidents/${id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.detail || `Patch failed for ${id}`);
        }
      }));
      await loadIncidents();
      setSelected(new Set());
      setError('');
    } catch (e) {
      setError(`Status update failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const canAcknowledge = useMemo(() => {
    const rows = incidents.filter((inc) => selected.has(inc.id));
    return rows.length > 0 && rows.every((inc) => inc.status === 'open');
  }, [incidents, selected]);

  const canClose = useMemo(() => {
    const rows = incidents.filter((inc) => selected.has(inc.id));
    return rows.length > 0 && rows.every((inc) => inc.status === 'acknowledged');
  }, [incidents, selected]);

  const filtered = incidents.filter((inc) => {
    if (filters.severity && inc.severity !== filters.severity) return false;
    if (filters.status && inc.status !== filters.status) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return inc.id.toLowerCase().includes(q) || inc.user.toLowerCase().includes(q) || inc.sourceIp.toLowerCase().includes(q) || inc.typeLabel.toLowerCase().includes(q);
  });

  const entityRows = useMemo(() => {
    const grouped = new Map();
    incidents.forEach((inc) => {
      const rawEntity = entityView === 'username' ? inc.user : inc.sourceIp;
      const entity = typeof rawEntity === 'string' && rawEntity.trim() ? rawEntity.trim() : 'unknown';
      if (!grouped.has(entity)) {
        grouped.set(entity, {
          entity,
          totalIncidents: 0,
          openIncidents: 0,
          highestConfidence: 0,
          lastSeen: '',
          lastSeenMs: 0,
          incidents: []
        });
      }
      const row = grouped.get(entity);
      row.totalIncidents += 1;
      if (inc.status === 'open') row.openIncidents += 1;

      const confidence = Number(inc.confidence);
      if (Number.isFinite(confidence) && confidence > row.highestConfidence) {
        row.highestConfidence = confidence;
      }

      const seenRaw = inc.last_seen || inc.first_seen || inc.timestamp;
      const seenMs = toTimestampMs(seenRaw);
      if (seenMs >= row.lastSeenMs) {
        row.lastSeenMs = seenMs;
        row.lastSeen = seenRaw || '';
      }

      row.incidents.push(inc);
    });

    return [...grouped.values()]
      .map((row) => ({
        ...row,
        rollingRiskScore: computeRollingRiskScore(row.incidents)
      }))
      .sort((a, b) => (
        b.rollingRiskScore - a.rollingRiskScore
        || b.openIncidents - a.openIncidents
        || b.highestConfidence - a.highestConfidence
        || b.lastSeenMs - a.lastSeenMs
      ));
  }, [incidents, entityView]);

  const filteredEntities = useMemo(() => {
    if (!search) return entityRows;
    const q = search.toLowerCase();
    return entityRows.filter((row) => row.entity.toLowerCase().includes(q));
  }, [entityRows, search]);

  useEffect(() => {
    (async () => {
      try {
        await Promise.all([loadRuns(), loadIncidents()]);
      } catch {
        setError('Failed to connect to backend');
      }
    })();
  }, []);

  useEffect(() => {
    if (runs.length > 0 && !selectedRun) loadRunContext(runs[0]);
  }, [runs, selectedRun]);

  const ingestEvents = async (events) => {
    const res = await fetch(`${API_BASE}/ingest/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(events)
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || 'Ingest failed');
    }
    const payload = await res.json();
    await loadRuns();
    await loadRunContext(payload.run_id);
  };

  const onUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const text = await file.text();
      const events = JSON.parse(text);
      await ingestEvents(events);
    } catch (e) {
      setError(`Upload failed: ${e.message}`);
    } finally {
      setUploading(false);
      event.target.value = '';
    }
  };

  const onLoadSample = async () => {
    setLoadingSample(true);
    try {
      const fixtureRes = await fetch(`/${selectedSample}`, { cache: 'no-store' });
      if (!fixtureRes.ok) throw new Error('Failed to load sample fixture');
      const events = await fixtureRes.json();
      if (!Array.isArray(events)) throw new Error('Sample fixture must be a JSON array');
      await ingestEvents(events);
      setActiveView('incidents');
      setError('');
    } catch (e) {
      setError(`Sample ingest failed: ${e.message}`);
    } finally {
      setLoadingSample(false);
    }
  };

  return (
    <div className="h-screen flex flex-col bg-gray-50">
      <header className="border-b border-gray-300 bg-white px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img src={securewatchLogo} alt="SecureWatch Engine logo" className="w-10 h-10 rounded" />
          <div>
            <div className="text-sm font-semibold">SecureWatch Engine</div>
            <div className="text-[11px] text-gray-500">Lifecycle Incident Registry View</div>
          </div>
        </div>
        <div className="text-[11px] text-gray-600">Events: {runMeta?.event_count ?? 0} - Normalized: {normalizedCount} - Incidents: {incidentCount}</div>
      </header>

      {error && <div className="px-4 py-2 text-xs bg-red-50 border-b border-red-200 text-red-700">{error}</div>}

      <div className="border-b border-gray-300 bg-white px-4 py-2 flex items-center gap-2">
        <select className="text-xs border border-gray-300 px-2 py-1 bg-white" value={selectedRun} onChange={(e) => loadRunContext(e.target.value)}>
          {runs.map((runId) => <option key={runId} value={runId}>{runId}</option>)}
        </select>
        <label className="px-2 py-1 text-xs bg-blue-600 text-white cursor-pointer flex items-center gap-1">
          <Upload className="w-3 h-3" />
          {uploading ? 'Uploading...' : 'Upload'}
          <input ref={fileInputRef} type="file" accept=".json" className="hidden" onChange={onUpload} disabled={uploading} />
        </label>
        <select
          className="text-xs border border-gray-300 px-2 py-1 bg-white"
          value={selectedSample}
          onChange={(e) => setSelectedSample(e.target.value)}
          disabled={uploading || loadingSample}
        >
          {SAMPLE_DATASETS.map((dataset) => (
            <option key={dataset.value} value={dataset.value}>{dataset.label}</option>
          ))}
        </select>
        <button
          type="button"
          className="px-2 py-1 text-xs border border-gray-300 bg-white disabled:text-gray-400"
          onClick={onLoadSample}
          disabled={uploading || loadingSample}
        >
          {loadingSample ? 'Loading Sample...' : 'Load Sample Dataset'}
        </button>
        <a href={`${API_BASE}/openapi.json`} target="_blank" rel="noreferrer" className="text-xs underline text-gray-700">OpenAPI Contract</a>
        {activeView === 'incidents' && (
          <div className="ml-auto flex items-center gap-2">
            <button className="px-2 py-1 text-xs border border-gray-300 disabled:text-gray-400" disabled={!canAcknowledge || loading} onClick={() => patchSelected('acknowledged')}>Mark Acknowledged</button>
            <button className="px-2 py-1 text-xs border border-gray-300 disabled:text-gray-400" disabled={!canClose || loading} onClick={() => patchSelected('closed')}>Mark Closed</button>
          </div>
        )}
      </div>

      <div className="border-b border-gray-200 bg-white px-4 py-2 flex items-center gap-2">
        <button
          type="button"
          className={`px-2 py-1 text-xs border ${activeView === 'incidents' ? 'border-blue-600 bg-blue-600 text-white' : 'border-gray-300 bg-white text-gray-700'}`}
          onClick={() => setActiveView('incidents')}
        >
          Incident Registry
        </button>
        <button
          type="button"
          className={`px-2 py-1 text-xs border ${activeView === 'entities' ? 'border-blue-600 bg-blue-600 text-white' : 'border-gray-300 bg-white text-gray-700'}`}
          onClick={() => setActiveView('entities')}
        >
          Entity Risk View
        </button>
        {activeView === 'entities' && (
          <div className="ml-2 flex items-center gap-2">
            <button
              type="button"
              className={`px-2 py-1 text-xs border ${entityView === 'username' ? 'border-gray-900 bg-gray-900 text-white' : 'border-gray-300 bg-white text-gray-700'}`}
              onClick={() => setEntityView('username')}
            >
              View by Username
            </button>
            <button
              type="button"
              className={`px-2 py-1 text-xs border ${entityView === 'source_ip' ? 'border-gray-900 bg-gray-900 text-white' : 'border-gray-300 bg-white text-gray-700'}`}
              onClick={() => setEntityView('source_ip')}
            >
              View by Source IP
            </button>
          </div>
        )}
      </div>

      <div className="border-b border-gray-200 bg-white px-4 py-2 flex items-center gap-2">
        <div className="relative w-80">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} className="w-full pl-7 pr-2 py-1 text-xs border border-gray-300" placeholder={activeView === 'incidents' ? 'Search incidents' : (entityView === 'username' ? 'Search usernames' : 'Search source IPs')} />
        </div>
        {activeView === 'incidents' && (
          <>
            <Filter className="w-3 h-3 text-gray-500" />
            <select className="text-xs border border-gray-300 px-2 py-1" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
              <option value="">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
            </select>
            <select className="text-xs border border-gray-300 px-2 py-1" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
              <option value="">All status</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="closed">Closed</option>
            </select>
          </>
        )}
      </div>

      <div className="flex-1 overflow-auto">
        {activeView === 'incidents' ? (
          <table className="w-full text-xs">
            <thead className="bg-gray-100 border-b border-gray-300 sticky top-0">
              <tr>
                <th className="px-2 py-2"><input type="checkbox" checked={selected.size > 0 && selected.size === filtered.length} onChange={() => setSelected(selected.size === filtered.length ? new Set() : new Set(filtered.map((inc) => inc.id)))} /></th>
                <th className="w-8 px-2 py-2"></th>
                <th className="px-2 py-2 text-left">ID</th><th className="px-2 py-2 text-left">Time</th><th className="px-2 py-2 text-left">Type</th><th className="px-2 py-2 text-left">Severity</th><th className="px-2 py-2 text-left">User</th><th className="px-2 py-2 text-left">Source IP</th><th className="px-2 py-2 text-left">Explanation</th><th className="px-2 py-2 text-left">Confidence</th><th className="px-2 py-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((inc) => (
                <React.Fragment key={inc.id}>
                  <tr className="border-b border-gray-200 hover:bg-gray-50 cursor-pointer" onClick={() => setExpandedId(expandedId === inc.id ? '' : inc.id)}>
                    <td className="px-2 py-2"><input type="checkbox" checked={selected.has(inc.id)} onChange={() => {}} onClick={(e) => { e.stopPropagation(); const next = new Set(selected); next.has(inc.id) ? next.delete(inc.id) : next.add(inc.id); setSelected(next); }} /></td>
                    <td className="px-1 py-2">
                      <button
                        type="button"
                        aria-label={expandedId === inc.id ? 'Collapse incident details' : 'Expand incident details'}
                        className="inline-flex h-5 w-5 items-center justify-center rounded border border-gray-200 bg-white text-gray-500 transition-colors hover:bg-gray-100 hover:text-gray-700"
                        onClick={(e) => {
                          e.stopPropagation();
                          setExpandedId(expandedId === inc.id ? '' : inc.id);
                        }}
                      >
                        <ChevronRight className={`w-3 h-3 transition-transform duration-200 ${expandedId === inc.id ? 'rotate-90' : ''}`} />
                      </button>
                    </td>
                    <td className="px-2 py-2 font-mono text-blue-700">{inc.id}</td><td className="px-2 py-2 font-mono">{inc.timestamp}</td><td className="px-2 py-2">{inc.typeLabel}</td><td className="px-2 py-2">{inc.severity}</td><td className="px-2 py-2">{inc.user}</td><td className="px-2 py-2 font-mono">{inc.sourceIp}</td>
                    <td className="px-2 py-2">{inc.explanation.observed} / {inc.explanation.threshold} in {inc.explanation.window}</td>
                    <td className="px-2 py-2 font-mono">{inc.confidenceText}</td>
                    <td className="px-2 py-2"><span className={`px-2 py-0.5 text-[10px] font-semibold ${STATUS_BADGES[inc.status] || STATUS_BADGES.open}`}>{inc.status}</span></td>
                  </tr>
                  <tr className="bg-gray-50 border-b border-gray-200">
                    <td colSpan={11} className="p-0">
                      <div className={`grid transition-all duration-300 ease-in-out ${expandedId === inc.id ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'}`}>
                        <div className="overflow-hidden">
                          <div className="px-3 py-3">
                            <div className="rounded border border-gray-200 bg-white p-3">
                              <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-600">Incident Details</div>
                              <div className="mt-2 grid grid-cols-2 gap-3 text-xs md:grid-cols-3">
                                <div>
                                  <div className="text-gray-500">First Seen</div>
                                  <div className="font-mono">{formatUtcTimestamp(inc.first_seen)}</div>
                                </div>
                                <div>
                                  <div className="text-gray-500">Last Seen</div>
                                  <div className="font-mono">{formatUtcTimestamp(inc.last_seen)}</div>
                                </div>
                                <div>
                                  <div className="text-gray-500">Evidence Count</div>
                                  <div className="font-mono">{inc.evidence_count ?? 0}</div>
                                </div>
                              </div>

                              <div className="mt-3 text-xs">
                                <div className="text-gray-500">Affected Entities</div>
                                {inc.affected.length > 0 ? (
                                  <ul className="mt-1 flex flex-wrap gap-1">
                                    {inc.affected.map((entity) => (
                                      <li key={`${inc.id}-${entity}`} className="rounded border border-gray-200 bg-gray-50 px-2 py-0.5 font-mono text-[11px]">
                                        {entity}
                                      </li>
                                    ))}
                                  </ul>
                                ) : (
                                  <div className="mt-1 font-mono">-</div>
                                )}
                              </div>

                              <div className="mt-3 text-xs">
                                <div className="text-gray-500">Full Explanation</div>
                                <pre className="mt-1 overflow-auto rounded border border-gray-200 bg-gray-50 p-2 font-mono text-[11px]">
                                  {JSON.stringify(inc.explanation || {}, null, 2)}
                                </pre>
                              </div>

                              <div className="mt-3 text-xs">
                                <div className="text-gray-500">Lifecycle Timestamps</div>
                                <div className="mt-1 grid grid-cols-1 gap-2 md:grid-cols-2">
                                  <div>
                                    <div className="text-gray-500">Created At</div>
                                    <div className="font-mono">{formatUtcTimestamp(inc.created_at)}</div>
                                  </div>
                                  <div>
                                    <div className="text-gray-500">Updated At</div>
                                    <div className="font-mono">{formatUtcTimestamp(inc.updated_at)}</div>
                                  </div>
                                  <div>
                                    <div className="text-gray-500">Status</div>
                                    <div className="font-mono">{inc.status || 'open'}</div>
                                  </div>
                                  <div>
                                    <div className="text-gray-500">Resolution Reason</div>
                                    <div className="font-mono break-all">{inc.resolution_reason || '-'}</div>
                                  </div>
                                </div>
                              </div>

                              <div className="mt-3 text-xs">
                                <div className="text-gray-500">MITRE ATT&CK Mapping</div>
                                <div className="mt-1 grid grid-cols-1 gap-2 md:grid-cols-3">
                                  <div>
                                    <div className="text-gray-500">Tactic</div>
                                    <div className="font-mono">{inc.mitre?.tactic || '-'}</div>
                                  </div>
                                  <div>
                                    <div className="text-gray-500">Technique</div>
                                    <div className="font-mono">{inc.mitre?.technique || inc.mitre_technique || '-'}</div>
                                  </div>
                                  <div>
                                    <div className="text-gray-500">Technique Name</div>
                                    <div className="font-mono">{inc.mitre?.technique_name || '-'}</div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                </React.Fragment>
              ))}
            </tbody>
          </table>
        ) : (
          <table className="w-full text-xs">
            <thead className="bg-gray-100 border-b border-gray-300 sticky top-0">
              <tr>
                <th className="px-2 py-2 text-left">{entityView === 'username' ? 'Username' : 'Source IP'}</th>
                <th className="px-2 py-2 text-right">Total Incidents</th>
                <th className="px-2 py-2 text-right">Open Incidents</th>
                <th className="px-2 py-2 text-right">Highest Confidence</th>
                <th className="px-2 py-2 text-left">Last Seen</th>
                <th className="px-2 py-2 text-right">Rolling Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {filteredEntities.length === 0 ? (
                <tr className="border-b border-gray-200">
                  <td colSpan={6} className="px-3 py-8 text-center text-gray-500">No entities found for current filters.</td>
                </tr>
              ) : (
                filteredEntities.map((row) => (
                  <tr key={row.entity} className="border-b border-gray-200 hover:bg-gray-50">
                    <td className="px-2 py-2 font-mono text-blue-700">{row.entity}</td>
                    <td className="px-2 py-2 text-right font-mono">{row.totalIncidents}</td>
                    <td className="px-2 py-2 text-right font-mono">{row.openIncidents}</td>
                    <td className="px-2 py-2 text-right font-mono">{formatConfidencePercent(row.highestConfidence)}</td>
                    <td className="px-2 py-2 font-mono">{formatUtcTimestamp(row.lastSeen)}</td>
                    <td className="px-2 py-2 text-right">
                      <span className={`inline-flex min-w-[44px] justify-center rounded px-2 py-0.5 font-mono text-[11px] font-semibold ${row.rollingRiskScore >= 75 ? 'bg-red-600 text-white' : row.rollingRiskScore >= 50 ? 'bg-orange-500 text-white' : row.rollingRiskScore >= 25 ? 'bg-yellow-400 text-black' : 'bg-green-500 text-white'}`}>
                        {row.rollingRiskScore}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="border-t border-gray-300 bg-gray-100 px-4 py-1.5 text-xs text-gray-600">
        {activeView === 'incidents'
          ? `${filtered.length} visible of ${incidentCount} total incidents`
          : `${filteredEntities.length} visible entities from ${incidentCount} total incidents`}
      </div>
    </div>
  );
}
