import React, { useState, useEffect } from 'react';
import { Upload, AlertCircle, CheckCircle, Clock, ChevronDown, ChevronUp, X } from 'lucide-react';

const API_BASE = 'http://localhost:8000';

// Deterministic severity colors: Red=Critical ONLY
const SEVERITY_COLORS = {
  critical: { bg: 'bg-red-900/20', border: 'border-red-700', text: 'text-red-200', label: 'bg-red-900 text-red-100' },
  high: { bg: 'bg-orange-900/20', border: 'border-orange-700', text: 'text-orange-200', label: 'bg-orange-900 text-orange-100' },
  medium: { bg: 'bg-yellow-900/20', border: 'border-yellow-700', text: 'text-yellow-200', label: 'bg-yellow-900 text-yellow-100' },
  low: { bg: 'bg-blue-900/20', border: 'border-blue-700', text: 'text-blue-200', label: 'bg-blue-900 text-blue-100' }
};

function formatRelativeTime(isoString) {
  try {
    const date = new Date(isoString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  } catch {
    return isoString.split('T')[0];
  }
}

function MetricPill({ label, value, severity = null }) {
  const isRed = severity === 'critical' && value > 0;
  return (
    <div className={`px-4 py-3 rounded-lg border transition-all ${
      isRed 
        ? 'bg-red-900/30 border-red-700/50' 
        : 'bg-slate-700/40 border-slate-600/50'
    }`}>
      <div className="text-xs font-medium text-slate-400 uppercase tracking-wide">{label}</div>
      <div className={`text-2xl font-bold mt-1 ${isRed ? 'text-red-300' : 'text-slate-100'}`}>
        {value}
      </div>
    </div>
  );
}

function RunCard({ runId, meta, isSelected, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left p-4 rounded-lg border transition-all duration-150 ${
        isSelected
          ? 'bg-slate-700/60 border-blue-500 shadow-lg shadow-blue-500/20'
          : 'bg-slate-800/40 border-slate-700/50 hover:border-slate-600'
      }`}
    >
      {isSelected && <div className="absolute left-0 top-0 bottom-0 w-1 bg-blue-500 rounded-l-lg"></div>}
      <div className="font-mono text-sm text-slate-300 truncate mb-2">{runId}</div>
      <div className="text-xs text-slate-500 space-y-1">
        <p>{meta.event_count} events • {formatRelativeTime(meta.created_at)}</p>
      </div>
    </button>
  );
}

function ErrorBanner({ message, onDismiss }) {
  return (
    <div className="flex items-center gap-3 bg-red-900/25 border border-red-700/50 text-red-200 px-4 py-2 rounded text-sm">
      <AlertCircle size={16} className="flex-shrink-0" />
      <span className="flex-1">{message}</span>
      <button
        onClick={onDismiss}
        className="text-red-300 hover:text-red-100 transition p-1"
      >
        <X size={16} />
      </button>
    </div>
  );
}

function EmptyStateRuns() {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center px-4">
      <Clock size={40} className="text-slate-600 mb-4" />
      <p className="text-slate-400 text-sm font-medium mb-1">No runs yet</p>
      <p className="text-slate-500 text-xs">Upload authentication events to begin analysis</p>
    </div>
  );
}

function EmptyStateMain() {
  return (
    <div className="flex flex-col items-center justify-center h-96 text-center px-4">
      <Clock size={48} className="text-slate-600 mb-6" />
      <p className="text-slate-300 text-base font-medium mb-1">Select a run or upload events</p>
      <p className="text-slate-500 text-sm">Start by uploading a JSON file containing authentication events</p>
    </div>
  );
}

function IncidentCard({ incident, isExpanded, onToggle }) {
  const color = SEVERITY_COLORS[incident.severity] || SEVERITY_COLORS.low;
  
  return (
    <div className={`rounded-lg border transition-all duration-150 ${color.bg} ${color.border}`}>
      <button
        onClick={onToggle}
        className="w-full text-left p-4 hover:bg-slate-700/20 transition-colors duration-100"
      >
        <div className="flex items-start justify-between gap-4 mb-2">
          <div className="flex items-center gap-2 flex-1">
            <span className={`px-2 py-1 rounded text-xs font-bold ${color.label}`}>
              {incident.severity.toUpperCase()}
            </span>
            <span className="bg-slate-700/60 text-slate-300 px-2 py-1 rounded text-xs font-mono">
              {incident.type.replace('_', ' ')}
            </span>
            <span className="text-slate-500 text-xs">{incident.mitre_technique}</span>
          </div>
          <div className={`flex-shrink-0 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
            <ChevronDown size={18} className={color.text} />
          </div>
        </div>
        <p className={`text-sm font-medium mb-2 ${color.text} line-clamp-2`}>{incident.summary}</p>
        <p className="text-xs text-slate-400">IP: <span className="font-mono text-slate-300">{incident.subject.source_ip}</span></p>
      </button>

      {isExpanded && (
        <div className={`border-t ${color.border} bg-slate-900/40 p-4 space-y-4 text-sm`}>
          <div>
            <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wide mb-2">Summary</h4>
            <p className="text-slate-300">{incident.summary}</p>
          </div>

          <div>
            <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wide mb-2">Evidence Window</h4>
            <div className="bg-slate-800/60 rounded p-3 text-xs text-slate-400 space-y-1 border border-slate-700/40">
              <p><span className="text-slate-300 font-medium">Start:</span> {incident.evidence.window_start}</p>
              <p><span className="text-slate-300 font-medium">End:</span> {incident.evidence.window_end}</p>
              <p><span className="text-slate-300 font-medium">Failed Attempts:</span> {incident.evidence.counts.failures}</p>
              {incident.evidence.counts.distinct_users && (
                <p><span className="text-slate-300 font-medium">Distinct Accounts:</span> {incident.evidence.counts.distinct_users}</p>
              )}
            </div>
          </div>

          <div>
            <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wide mb-2">Timeline ({incident.evidence.timeline.length})</h4>
            <div className="bg-slate-800/60 rounded p-3 max-h-40 overflow-y-auto border border-slate-700/40 space-y-1 text-xs text-slate-400">
              {incident.evidence.timeline.map((ev, i) => (
                <div key={i} className="font-mono">
                  <span className="text-slate-500">{ev.timestamp}</span>
                  <span className="text-slate-400 mx-2">→</span>
                  <span className="text-slate-300">{ev.event_type}</span>
                  <span className={ev.result === 'failure' ? 'text-red-400' : 'text-green-400'}>
                    {' '}[{ev.result}]
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wide mb-2">Recommended Actions</h4>
            <ul className="space-y-2">
              {incident.recommended_actions.map((action, i) => (
                <li key={i} className="text-slate-300 text-xs flex gap-3">
                  <span className="text-slate-500 flex-shrink-0 font-bold mt-0.5">→</span>
                  <span className="pt-0.5">{action}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="text-xs text-slate-500 pt-2 border-t border-slate-700/40">
            Confidence: <span className="text-slate-400 font-medium">{incident.confidence}%</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SecurityDashboard() {
  const [runs, setRuns] = useState([]);
  const [selectedRun, setSelectedRun] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [normalized, setNormalized] = useState([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [expandedIncident, setExpandedIncident] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchRuns();
  }, []);

  const fetchRuns = async () => {
    try {
      const res = await fetch(`${API_BASE}/runs/`);
      const data = await res.json();
      setRuns(data);
      setError(null);
    } catch (err) {
      setError('Failed to connect to server. Ensure FastAPI is running on localhost:8000');
    }
  };

  const fetchRunDetails = async (runId) => {
    setLoading(true);
    try {
      const [metaRes, normRes, incRes] = await Promise.all([
        fetch(`${API_BASE}/runs/${runId}/meta`),
        fetch(`${API_BASE}/runs/${runId}/normalized`),
        fetch(`${API_BASE}/runs/${runId}/incidents`)
      ]);

      const meta = await metaRes.json();
      const norm = await normRes.json();
      const inc = await incRes.json();

      setSelectedRun({ id: runId, ...meta });
      setNormalized(norm.events || []);
      setIncidents(inc.incidents || []);
      setFilterSeverity('all');
      setExpandedIncident(null);
      setError(null);
    } catch (err) {
      setError('Failed to load run details');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    try {
      const fileContent = await file.text();
      const events = JSON.parse(fileContent);

      const res = await fetch(`${API_BASE}/ingest/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(events)
      });

      if (!res.ok) throw new Error('Upload failed');

      const result = await res.json();
      setError(null);
      
      await fetchRuns();
      setTimeout(() => fetchRunDetails(result.run_id), 500);
    } catch (err) {
      setError('Upload failed: ' + err.message);
    } finally {
      setUploading(false);
    }
  };

  const filteredIncidents = incidents.filter(inc => 
    filterSeverity === 'all' || inc.severity === filterSeverity
  );

  const stats = {
    total: incidents.length,
    critical: incidents.filter(i => i.severity === 'critical').length,
    high: incidents.filter(i => i.severity === 'high').length,
    bruteForce: incidents.filter(i => i.type === 'brute_force').length,
    credAbuse: incidents.filter(i => i.type === 'credential_abuse').length
  };

  return (
    <div className="h-full w-full bg-slate-950 flex flex-col">
      {/* TIER 1: System State Header */}
      <div className="bg-slate-900 border-b border-slate-800 sticky top-0 z-50 w-full">
        <div className="w-full px-6 py-4">
          <div className="flex justify-between items-center mb-4">
            <div>
              <h1 className="text-2xl font-bold text-slate-100">🛡️ Security Workflow</h1>
              <p className="text-slate-500 text-xs font-medium mt-1">Authentication Event Detection & Analysis</p>
            </div>
            <div className="flex gap-3">
              <label className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg cursor-pointer flex items-center gap-2 transition-colors duration-150 text-sm font-medium">
                <Upload size={16} />
                Upload Events
                <input type="file" accept=".json" onChange={handleFileUpload} disabled={uploading} className="hidden" />
              </label>
              <button onClick={fetchRuns} className="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg transition-colors duration-150 text-sm font-medium">
                Refresh
              </button>
            </div>
          </div>

          {error && (
            <ErrorBanner 
              message={error} 
              onDismiss={() => setError(null)}
            />
          )}
        </div>
      </div>

      <div className="w-full px-6 py-8 flex flex-col flex-1 overflow-hidden">
        {/* TIER 2: Context Metrics (Analyst Scan) */}
        {selectedRun && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
            <MetricPill label="Total Events" value={selectedRun.event_count} />
            <MetricPill label="Normalized" value={normalized.length} />
            <MetricPill label="Incidents" value={stats.total} severity={stats.critical > 0 ? 'critical' : null} />
            <MetricPill label="Critical" value={stats.critical} severity="critical" />
          </div>
        )}

        <div className="flex flex-1 gap-6 overflow-hidden">
          {/* TIER 2b: Run Context (Darker Background) */}
          <div className="w-full max-w-xs min-w-[220px]">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden backdrop-blur-sm">
              <div className="bg-slate-900/80 border-b border-slate-700/50 px-4 py-3">
                <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wide">Runs</h2>
                <p className="text-xs text-slate-500 mt-1">{runs.length} total</p>
              </div>
              <div className="overflow-y-auto max-h-96 space-y-2 p-3">
                {runs.length === 0 ? (
                  <EmptyStateRuns />
                ) : (
                  runs.map(runId => (
                    <RunCard
                      key={runId}
                      runId={runId}
                      meta={selectedRun?.id === runId ? selectedRun : { event_count: '...', created_at: new Date().toISOString() }}
                      isSelected={selectedRun?.id === runId}
                      onClick={() => fetchRunDetails(runId)}
                    />
                  ))
                )}
              </div>
            </div>
          </div>

          {/* TIER 3: Incident Detail (Lighter Background, Main Canvas) */}
          <div className="flex-1 min-w-0">
            {!selectedRun ? (
              <div className="bg-slate-800/30 border border-slate-700/40 rounded-lg backdrop-blur-sm">
                <EmptyStateMain />
              </div>
            ) : (
              <div className="space-y-6">
                {/* Incident Type Breakdown */}
                {incidents.length > 0 && (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4 backdrop-blur-sm">
                      <p className="text-xs text-slate-400 uppercase tracking-wide font-medium">Brute Force</p>
                      <p className="text-2xl font-bold text-orange-300 mt-2">{stats.bruteForce}</p>
                    </div>
                    <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4 backdrop-blur-sm">
                      <p className="text-xs text-slate-400 uppercase tracking-wide font-medium">Credential Abuse</p>
                      <p className="text-2xl font-bold text-red-300 mt-2">{stats.credAbuse}</p>
                    </div>
                  </div>
                )}

                {/* Severity Filter */}
                {incidents.length > 0 && (
                  <div className="flex gap-2 flex-wrap">
                    {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
                      <button
                        key={sev}
                        onClick={() => setFilterSeverity(sev)}
                        className={`px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 ${
                          filterSeverity === sev
                            ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20'
                            : 'bg-slate-700/40 text-slate-300 hover:bg-slate-700/60'
                        }`}
                      >
                        {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
                        {sev !== 'all' && ` (${incidents.filter(i => i.severity === sev).length})`}
                      </button>
                    ))}
                  </div>
                )}

                {/* Incidents List */}
                <div className="space-y-3">
                  {loading ? (
                    <div className="text-center py-12 text-slate-400">
                      <div className="inline-block animate-pulse">Loading incidents...</div>
                    </div>
                  ) : filteredIncidents.length === 0 ? (
                    <div className="bg-slate-800/30 border border-slate-700/40 rounded-lg backdrop-blur-sm">
                      <div className="flex flex-col items-center justify-center py-12 text-center px-4">
                        <CheckCircle size={40} className="text-green-600 mb-4" />
                        <p className="text-slate-300 text-sm font-medium">No incidents detected</p>
                        <p className="text-slate-500 text-xs mt-1">Your authentication events are clean</p>
                      </div>
                    </div>
                  ) : (
                    filteredIncidents.map(incident => (
                      <IncidentCard
                        key={incident.incident_id}
                        incident={incident}
                        isExpanded={expandedIncident === incident.incident_id}
                        onToggle={() => setExpandedIncident(
                          expandedIncident === incident.incident_id ? null : incident.incident_id
                        )}
                      />
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
