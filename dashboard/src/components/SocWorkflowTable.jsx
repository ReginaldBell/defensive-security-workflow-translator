import React, { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

// ── Mapping-approved severity colors (deterministic, backend-authoritative) ──
const SEVERITY_COLORS = {
  critical: { label: 'bg-red-900 text-red-100' },
  high:     { label: 'bg-orange-900 text-orange-100' },
  medium:   { label: 'bg-yellow-900 text-yellow-100' },
  low:      { label: 'bg-blue-900 text-blue-100' }
};

const TYPE_LABELS = {
  brute_force: 'Brute Force',
  credential_abuse: 'Credential Abuse'
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ── Approved columns (read-only projection of IncidentNew schema) ──
//
// | UI Column   | Backend Field Path                         |
// |-------------|---------------------------------------------|
// | ID          | incident.incident_id                        |
// | Time        | incident.evidence.window_start              |
// | Severity    | incident.severity                           |
// | Type        | incident.type                               |
// | Technique   | incident.mitre_technique                    |
// | User        | incident.subject.username                   |
// | Source IP   | incident.subject.source_ip                  |
// | Confidence  | incident.confidence                         |
// | (expanded)  | incident.summary                            |
// | (expanded)  | incident.recommended_actions                |
// | (expanded)  | incident.evidence.window_start → window_end |
// | (expanded)  | incident.evidence.counts                    |
// | (expanded)  | incident.evidence.timeline                  |
//
// Unsupported (NOT rendered): status, assignee, tags, actions, playbook, SIEM query

function SeverityBadge({ severity }) {
  const colors = SEVERITY_COLORS[severity] || SEVERITY_COLORS.low;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${colors.label}`}>
      {severity}
    </span>
  );
}

function ExpandedRow({ incident, colSpan }) {
  const confidencePercent = Number.isFinite(Number(incident.confidence))
    ? (Number(incident.confidence) * 100).toFixed(0)
    : '0';
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-3 bg-zinc-800/50 border-b border-zinc-700">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          {/* Summary — incident.summary */}
          <div>
            <h4 className="text-zinc-400 font-medium mb-1">Summary</h4>
            <p className="text-zinc-200">{incident.summary}</p>
          </div>

          {/* Recommended Actions — incident.recommended_actions (display only) */}
          <div>
            <h4 className="text-zinc-400 font-medium mb-1">Recommended Actions</h4>
            <ul className="list-disc list-inside text-zinc-300 space-y-0.5">
              {incident.recommended_actions.map((action, i) => (
                <li key={i}>{action}</li>
              ))}
            </ul>
          </div>

          {/* Evidence Window — incident.evidence.window_start/end + counts */}
          <div>
            <h4 className="text-zinc-400 font-medium mb-1">Evidence Window</h4>
            <div className="text-zinc-300 space-y-0.5">
              <p><span className="text-zinc-500">Start:</span> {incident.evidence.window_start}</p>
              <p><span className="text-zinc-500">End:</span> {incident.evidence.window_end}</p>
              {incident.evidence.counts && (
                <p>
                  <span className="text-zinc-500">Failures:</span> {incident.evidence.counts.failures ?? '—'}
                  {incident.evidence.counts.distinct_users != null && (
                    <> &middot; <span className="text-zinc-500">Distinct users:</span> {incident.evidence.counts.distinct_users}</>
                  )}
                </p>
              )}
              {incident.evidence.events && (
                <p><span className="text-zinc-500">Events:</span> {incident.evidence.events.length}</p>
              )}
            </div>
          </div>

          {/* Timeline — incident.evidence.timeline */}
          <div>
            <h4 className="text-zinc-400 font-medium mb-1">
              Timeline ({incident.evidence.timeline?.length ?? 0})
            </h4>
            <div className="bg-zinc-900/60 rounded p-2 max-h-40 overflow-y-auto border border-zinc-700/40 space-y-1 text-xs text-zinc-400">
              {(incident.evidence.timeline || []).map((ev, i) => (
                <div key={i} className="font-mono">
                  <span className="text-zinc-500">{ev.timestamp}</span>
                  <span className="text-zinc-600 mx-1">&rarr;</span>
                  <span className="text-zinc-300">{ev.event_type}</span>
                  <span className={ev.result === 'failure' ? 'text-red-400' : 'text-green-400'}>
                    {' '}[{ev.result}]
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Confidence — incident.confidence */}
        <div className="text-xs text-zinc-500 pt-3 mt-3 border-t border-zinc-700/40">
          Confidence: <span className="text-zinc-400 font-medium">{confidencePercent}%</span>
        </div>
      </td>
    </tr>
  );
}

// ── Column definitions (approved mapping only, no unsupported fields) ──
const COLUMNS = [
  { key: 'incident_id',    label: 'ID' },
  { key: 'window_start',   label: 'Time' },
  { key: 'severity',       label: 'Severity' },
  { key: 'type',           label: 'Type' },
  { key: 'mitre_technique', label: 'Technique' },
  { key: 'username',       label: 'User' },
  { key: 'source_ip',      label: 'Source IP' },
  { key: 'confidence',     label: 'Confidence' },
];

const COL_SPAN = COLUMNS.length + 1; // +1 for expand toggle

function sortCompare(a, b, key) {
  switch (key) {
    case 'severity':
      return (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4);
    case 'type':
      return a.type.localeCompare(b.type);
    case 'mitre_technique':
      return a.mitre_technique.localeCompare(b.mitre_technique);
    case 'source_ip':
      return a.subject.source_ip.localeCompare(b.subject.source_ip);
    case 'username':
      return a.subject.username.localeCompare(b.subject.username);
    case 'confidence':
      return Number(a.confidence ?? 0) - Number(b.confidence ?? 0);
    case 'window_start':
      return a.evidence.window_start.localeCompare(b.evidence.window_start);
    case 'incident_id':
      return a.incident_id.localeCompare(b.incident_id);
    default:
      return 0;
  }
}

export default function SocWorkflowTable({ incidents = [] }) {
  const [sortKey, setSortKey] = useState('severity');
  const [sortAsc, setSortAsc] = useState(false);
  const [expandedId, setExpandedId] = useState(null);

  const sorted = [...incidents].sort((a, b) => {
    const cmp = sortCompare(a, b, sortKey);
    return sortAsc ? cmp : -cmp;
  });

  function handleSort(key) {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  }

  function SortHeader({ label, columnKey }) {
    const active = sortKey === columnKey;
    return (
      <th
        className="px-3 py-2 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider cursor-pointer select-none hover:text-zinc-200"
        onClick={() => handleSort(columnKey)}
      >
        <span className="inline-flex items-center gap-1">
          {label}
          {active && (sortAsc ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
        </span>
      </th>
    );
  }

  if (incidents.length === 0) {
    return (
      <div className="text-center text-zinc-500 py-12">
        No incidents to display. Select a run from the sidebar.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-700">
      <table className="w-full text-sm text-left">
        <thead className="bg-zinc-800/80 border-b border-zinc-700">
          <tr>
            {COLUMNS.map(col => (
              <SortHeader key={col.key} label={col.label} columnKey={col.key} />
            ))}
            <th className="px-3 py-2 w-8"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-700/50">
          {sorted.map((inc) => {
            const isExpanded = expandedId === inc.incident_id;
            return (
              <React.Fragment key={inc.incident_id}>
                <tr
                  className="hover:bg-zinc-800/40 cursor-pointer transition-colors"
                  onClick={() => setExpandedId(isExpanded ? null : inc.incident_id)}
                >
                  {/* ID — incident.incident_id */}
                  <td className="px-3 py-2.5 text-zinc-300 font-mono text-xs truncate max-w-[140px]">
                    {inc.incident_id}
                  </td>
                  {/* Time — incident.evidence.window_start */}
                  <td className="px-3 py-2.5 text-zinc-400 text-xs whitespace-nowrap">
                    {inc.evidence.window_start}
                  </td>
                  {/* Severity — incident.severity */}
                  <td className="px-3 py-2.5">
                    <SeverityBadge severity={inc.severity} />
                  </td>
                  {/* Type — incident.type */}
                  <td className="px-3 py-2.5 text-zinc-200">
                    {TYPE_LABELS[inc.type] || inc.type}
                  </td>
                  {/* Technique — incident.mitre_technique */}
                  <td className="px-3 py-2.5">
                    <span className="font-mono text-xs bg-zinc-700 text-zinc-300 px-1.5 py-0.5 rounded">
                      {inc.mitre_technique}
                    </span>
                  </td>
                  {/* User — incident.subject.username */}
                  <td className="px-3 py-2.5 text-zinc-300">
                    {inc.subject.username}
                  </td>
                  {/* Source IP — incident.subject.source_ip */}
                  <td className="px-3 py-2.5 text-zinc-300 font-mono text-xs">
                    {inc.subject.source_ip}
                  </td>
                  {/* Confidence — incident.confidence */}
                  <td className="px-3 py-2.5 text-zinc-400 text-xs">
                    {Number.isFinite(Number(inc.confidence)) ? (Number(inc.confidence) * 100).toFixed(0) : '0'}%
                  </td>
                  {/* Expand toggle */}
                  <td className="px-3 py-2.5 text-zinc-500">
                    {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </td>
                </tr>
                {isExpanded && <ExpandedRow incident={inc} colSpan={COL_SPAN} />}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
