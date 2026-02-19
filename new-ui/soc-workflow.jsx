import React, { useState, useEffect, useRef } from 'react';
import { Search, Filter, Download, CheckSquare, Square, ChevronRight, ExternalLink, Clock, User, Globe, Shield, Activity } from 'lucide-react';

const SecurityWorkflow = () => {
  const [selectedRun, setSelectedRun] = useState(null);
  const [selectedIncidents, setSelectedIncidents] = useState(new Set());
  const [expandedIncidentId, setExpandedIncidentId] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState({
    severity: [],
    technique: [],
    status: ['new'] // Default to unacknowledged
  });
  const [bulkActionMenu, setBulkActionMenu] = useState(false);
  const [viewDensity, setViewDensity] = useState('comfortable'); // compact, comfortable, spacious
  const searchInputRef = useRef(null);

  // Real SOC data structure
  const runs = [
    {
      id: 'a67f183c16',
      timestamp: '2025-12-21 06:01:00',
      events: 7,
      normalized: 7,
      incidents: 2,
      critical: 0,
      high: 0,
      medium: 0,
      low: 2,
      delta: { incidents: +1, critical: 0 }
    },
    {
      id: 'a6424ec160',
      timestamp: '2025-12-21 05:59:00',
      events: 6,
      normalized: 6,
      incidents: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      delta: { incidents: -1, critical: 0 }
    },
    {
      id: '9e36c36da3',
      timestamp: '2025-12-21 05:54:00',
      events: 6,
      normalized: 6,
      incidents: 2,
      critical: 0,
      high: 0,
      medium: 0,
      low: 2,
      delta: { incidents: 0, critical: 0 }
    }
  ];

  const incidents = [
    {
      id: 'INC-001',
      timestamp: '2025-12-21 06:00:50',
      severity: 'low',
      technique: 'T1110',
      type: 'Brute Force',
      user: 'alice',
      sourceIp: '203.0.113.10',
      destIp: '10.0.1.50',
      attempts: 6,
      threshold: 5,
      windowSeconds: 50,
      status: 'new', // new, acknowledged, investigating, false_positive, escalated
      assignee: null,
      tags: ['authentication', 'failed-login'],
      rawEvents: 6,
      firstSeen: '2025-12-21 06:00:02',
      lastSeen: '2025-12-21 06:00:50',
      relatedIncidents: [],
      playbookUrl: '/playbooks/brute-force-response',
      siemQuery: 'source_ip:203.0.113.10 AND event_type:auth_failure',
      events: [
        { time: '06:00:02', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:12', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:22', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:32', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:42', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:50', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' }
      ]
    },
    {
      id: 'INC-002',
      timestamp: '2025-12-21 06:00:48',
      severity: 'low',
      technique: 'T1110',
      type: 'Brute Force',
      user: 'alice',
      sourceIp: '203.0.113.10',
      destIp: '10.0.1.50',
      attempts: 5,
      threshold: 5,
      windowSeconds: 48,
      status: 'new',
      assignee: null,
      tags: ['authentication', 'failed-login'],
      rawEvents: 5,
      firstSeen: '2025-12-21 06:00:00',
      lastSeen: '2025-12-21 06:00:48',
      relatedIncidents: ['INC-001'],
      playbookUrl: '/playbooks/brute-force-response',
      siemQuery: 'source_ip:203.0.113.10 AND event_type:auth_failure',
      events: [
        { time: '06:00:00', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:12', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:24', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:36', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' },
        { time: '06:00:48', user: 'alice', result: 'AUTH_FAILED', reason: 'invalid_password' }
      ]
    }
  ];

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyPress = (e) => {
      // Don't trigger if typing in input
      if (e.target.tagName === 'INPUT') return;
      
      if (e.key === '/') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
      if (e.key === 'a' && e.ctrlKey) {
        e.preventDefault();
        handleSelectAll();
      }
      if (e.key === 'Escape') {
        setSelectedIncidents(new Set());
      }
      // Number keys 1-9 to select incidents
      if (e.key >= '1' && e.key <= '9') {
        const index = parseInt(e.key) - 1;
        if (filteredIncidents[index]) {
          toggleIncidentSelection(filteredIncidents[index].id);
        }
      }
    };
    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, []);

  // Auto-select newest run
  useEffect(() => {
    if (runs.length > 0 && !selectedRun) {
      setSelectedRun(runs[0].id);
    }
  }, []);

  const currentRun = runs.find(r => r.id === selectedRun);

  // Filter incidents
  const filteredIncidents = incidents.filter(inc => {
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      if (!inc.id.toLowerCase().includes(query) &&
          !inc.user.toLowerCase().includes(query) &&
          !inc.sourceIp.includes(query) &&
          !inc.type.toLowerCase().includes(query)) {
        return false;
      }
    }
    if (filters.severity.length && !filters.severity.includes(inc.severity)) return false;
    if (filters.technique.length && !filters.technique.includes(inc.technique)) return false;
    if (filters.status.length && !filters.status.includes(inc.status)) return false;
    return true;
  });

  const toggleIncidentSelection = (id) => {
    const newSelected = new Set(selectedIncidents);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedIncidents(newSelected);
  };

  const toggleIncidentExpansion = (id) => {
    setExpandedIncidentId(prev => (prev === id ? null : id));
  };

  const handleSelectAll = () => {
    if (selectedIncidents.size === filteredIncidents.length) {
      setSelectedIncidents(new Set());
    } else {
      setSelectedIncidents(new Set(filteredIncidents.map(i => i.id)));
    }
  };

  const handleBulkAction = (action) => {
    console.log(`Bulk action: ${action} on ${selectedIncidents.size} incidents`);
    // In production: API call to update incident statuses
    setBulkActionMenu(false);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      low: 'text-gray-600',
      medium: 'text-yellow-700',
      high: 'text-orange-700',
      critical: 'text-red-700'
    };
    return colors[severity];
  };

  const getSeverityBg = (severity) => {
    const colors = {
      low: 'bg-gray-100',
      medium: 'bg-yellow-100',
      high: 'bg-orange-100',
      critical: 'bg-red-100'
    };
    return colors[severity];
  };

  const getSeverityRail = (severity) => {
    const rails = {
      low: 'border-l-2 border-gray-300',
      medium: 'border-l-2 border-yellow-400',
      high: 'border-l-2 border-orange-400',
      critical: 'border-l-2 border-red-500'
    };
    return rails[severity] || 'border-l-2 border-gray-300';
  };

  const getStatusBadge = (status) => {
    const badges = {
      new: { label: 'NEW', class: 'bg-blue-100 text-blue-800' },
      acknowledged: { label: 'ACK', class: 'bg-gray-100 text-gray-700' },
      investigating: { label: 'INVESTIGATING', class: 'bg-purple-100 text-purple-800' },
      false_positive: { label: 'FALSE +', class: 'bg-green-100 text-green-800' },
      escalated: { label: 'ESCALATED', class: 'bg-red-100 text-red-800' }
    };
    return badges[status] || badges.new;
  };

  return (
    <div className="h-screen flex flex-col bg-gray-50">
      {/* Compact Header */}
      <header className="border-b border-gray-300 bg-white px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="pr-4 border-r border-gray-200">
            <h1 className="text-sm font-semibold">Security Workflow</h1>
            {currentRun && (
              <>
                <div className="text-xs text-gray-700 font-medium mt-0.5">
                  Run {currentRun.id} - {currentRun.timestamp}
                </div>
                <div className="mt-1 h-px w-24 bg-gray-200"></div>
              </>
            )}
          </div>
        </div>

        {/* Quick Stats */}
        <div className="flex items-center gap-6 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-gray-500">Total:</span>
            <span className="font-medium">{currentRun?.incidents || 0}</span>
            {currentRun?.delta.incidents !== 0 && (
              <span className={currentRun?.delta.incidents > 0 ? 'text-red-600' : 'text-green-600'}>
                {currentRun?.delta.incidents > 0 ? '↑' : '↓'}{Math.abs(currentRun?.delta.incidents)}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-red-600 rounded-full"></span>
            <span className="font-medium">{currentRun?.critical || 0}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-orange-600 rounded-full"></span>
            <span className="font-medium">{currentRun?.high || 0}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-yellow-600 rounded-full"></span>
            <span className="font-medium">{currentRun?.medium || 0}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-gray-600 rounded-full"></span>
            <span className="font-medium">{currentRun?.low || 0}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <select className="text-xs border border-gray-300 px-2 py-1 bg-white">
            <option value="a67f183c16">Run a67f183c16</option>
            <option value="a6424ec160">Run a6424ec160</option>
            <option value="9e36c36da3">Run 9e36c36da3</option>
          </select>
        </div>
      </header>

      {/* Toolbar */}
      <div className="border-b border-gray-300 bg-white px-4 py-2">
        <div className="flex items-center justify-between gap-4">
          {/* Left: Search & Filter */}
          <div className="flex items-center gap-2 flex-1">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                ref={searchInputRef}
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search incidents (press / to focus)"
                className="w-full pl-8 pr-3 py-1.5 text-xs border border-gray-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <div className="flex items-center gap-1 border border-gray-300 px-2 py-1">
              <Filter className="w-3 h-3 text-gray-500" />
              <select 
                className="text-xs bg-transparent border-none focus:outline-none"
                onChange={(e) => setFilters({...filters, severity: e.target.value ? [e.target.value] : []})}
              >
                <option value="">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div className="flex items-center gap-1 border border-gray-300 px-2 py-1">
              <select 
                className="text-xs bg-transparent border-none focus:outline-none"
                onChange={(e) => setFilters({...filters, status: e.target.value ? [e.target.value] : []})}
              >
                <option value="new">New Only</option>
                <option value="">All Status</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="investigating">Investigating</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>

            <select 
              value={viewDensity}
              onChange={(e) => setViewDensity(e.target.value)}
              className="text-xs border border-gray-300 px-2 py-1 bg-white"
            >
              <option value="compact">Compact</option>
              <option value="comfortable">Comfortable</option>
              <option value="spacious">Spacious</option>
            </select>
          </div>

          {/* Right: Actions */}
          <div className="flex items-center gap-2">
            {selectedIncidents.size > 0 && (
              <div className="flex items-center gap-2 text-xs">
                <span className="text-gray-600">{selectedIncidents.size} selected</span>
                <div className="relative">
                  <button
                    onClick={() => setBulkActionMenu(!bulkActionMenu)}
                    className="px-3 py-1.5 bg-blue-600 text-white text-xs hover:bg-blue-700"
                  >
                    Actions ▾
                  </button>
                  {bulkActionMenu && (
                    <div className="absolute right-0 top-full mt-1 bg-white border border-gray-300 shadow-lg z-10 min-w-[160px]">
                      <button
                        onClick={() => handleBulkAction('acknowledge')}
                        className="w-full px-3 py-2 text-left text-xs hover:bg-gray-100"
                      >
                        Acknowledge
                      </button>
                      <button
                        onClick={() => handleBulkAction('investigate')}
                        className="w-full px-3 py-2 text-left text-xs hover:bg-gray-100"
                      >
                        Mark Investigating
                      </button>
                      <button
                        onClick={() => handleBulkAction('false_positive')}
                        className="w-full px-3 py-2 text-left text-xs hover:bg-gray-100"
                      >
                        False Positive
                      </button>
                      <button
                        onClick={() => handleBulkAction('escalate')}
                        className="w-full px-3 py-2 text-left text-xs hover:bg-gray-100 border-t border-gray-200"
                      >
                        Escalate
                      </button>
                      <button
                        onClick={() => handleBulkAction('export')}
                        className="w-full px-3 py-2 text-left text-xs hover:bg-gray-100 border-t border-gray-200"
                      >
                        Export Selected
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}

            <button className="px-3 py-1.5 text-xs border border-gray-300 hover:bg-gray-50 flex items-center gap-1">
              <Download className="w-3 h-3" />
              Export
            </button>
          </div>
        </div>
      </div>

      {/* Main Content - Table View */}
      <div className="flex-1 overflow-auto p-3">
        <div className="border border-gray-200 bg-white rounded-md overflow-hidden">
          <table className="w-full text-xs">
          <thead className="bg-gray-100 sticky top-0 border-b border-gray-300">
            <tr>
              <th className="px-2 py-2 text-left w-8">
                <input
                  type="checkbox"
                  checked={selectedIncidents.size === filteredIncidents.length && filteredIncidents.length > 0}
                  onChange={handleSelectAll}
                  className="w-3 h-3"
                />
              </th>
              <th className="px-2 py-2 text-left font-medium">ID</th>
              <th className="px-2 py-2 text-left font-medium">Time</th>
              <th className="px-2 py-2 text-left font-medium">Severity</th>
              <th className="px-2 py-2 text-left font-medium">Type</th>
              <th className="px-2 py-2 text-left font-medium">Technique</th>
              <th className="px-2 py-2 text-left font-medium">User</th>
              <th className="px-2 py-2 text-left font-medium">Source IP</th>
              <th className="px-2 py-2 text-left font-medium">Details</th>
              <th className="px-2 py-2 text-left font-medium">Status</th>
              <th className="px-2 py-2 text-left font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredIncidents.map((incident, idx) => (
              <React.Fragment key={incident.id}>
                <tr 
                  className={`border-b border-gray-200 hover:bg-gray-50 cursor-pointer ${getSeverityRail(incident.severity)} ${
                    selectedIncidents.has(incident.id) ? 'bg-blue-50' : 'bg-white'
                  }`}
                  onClick={() => {
                    toggleIncidentSelection(incident.id);
                    toggleIncidentExpansion(incident.id);
                  }}
                >
                  <td className="px-2 py-2">
                    <input
                      type="checkbox"
                      checked={selectedIncidents.has(incident.id)}
                      onChange={() => {}}
                      onClick={(e) => e.stopPropagation()}
                      className="w-3 h-3"
                    />
                  </td>
                  <td className="px-2 py-2 font-mono text-blue-600">{incident.id}</td>
                  <td className="px-2 py-2 font-mono text-gray-600">{incident.timestamp}</td>
                  <td className="px-2 py-2">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 ${getSeverityBg(incident.severity)} ${getSeverityColor(incident.severity)} font-medium`}>
                      {incident.severity === 'critical' && '🔴'}
                      {incident.severity === 'high' && '🟠'}
                      {incident.severity === 'medium' && '🟡'}
                      {incident.severity === 'low' && '⚪'}
                      {incident.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-2 py-2 font-medium">{incident.type}</td>
                  <td className="px-2 py-2">
                    <span className="px-2 py-0.5 bg-gray-100 font-mono text-gray-700">
                      {incident.technique}
                    </span>
                  </td>
                  <td className="px-2 py-2 font-mono">{incident.user}</td>
                  <td className="px-2 py-2 font-mono text-gray-700">{incident.sourceIp}</td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-1 text-gray-600">
                      <span>{incident.attempts}/{incident.threshold} in {incident.windowSeconds}s</span>
                      <ChevronRight
                        className={`w-3 h-3 text-gray-400 transition-transform ${expandedIncidentId === incident.id ? 'rotate-90' : ''}`}
                      />
                    </div>
                  </td>
                  <td className="px-2 py-2">
                    <span className={`px-2 py-0.5 text-[10px] font-medium ${getStatusBadge(incident.status).class}`}>
                      {getStatusBadge(incident.status).label}
                    </span>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-1">
                      <button
                        className="p-1 hover:bg-gray-200 text-gray-600"
                        title="View in SIEM"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <ExternalLink className="w-3 h-3" />
                      </button>
                      <button
                        className="p-1 hover:bg-gray-200 text-gray-600"
                        title="Playbook"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Activity className="w-3 h-3" />
                      </button>
                    </div>
                  </td>
                </tr>
                {expandedIncidentId === incident.id && (
                  <tr className="bg-gray-50 border-b border-gray-200">
                    <td colSpan={11} className="px-3 py-3">
                      <div className="grid grid-cols-4 gap-3 text-xs text-gray-700">
                        <div>
                          <div className="text-[10px] uppercase tracking-wide text-gray-500">Window</div>
                          <div className="font-mono">{incident.windowSeconds}s</div>
                        </div>
                        <div>
                          <div className="text-[10px] uppercase tracking-wide text-gray-500">First Seen</div>
                          <div className="font-mono">{incident.firstSeen}</div>
                        </div>
                        <div>
                          <div className="text-[10px] uppercase tracking-wide text-gray-500">Last Seen</div>
                          <div className="font-mono">{incident.lastSeen}</div>
                        </div>
                        <div>
                          <div className="text-[10px] uppercase tracking-wide text-gray-500">Raw Events</div>
                          <div className="font-mono">{incident.rawEvents}</div>
                        </div>
                      </div>

                      <div className="mt-3 border border-gray-200 bg-white">
                        <div className="px-2 py-1 text-[10px] uppercase tracking-wide text-gray-500 border-b border-gray-200">
                          Event Evidence
                        </div>
                        <div className="divide-y divide-gray-100">
                          {incident.events.map((evt, evtIdx) => (
                            <div key={evtIdx} className="px-2 py-1.5 flex items-center gap-3 text-xs">
                              <span className="font-mono text-gray-600 w-16">{evt.time}</span>
                              <span className="font-mono text-gray-700 w-20">{evt.user}</span>
                              <span className="text-gray-700">{evt.result}</span>
                              <span className="text-gray-500">({evt.reason})</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>

          {filteredIncidents.length === 0 && (
            <div className="p-12 text-center text-gray-500 text-sm">
              No incidents match current filters
            </div>
          )}
        </div>
      </div>

      {/* Status Bar */}
      <div className="border-t border-gray-300 bg-gray-100 px-4 py-1.5 flex items-center justify-between text-xs text-gray-600">
        <div className="flex items-center gap-4">
          <span>{filteredIncidents.length} incidents</span>
          {selectedIncidents.size > 0 && <span>• {selectedIncidents.size} selected</span>}
        </div>
        <div className="flex items-center gap-3">
          <kbd className="px-1.5 py-0.5 bg-white border border-gray-300 font-mono text-[10px]">/</kbd>
          <span>Search</span>
          <kbd className="px-1.5 py-0.5 bg-white border border-gray-300 font-mono text-[10px]">Ctrl+A</kbd>
          <span>Select All</span>
          <kbd className="px-1.5 py-0.5 bg-white border border-gray-300 font-mono text-[10px]">1-9</kbd>
          <span>Quick Select</span>
          <kbd className="px-1.5 py-0.5 bg-white border border-gray-300 font-mono text-[10px]">Esc</kbd>
          <span>Clear</span>
        </div>
      </div>
    </div>
  );
};

export default SecurityWorkflow;
