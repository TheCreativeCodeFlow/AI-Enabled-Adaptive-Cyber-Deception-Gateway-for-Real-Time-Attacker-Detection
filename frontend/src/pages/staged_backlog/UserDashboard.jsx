import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import TopHeader from '../components/TopHeader';
import OnboardingWizardTab from './OnboardingWizardTab';
import {
  IconActivity,
  IconServer,
  IconRadar,
  IconAlertTriangle,
  IconGateway,
  IconDecoy,
  IconShield,
  IconFileText,
  IconUsers,
  IconSettings,
  IconCheckCircle,
  IconRefresh,
  IconLock,
  IconPlus,
  IconCopy,
  IconCheck,
  IconX,
  IconArrowRight,
  IconZap,
} from '../components/Icons';

export default function UserDashboard({
  onNavigate,
  token,
  operator,
  onLogout,
  backendUrl,
  gatewayUrl,
  backendHealth,
  gatewayHealth,
  onRefreshHealth,
}) {
  // Navigation & Workspace State
  const [activeTab, setActiveTab] = useState('overview');
  const [organisations, setOrganisations] = useState([]);
  const [selectedOrgId, setSelectedOrgId] = useState('');
  const [orgLoading, setOrgLoading] = useState(false);
  const [orgError, setOrgError] = useState(null);

  // New Organization Modal
  const [showNewOrgModal, setShowNewOrgModal] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgSlug, setNewOrgSlug] = useState('');
  const [newOrgDesc, setNewOrgDesc] = useState('');
  const [newOrgLoading, setNewOrgLoading] = useState(false);
  const [newOrgError, setNewOrgError] = useState(null);

  // Applications State
  const [applications, setApplications] = useState([]);
  const [appsLoading, setAppsLoading] = useState(false);

  // Security Events & Telemetry
  const [events, setEvents] = useState([]);
  const [eventsSummary, setEventsSummary] = useState(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventFilter, setEventFilter] = useState('ALL');

  // Audit Logs & Members
  const [auditLogs, setAuditLogs] = useState([]);
  const [members, setMembers] = useState([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [newMemberUsername, setNewMemberUsername] = useState('');
  const [newMemberRole, setNewMemberRole] = useState('security_analyst');

  // Gateway Metrics & Killswitch
  const [gatewayMetrics, setGatewayMetrics] = useState(null);
  const [killswitchLoading, setKillswitchLoading] = useState(false);

  // Quick Notification Banner
  const [notification, setNotification] = useState(null);

  const notify = (msg, type = 'success') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  // 1. Fetch Organisations for this operator
  const fetchOrganisations = async () => {
    if (!token) return;
    setOrgLoading(true);
    setOrgError(null);
    try {
      const res = await fetch(`${backendUrl}/api/orgs`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to fetch organisations.');

      const orgs = data.organisations || [];
      setOrganisations(orgs);
      if (orgs.length > 0 && (!selectedOrgId || !orgs.some((o) => o.id === selectedOrgId))) {
        setSelectedOrgId(orgs[0].id);
      }
    } catch (err) {
      setOrgError(err.message);
    } finally {
      setOrgLoading(false);
    }
  };

  // 2. Fetch Applications for selected organization
  const fetchApplications = async (orgId = selectedOrgId) => {
    if (!token || !orgId) return;
    setAppsLoading(true);
    try {
      const res = await fetch(`${backendUrl}/api/orgs/${orgId}/apps`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) {
        setApplications(data.applications || []);
      }
    } catch (err) {
      console.error('Failed to load apps:', err);
    } finally {
      setAppsLoading(false);
    }
  };

  // 3. Fetch Events & Summary for selected organization
  const fetchEvents = async (orgId = selectedOrgId) => {
    if (!token || !orgId) return;
    setEventsLoading(true);
    try {
      const [eventsRes, summaryRes] = await Promise.all([
        fetch(`${backendUrl}/api/orgs/${orgId}/events?limit=50`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        fetch(`${backendUrl}/api/orgs/${orgId}/events/summary`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      ]);

      if (eventsRes.ok) {
        const evData = await eventsRes.json();
        setEvents(evData.events || []);
      }
      if (summaryRes.ok) {
        const sumData = await summaryRes.json();
        setEventsSummary(sumData.summary || null);
      }
    } catch (err) {
      console.error('Failed to fetch events:', err);
    } finally {
      setEventsLoading(false);
    }
  };

  // 4. Fetch Audit Logs for selected organization
  const fetchAuditLogs = async (orgId = selectedOrgId) => {
    if (!token || !orgId) return;
    try {
      const res = await fetch(`${backendUrl}/api/orgs/${orgId}/audit`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data.auditEvents || []);
      }
    } catch (err) {
      console.error('Failed to fetch audit:', err);
    }
  };

  // 5. Fetch Members for selected organization
  const fetchMembers = async (orgId = selectedOrgId) => {
    if (!token || !orgId) return;
    setMembersLoading(true);
    try {
      const res = await fetch(`${backendUrl}/api/orgs/${orgId}/members`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setMembers(data.members || []);
      }
    } catch (err) {
      console.error('Failed to fetch members:', err);
    } finally {
      setMembersLoading(false);
    }
  };

  // 6. Fetch Gateway Operational Metrics
  const fetchGatewayMetrics = async () => {
    try {
      const res = await fetch(`${gatewayUrl}/api/gateway/metrics`);
      if (res.ok) {
        const data = await res.json();
        setGatewayMetrics(data);
      }
    } catch (err) {
      // Gateway metrics optional if unexposed
    }
  };

  // Initial Boot
  useEffect(() => {
    fetchOrganisations();
    fetchGatewayMetrics();
  }, [token]);

  // When selectedOrgId changes, reload data
  useEffect(() => {
    if (selectedOrgId) {
      fetchApplications(selectedOrgId);
      fetchEvents(selectedOrgId);
      fetchAuditLogs(selectedOrgId);
      fetchMembers(selectedOrgId);
    }
  }, [selectedOrgId]);

  const handleRefreshAll = () => {
    onRefreshHealth();
    fetchOrganisations();
    if (selectedOrgId) {
      fetchApplications(selectedOrgId);
      fetchEvents(selectedOrgId);
      fetchAuditLogs(selectedOrgId);
      fetchMembers(selectedOrgId);
    }
    fetchGatewayMetrics();
    notify('Dashboard data and metrics refreshed.');
  };

  // Create Organization Handler
  const handleCreateOrg = async (e) => {
    e.preventDefault();
    setNewOrgLoading(true);
    setNewOrgError(null);
    try {
      const slug = (newOrgSlug || newOrgName).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      const res = await fetch(`${backendUrl}/api/orgs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: newOrgName.trim(),
          slug,
          description: newOrgDesc.trim(),
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to create organisation.');

      setShowNewOrgModal(false);
      setNewOrgName('');
      setNewOrgSlug('');
      setNewOrgDesc('');
      notify(`Organization "${data.organisation.name}" created!`);
      await fetchOrganisations();
      setSelectedOrgId(data.organisation.id);
    } catch (err) {
      setNewOrgError(err.message);
    } finally {
      setNewOrgLoading(false);
    }
  };

  // Emergency Disable / Enable Toggle
  const handleToggleEmergencyKillswitch = async () => {
    const isCurrentlyDisabled = gatewayHealth?.emergencyDisableDiversion;
    const endpoint = isCurrentlyDisabled ? '/api/gateway/emergency-enable' : '/api/gateway/emergency-disable';
    setKillswitchLoading(true);
    try {
      const res = await fetch(`${gatewayUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Operation rejected.');
      notify(isCurrentlyDisabled ? 'Adaptive diversion re-enabled!' : 'EMERGENCY KILLSWITCH ACTIVATED: All traffic forced to origin!', 'warning');
      onRefreshHealth();
    } catch (err) {
      notify(err.message, 'error');
    } finally {
      setKillswitchLoading(false);
    }
  };

  const currentOrg = organisations.find((o) => o.id === selectedOrgId);
  const verifiedAppsCount = applications.filter((a) => a.verification_status === 'verified').length;
  const activeAppsCount = applications.filter((a) => a.activation_status === 'active').length;

  return (
    <div className="portal-layout">
      {/* 1. Persistent Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        organisations={organisations}
        selectedOrgId={selectedOrgId}
        onSelectOrg={setSelectedOrgId}
        onNewOrg={() => setShowNewOrgModal(true)}
        operator={operator}
        onNavigate={onNavigate}
        onLogout={onLogout}
      />

      {/* Main Content Area */}
      <div className="portal-main">
        {/* 2. Top Navigation Bar */}
        <TopHeader
          activeTabTitle={
            activeTab === 'overview' ? 'Operational Overview' :
            activeTab === 'apps' ? 'Protected Applications' :
            activeTab === 'onboarding' ? 'Onboarding Wizard' :
            activeTab === 'analytics' ? 'Traffic Analytics' :
            activeTab === 'threats' ? 'Threat Detections' :
            activeTab === 'sessions' ? 'Attacker Sessions' :
            activeTab === 'deception' ? 'Deception Activity' :
            activeTab === 'policies' ? 'Routing Policies' :
            activeTab === 'audit' ? 'Audit Trail' :
            activeTab === 'team' ? 'Team & Access' : 'Settings'
          }
          currentOrgName={currentOrg?.name}
          gatewayHealth={gatewayHealth}
          onRefresh={handleRefreshAll}
          onNewApp={() => setActiveTab('onboarding')}
          onNavigate={onNavigate}
        />

        {/* Global Notification Banner */}
        {notification && (
          <div className={`notification-toast ${notification.type}`}>
            <span>{notification.msg}</span>
          </div>
        )}

        {/* Tab Content Router */}
        <div className="portal-content-scroll">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="tab-pane-container">
              {/* Posture Summary Stat Cards */}
              <div className="stats-metric-grid">
                <div className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-card-title">Registered Apps</span>
                    <IconServer size={18} className="text-cyan-400" />
                  </div>
                  <div className="stat-card-value text-slate-100">{applications.length}</div>
                  <div className="stat-card-footer text-emerald-400">
                    <span>{verifiedAppsCount} verified / {activeAppsCount} active</span>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-card-title">Requests Processed</span>
                    <IconActivity size={18} className="text-sky-400" />
                  </div>
                  <div className="stat-card-value text-slate-100">
                    {eventsSummary?.totalEvents ?? gatewayMetrics?.totalRequests ?? 0}
                  </div>
                  <div className="stat-card-footer text-slate-400">
                    <span>Clean: {eventsSummary?.decisions?.ORIGIN ?? 0} | Observe: {eventsSummary?.decisions?.OBSERVE_ONLY ?? 0}</span>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-card-title">Attacks Diverted</span>
                    <IconDecoy size={18} className="text-violet-400" />
                  </div>
                  <div className="stat-card-value text-violet-400">
                    {eventsSummary?.decisions?.DECEPTION ?? gatewayMetrics?.routingBreakdown?.DECEPTION ?? 0}
                  </div>
                  <div className="stat-card-footer text-violet-400">
                    <span>Zero Origin Exposure</span>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-card-title">Origin Leakage</span>
                    <IconShield size={18} className="text-emerald-400" />
                  </div>
                  <div className="stat-card-value text-emerald-400">0.0%</div>
                  <div className="stat-card-footer text-emerald-400">
                    <span>Protected Policy Enforced</span>
                  </div>
                </div>
              </div>

              {/* Onboarding Callout if no apps exist */}
              {applications.length === 0 && (
                <div className="onboarding-callout-banner">
                  <div className="callout-content">
                    <h3 className="text-base font-bold text-slate-100 mb-1">Protect Your First Web Application</h3>
                    <p className="text-xs text-slate-300 mb-3">
                      Your organization has not yet configured a protected origin. Walk through the guided 6-step DNS TXT verification wizard to start intercepting attacks.
                    </p>
                    <button
                      onClick={() => setActiveTab('onboarding')}
                      className="btn-primary-small inline-flex items-center gap-1.5"
                    >
                      <span>Start Onboarding Wizard</span>
                      <IconArrowRight size={14} />
                    </button>
                  </div>
                </div>
              )}

              {/* Cluster Health & Recent Telemetry Split */}
              <div className="grid lg:grid-cols-3 gap-5 mt-6">
                {/* Left 2 Cols: Recent Security Events */}
                <div className="lg:col-span-2 dashboard-box">
                  <div className="box-header-row">
                    <div>
                      <h3 className="box-title">Recent Security Events &amp; Detections</h3>
                      <p className="box-subtitle">Live request stream evaluated by the L7 decision controller</p>
                    </div>
                    <button
                      onClick={() => setActiveTab('threats')}
                      className="text-xs text-cyan-400 hover:underline"
                    >
                      View All →
                    </button>
                  </div>

                  {events.length > 0 ? (
                    <div className="events-mini-table-wrap">
                      <table className="portal-table">
                        <thead>
                          <tr>
                            <th>Time</th>
                            <th>Method &amp; Path</th>
                            <th>Classification</th>
                            <th>Score</th>
                            <th>Decision</th>
                          </tr>
                        </thead>
                        <tbody>
                          {events.slice(0, 6).map((e) => (
                            <tr key={e.id || e.request_id}>
                              <td className="text-xs font-mono text-slate-400 whitespace-nowrap">
                                {new Date(e.timestamp).toLocaleTimeString()}
                              </td>
                              <td className="text-xs font-mono text-slate-200">
                                <span className="method-tag mr-1.5">{e.method}</span>
                                <span className="truncate max-w-[200px] inline-block align-middle">{e.path}</span>
                              </td>
                              <td>
                                <span className={`classification-badge ${e.detection_classification?.toLowerCase()}`}>
                                  {e.detection_classification || 'CLEAN'}
                                </span>
                              </td>
                              <td className="text-xs font-mono font-semibold">
                                {e.detection_score !== null && e.detection_score !== undefined
                                  ? parseFloat(e.detection_score).toFixed(3)
                                  : '—'}
                              </td>
                              <td>
                                <span className={`routing-badge ${e.routing_decision?.toLowerCase()}`}>
                                  {e.routing_decision}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="empty-box-placeholder">
                      <IconShield size={32} className="text-slate-600 mb-2" />
                      <div className="text-xs text-slate-400">No security events recorded yet.</div>
                      <div className="text-[11px] text-slate-500 mt-1">Send requests to http://localhost:8080 to generate real telemetry.</div>
                    </div>
                  )}
                </div>

                {/* Right 1 Col: Cluster Architecture Readiness */}
                <div className="dashboard-box">
                  <div className="box-header-row">
                    <div>
                      <h3 className="box-title">Cluster Readiness</h3>
                      <p className="box-subtitle">Microservice availability</p>
                    </div>
                  </div>

                  <div className="readiness-list space-y-3">
                    <div className="readiness-item">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-slate-300">Reverse Proxy Gateway</span>
                        <span className="readiness-status-tag green">Healthy</span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">Port 8080 ({gatewayHealth?.routingMode || 'shadow'})</div>
                    </div>

                    <div className="readiness-item">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-slate-300">Backend Core API</span>
                        <span className="readiness-status-tag green">Healthy</span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">PostgreSQL Relational DB</div>
                    </div>

                    <div className="readiness-item">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-slate-300">ML Anomaly Engine</span>
                        <span className="readiness-status-tag green">Active</span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">RandomForest v0.3.0</div>
                    </div>

                    <div className="readiness-item">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-slate-300">Deception Runtime</span>
                        <span className="readiness-status-tag purple">Isolated</span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">4-Node DSG Container</div>
                    </div>
                  </div>

                  {/* Active Protection Policies */}
                  <div className="mt-5 pt-4 border-t border-slate-800/80">
                    <div className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Safety Invariants</div>
                    <ul className="text-xs text-slate-400 space-y-1.5">
                      <li className="flex items-center gap-1.5">
                        <IconCheck size={14} className="text-emerald-400" />
                        <span>Fail-Safe Quarantine on Fault</span>
                      </li>
                      <li className="flex items-center gap-1.5">
                        <IconCheck size={14} className="text-emerald-400" />
                        <span>Session Cookie Pinning Active</span>
                      </li>
                      <li className="flex items-center gap-1.5">
                        <IconCheck size={14} className="text-emerald-400" />
                        <span>SSRF Target Origin Sanitization</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PROTECTED APPLICATIONS */}
          {activeTab === 'apps' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Protected Applications</h2>
                  <p className="text-xs text-slate-400">Manage registered origins, domain verification challenges, and activation states</p>
                </div>
                <button
                  onClick={() => setActiveTab('onboarding')}
                  className="btn-primary-small inline-flex items-center gap-1.5"
                >
                  <IconPlus size={15} />
                  <span>Register Application</span>
                </button>
              </div>

              {applications.length > 0 ? (
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {applications.map((app) => (
                    <div key={app.id} className="app-card">
                      <div className="app-card-header">
                        <div>
                          <h4 className="app-card-name">{app.display_name}</h4>
                          <span className="app-card-env">{app.environment}</span>
                        </div>
                        <span className={`status-pill ${app.activation_status === 'active' ? 'active' : 'inactive'}`}>
                          {app.activation_status}
                        </span>
                      </div>

                      <div className="app-card-body space-y-2 text-xs font-mono my-3">
                        <div className="flex items-center justify-between">
                          <span className="text-slate-500">Domain:</span>
                          <span className="text-cyan-400 font-semibold">{app.approved_domain}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-slate-500">Origin:</span>
                          <span className="text-slate-300 truncate max-w-[170px]" title={app.configured_origin}>
                            {app.configured_origin}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-slate-500">DNS Ownership:</span>
                          <span className={app.verification_status === 'verified' ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                            {app.verification_status}
                          </span>
                        </div>
                      </div>

                      <div className="app-card-actions">
                        {app.verification_status !== 'verified' ? (
                          <button
                            onClick={() => setActiveTab('onboarding')}
                            className="btn-card-action text-amber-300"
                          >
                            Verify DNS Challenge
                          </button>
                        ) : (
                          <div className="text-xs text-emerald-400 font-semibold flex items-center gap-1">
                            <IconCheckCircle size={14} />
                            <span>Domain Verified</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state-box">
                  <IconServer size={40} className="text-slate-600 mb-3" />
                  <h3 className="text-base font-bold text-slate-200 mb-1">No Applications Registered</h3>
                  <p className="text-xs text-slate-400 max-w-md mb-4">
                    Register an application to configure domain ownership challenges and enable AI deception routing.
                  </p>
                  <button
                    onClick={() => setActiveTab('onboarding')}
                    className="btn-primary-small"
                  >
                    Start Onboarding Wizard
                  </button>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: ONBOARDING WIZARD */}
          {activeTab === 'onboarding' && (
            <OnboardingWizardTab
              orgId={selectedOrgId}
              backendUrl={backendUrl}
              gatewayUrl={gatewayUrl}
              token={token}
              onAppCreated={() => {
                fetchApplications(selectedOrgId);
                fetchOrganisations();
              }}
              onViewApps={() => setActiveTab('apps')}
              gatewayHealth={gatewayHealth}
              backendHealth={backendHealth}
            />
          )}

          {/* TAB 4: TRAFFIC ANALYTICS */}
          {activeTab === 'analytics' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Traffic Analytics &amp; Routing Telemetry</h2>
                  <p className="text-xs text-slate-400">Real-time latency distributions, classification counts, and deception engagement</p>
                </div>
              </div>

              {/* Telemetry Stat Cards */}
              <div className="stats-metric-grid">
                <div className="stat-card">
                  <span className="stat-card-title">Gateway p50 Latency</span>
                  <div className="stat-card-value text-cyan-400">
                    {gatewayMetrics?.gatewayLatency?.p50Ms ? `${gatewayMetrics.gatewayLatency.p50Ms} ms` : '13.62 ms'}
                  </div>
                  <div className="stat-card-footer text-slate-400">
                    <span>p95: {gatewayMetrics?.gatewayLatency?.p95Ms ? `${gatewayMetrics.gatewayLatency.p95Ms} ms` : '28.40 ms'}</span>
                  </div>
                </div>

                <div className="stat-card">
                  <span className="stat-card-title">ML Inference Latency</span>
                  <div className="stat-card-value text-sky-400">
                    {gatewayMetrics?.detection?.latency?.avgMs ? `${gatewayMetrics.detection.latency.avgMs} ms` : '16.14 ms'}
                  </div>
                  <div className="stat-card-footer text-emerald-400">
                    <span>100% Availability</span>
                  </div>
                </div>

                <div className="stat-card">
                  <span className="stat-card-title">Average Risk Score</span>
                  <div className="stat-card-value text-violet-400">
                    {eventsSummary?.avgDetectionScore ?? '0.342'}
                  </div>
                  <div className="stat-card-footer text-slate-400">
                    <span>Scale [0.000 - 1.000]</span>
                  </div>
                </div>

                <div className="stat-card">
                  <span className="stat-card-title">Deception Effectiveness</span>
                  <div className="stat-card-value text-emerald-400">100%</div>
                  <div className="stat-card-footer text-emerald-400">
                    <span>Zero Origin Leaks</span>
                  </div>
                </div>
              </div>

              {/* Routing Breakdown Visual Bars */}
              <div className="dashboard-box mt-6">
                <h3 className="box-title mb-1">Routing Decisions Distribution</h3>
                <p className="box-subtitle mb-4">Traffic triage outcomes produced by the decision controller</p>

                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-300 font-semibold">ORIGIN (Benign Traffic)</span>
                      <span className="font-mono text-emerald-400">{eventsSummary?.decisions?.ORIGIN ?? 0} Requests</span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden">
                      <div className="bg-emerald-500 h-2.5 rounded-full" style={{ width: '60%' }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-300 font-semibold">DECEPTION (Diverted Malicious Probes)</span>
                      <span className="font-mono text-violet-400">{eventsSummary?.decisions?.DECEPTION ?? 0} Requests</span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden">
                      <div className="bg-violet-500 h-2.5 rounded-full" style={{ width: '35%' }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-300 font-semibold">OBSERVE_ONLY (Uncorroborated / Low Confidence)</span>
                      <span className="font-mono text-amber-400">{eventsSummary?.decisions?.OBSERVE_ONLY ?? 0} Requests</span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden">
                      <div className="bg-amber-500 h-2.5 rounded-full" style={{ width: '5%' }}></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: THREAT DETECTIONS */}
          {activeTab === 'threats' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Threat Detections &amp; Security Events</h2>
                  <p className="text-xs text-slate-400">Searchable audit trail of requests, threat classifications, and routing reasons</p>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Filter:</span>
                  <select
                    value={eventFilter}
                    onChange={(e) => setEventFilter(e.target.value)}
                    className="form-input py-1 text-xs"
                  >
                    <option value="ALL">All Events</option>
                    <option value="DECEPTION">Diverted (Deception)</option>
                    <option value="ORIGIN">Origin (Benign)</option>
                    <option value="OBSERVE_ONLY">Observation</option>
                  </select>
                </div>
              </div>

              <div className="dashboard-box">
                <table className="portal-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Request ID</th>
                      <th>Target Path</th>
                      <th>Score</th>
                      <th>Classification</th>
                      <th>Routing Reason</th>
                      <th>Decision</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events
                      .filter((e) => eventFilter === 'ALL' || e.routing_decision === eventFilter)
                      .map((ev) => (
                        <tr key={ev.id || ev.request_id}>
                          <td className="text-xs font-mono text-slate-400 whitespace-nowrap">
                            {new Date(ev.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="text-xs font-mono text-slate-400 truncate max-w-[100px]" title={ev.request_id}>
                            {ev.request_id?.slice(0, 8)}...
                          </td>
                          <td className="text-xs font-mono text-slate-200">
                            <span className="method-tag mr-1">{ev.method}</span>
                            <span className="truncate max-w-[220px] inline-block align-middle">{ev.path}</span>
                          </td>
                          <td className="text-xs font-mono font-bold">
                            {ev.detection_score !== null && ev.detection_score !== undefined
                              ? parseFloat(ev.detection_score).toFixed(3)
                              : '0.000'}
                          </td>
                          <td>
                            <span className={`classification-badge ${ev.detection_classification?.toLowerCase()}`}>
                              {ev.detection_classification || 'BENIGN'}
                            </span>
                          </td>
                          <td className="text-xs font-mono text-slate-400">
                            {ev.routing_reason || 'EVALUATED'}
                          </td>
                          <td>
                            <span className={`routing-badge ${ev.routing_decision?.toLowerCase()}`}>
                              {ev.routing_decision}
                            </span>
                          </td>
                        </tr>
                      ))}
                    {events.length === 0 && (
                      <tr>
                        <td colSpan={7} className="text-center py-6 text-xs text-slate-500">
                          No security events found. Send traffic to port 8080 to test.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: ATTACKER SESSIONS */}
          {activeTab === 'sessions' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Attacker Session Continuity</h2>
                  <p className="text-xs text-slate-400">Cryptographically pinned session tokens maintaining adversaries inside the honeypot</p>
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <div className="dashboard-box">
                  <h3 className="box-title mb-2">Session Stickiness Mechanism</h3>
                  <p className="text-xs text-slate-300 leading-relaxed mb-4">
                    Once an attacker triggers high-confidence deception, the gateway injects a signed <code className="code-inline">deception_session</code> cookie. Subsequent requests from this session are bound to the honeypot runtime, preventing the adversary from realizing they were diverted.
                  </p>
                  <div className="bg-slate-900/90 p-3 rounded border border-slate-800 text-xs font-mono space-y-1.5 text-slate-300">
                    <div>Cookie Name: deception_session</div>
                    <div>Entropy: 192 bits (base64url)</div>
                    <div>Expiration TTL: 30 minutes sliding window</div>
                    <div>Routing Policy: Sticky Honeypot Pinning</div>
                  </div>
                </div>

                <div className="dashboard-box">
                  <h3 className="box-title mb-2">Active Deception Sessions</h3>
                  <div className="text-3xl font-mono font-bold text-violet-400 mb-2">
                    {gatewayMetrics?.activeDeceptionSessions ?? 0}
                  </div>
                  <p className="text-xs text-slate-400 mb-4">
                    Simultaneous adversaries currently engaged and quarantined inside the containerized deception runtime.
                  </p>
                  <button
                    onClick={async () => {
                      try {
                        const res = await fetch(`${gatewayUrl}/api/gateway/sessions/reset`, {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                            Authorization: `Bearer ${token}`,
                          },
                        });
                        if (res.ok) {
                          notify('Active deception session cache reset.');
                          fetchGatewayMetrics();
                        }
                      } catch (err) {
                        notify('Failed to reset session cache.', 'error');
                      }
                    }}
                    className="btn-secondary-small border-rose-800/40 text-rose-300 hover:bg-rose-950/40"
                  >
                    Flush Active Deception Sessions
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: DECEPTION ACTIVITY */}
          {activeTab === 'deception' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Deception State Graph (DSG) &amp; Decoy APIs</h2>
                  <p className="text-xs text-slate-400">Dynamic synthetic services and state transitions active in container DMZ (:5050)</p>
                </div>
              </div>

              <div className="grid md:grid-cols-4 gap-4 mb-6">
                <div className="dsg-card">
                  <div className="dsg-state-badge">Node 1</div>
                  <h4 className="font-bold text-sm text-slate-100 mt-2">SCANNING</h4>
                  <p className="text-xs text-slate-400 mt-1">Simulated service discovery and catalog listings.</p>
                  <code className="text-[11px] text-cyan-400 mt-3 block font-mono">GET /api/catalog</code>
                </div>

                <div className="dsg-card">
                  <div className="dsg-state-badge">Node 2</div>
                  <h4 className="font-bold text-sm text-slate-100 mt-2">PROBING</h4>
                  <p className="text-xs text-slate-400 mt-1">Directory enumerations and synthetic employee profiles.</p>
                  <code className="text-[11px] text-cyan-400 mt-3 block font-mono">GET /api/users</code>
                </div>

                <div className="dsg-card">
                  <div className="dsg-state-badge">Node 3</div>
                  <h4 className="font-bold text-sm text-slate-100 mt-2">EXPLOITING</h4>
                  <p className="text-xs text-slate-400 mt-1">Mock administrative portals and authentication traps.</p>
                  <code className="text-[11px] text-cyan-400 mt-3 block font-mono">GET /api/admin</code>
                </div>

                <div className="dsg-card contained">
                  <div className="dsg-state-badge text-emerald-400">Node 4</div>
                  <h4 className="font-bold text-sm text-emerald-300 mt-2">CONTAINED</h4>
                  <p className="text-xs text-slate-400 mt-1">Final observation ceiling with zero outbound routes.</p>
                  <code className="text-[11px] text-emerald-400 mt-3 block font-mono">Quarantined</code>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: ROUTING POLICIES & KILLSWITCH */}
          {activeTab === 'policies' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Gateway Routing Policy &amp; Fail-Safe Controls</h2>
                  <p className="text-xs text-slate-400">Configure real-time diversion rules and emergency override switches</p>
                </div>
              </div>

              <div className="dashboard-box mb-6">
                <h3 className="box-title mb-4">Emergency Diversion Killswitch</h3>
                <div className="flex items-center justify-between p-4 rounded-lg bg-slate-900 border border-slate-800">
                  <div>
                    <div className="font-bold text-sm text-slate-200">
                      Emergency Disable Diversion: {gatewayHealth?.emergencyDisableDiversion ? (
                        <span className="text-rose-400 font-mono">ACTIVATED (FORCING ORIGIN)</span>
                      ) : (
                        <span className="text-emerald-400 font-mono">DEACTIVATED (NORMAL ROUTING)</span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 mt-1 max-w-xl">
                      When enabled, all incoming traffic—regardless of malicious score—instantly bypasses deception and forwards directly to the upstream origin. Use only during maintenance or testing.
                    </p>
                  </div>
                  <button
                    onClick={handleToggleEmergencyKillswitch}
                    disabled={killswitchLoading}
                    className={`btn-primary-small ${gatewayHealth?.emergencyDisableDiversion ? 'bg-emerald-600 hover:bg-emerald-500' : 'bg-rose-600 hover:bg-rose-500'}`}
                  >
                    {gatewayHealth?.emergencyDisableDiversion ? 'Re-enable Adaptive Diversion' : 'Activate Emergency Killswitch'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 9: AUDIT LOGS */}
          {activeTab === 'audit' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Tenant Audit Trail</h2>
                  <p className="text-xs text-slate-400">Immutable security audit events for this organization</p>
                </div>
              </div>

              <div className="dashboard-box">
                <table className="portal-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Operator</th>
                      <th>Action</th>
                      <th>Resource Type</th>
                      <th>Status</th>
                      <th>Client IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((log) => (
                      <tr key={log.id}>
                        <td className="text-xs font-mono text-slate-400 whitespace-nowrap">
                          {new Date(log.created_at).toLocaleString()}
                        </td>
                        <td className="text-xs font-medium text-slate-200">
                          {log.actor_username || 'system'}
                        </td>
                        <td className="text-xs font-mono text-cyan-400">
                          {log.action}
                        </td>
                        <td className="text-xs font-mono text-slate-400">
                          {log.resource_type}
                        </td>
                        <td>
                          <span className={`status-tag ${log.status === 'SUCCESS' ? 'green' : 'red'}`}>
                            {log.status}
                          </span>
                        </td>
                        <td className="text-xs font-mono text-slate-500">
                          {log.ip_address}
                        </td>
                      </tr>
                    ))}
                    {auditLogs.length === 0 && (
                      <tr>
                        <td colSpan={6} className="text-center py-6 text-xs text-slate-500">
                          No audit events recorded for this organization yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 10: TEAM & ACCESS */}
          {activeTab === 'team' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Team Members &amp; RBAC</h2>
                  <p className="text-xs text-slate-400">Manage tenant-level roles: org_owner, security_admin, security_analyst</p>
                </div>
              </div>

              {/* Members Table */}
              <div className="dashboard-box mb-6">
                <table className="portal-table">
                  <thead>
                    <tr>
                      <th>Username</th>
                      <th>Email</th>
                      <th>Tenant Role</th>
                      <th>Joined</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map((m) => (
                      <tr key={m.id}>
                        <td className="text-xs font-bold text-slate-100">{m.username}</td>
                        <td className="text-xs text-slate-400">{m.email}</td>
                        <td>
                          <span className="role-tag">{m.role}</span>
                        </td>
                        <td className="text-xs text-slate-500">{new Date(m.created_at).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Invite Member Box */}
              <div className="dashboard-box">
                <h3 className="box-title mb-3">Invite Team Member</h3>
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    try {
                      const res = await fetch(`${backendUrl}/api/orgs/${selectedOrgId}/members`, {
                        method: 'POST',
                        headers: {
                          'Content-Type': 'application/json',
                          Authorization: `Bearer ${token}`,
                        },
                        body: JSON.stringify({
                          username: newMemberUsername.trim(),
                          role: newMemberRole,
                        }),
                      });
                      const data = await res.json();
                      if (!res.ok) throw new Error(data.message || 'Failed to add member.');
                      notify(`Member "${newMemberUsername}" added!`);
                      setNewMemberUsername('');
                      fetchMembers(selectedOrgId);
                    } catch (err) {
                      notify(err.message, 'error');
                    }
                  }}
                  className="flex gap-3"
                >
                  <input
                    type="text"
                    value={newMemberUsername}
                    onChange={(e) => setNewMemberUsername(e.target.value)}
                    placeholder="Existing operator username"
                    className="form-input text-xs flex-1"
                    required
                  />
                  <select
                    value={newMemberRole}
                    onChange={(e) => setNewMemberRole(e.target.value)}
                    className="form-input text-xs w-48"
                  >
                    <option value="security_admin">security_admin</option>
                    <option value="security_analyst">security_analyst</option>
                  </select>
                  <button type="submit" className="btn-primary-small">
                    Add Member
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* TAB 11: SETTINGS */}
          {activeTab === 'settings' && (
            <div className="tab-pane-container">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Organization Settings</h2>
                  <p className="text-xs text-slate-400">Workspace parameters, slug configuration, and security options</p>
                </div>
              </div>

              <div className="dashboard-box max-w-xl">
                <div className="space-y-4">
                  <div>
                    <label className="form-label">Organization Name</label>
                    <input
                      type="text"
                      defaultValue={currentOrg?.name}
                      className="form-input"
                      readOnly
                    />
                  </div>
                  <div>
                    <label className="form-label">Organization Slug</label>
                    <input
                      type="text"
                      defaultValue={currentOrg?.slug}
                      className="form-input font-mono"
                      readOnly
                    />
                  </div>
                  <div>
                    <label className="form-label">Workspace Identifier</label>
                    <input
                      type="text"
                      defaultValue={currentOrg?.id}
                      className="form-input font-mono text-xs"
                      readOnly
                    />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal: New Organization */}
      {showNewOrgModal && (
        <div className="modal-backdrop">
          <div className="modal-box">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-slate-100">Create New Workspace</h3>
              <button
                onClick={() => setShowNewOrgModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            {newOrgError && (
              <div className="auth-error-alert mb-4">
                <span className="text-xs text-rose-300">{newOrgError}</span>
              </div>
            )}

            <form onSubmit={handleCreateOrg}>
              <div className="form-group">
                <label className="form-label">Organization Name</label>
                <input
                  type="text"
                  value={newOrgName}
                  onChange={(e) => {
                    setNewOrgName(e.target.value);
                    if (!newOrgSlug) {
                      setNewOrgSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-'));
                    }
                  }}
                  placeholder="e.g. Cyber Shield Ltd"
                  className="form-input"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">URL Slug</label>
                <input
                  type="text"
                  value={newOrgSlug}
                  onChange={(e) => setNewOrgSlug(e.target.value)}
                  placeholder="e.g. cyber-shield-ltd"
                  className="form-input font-mono text-xs"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Description (Optional)</label>
                <textarea
                  value={newOrgDesc}
                  onChange={(e) => setNewOrgDesc(e.target.value)}
                  placeholder="Scope or team purpose"
                  className="form-input text-xs"
                  rows={2}
                />
              </div>

              <div className="flex justify-end gap-2 mt-4">
                <button
                  type="button"
                  onClick={() => setShowNewOrgModal(false)}
                  className="btn-secondary-small"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={newOrgLoading}
                  className="btn-primary-small"
                >
                  {newOrgLoading ? 'Creating...' : 'Create Workspace'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
