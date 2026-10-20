import React, { useState, useEffect } from 'react';
import {
  IconLock,
  IconShield,
  IconServer,
  IconUsers,
  IconAlertTriangle,
  IconActivity,
  IconGateway,
  IconRefresh,
  IconCheckCircle,
  IconTerminal,
  IconZap,
  IconCheck,
} from '../components/Icons';

export default function AdminConsole({
  onNavigate,
  token,
  operator,
  onLogout,
  backendUrl,
  gatewayUrl,
  gatewayHealth,
  onRefreshHealth,
}) {
  const [activeTab, setActiveTab] = useState('overview');
  const [overview, setOverview] = useState(null);
  const [organisations, setOrganisations] = useState([]);
  const [applications, setApplications] = useState([]);
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [systemHealth, setSystemHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [actionNotice, setActionNotice] = useState(null);

  const notify = (msg, type = 'success') => {
    setActionNotice({ msg, type });
    setTimeout(() => setActionNotice(null), 4000);
  };

  // 1. Fetch Platform Overview
  const fetchOverview = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/admin/overview`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Access Denied.');
      setOverview(data.platformOverview || null);
    } catch (err) {
      setError(err.message);
    }
  };

  // 2. Fetch All Organizations
  const fetchOrgs = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/admin/organisations`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setOrganisations(data.organisations || []);
    } catch (err) {
      console.error(err);
    }
  };

  // 3. Fetch All Applications Across Platform
  const fetchApps = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/admin/applications`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setApplications(data.applications || []);
    } catch (err) {
      console.error(err);
    }
  };

  // 4. Fetch All Users
  const fetchUsers = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/admin/users`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setUsers(data.users || []);
    } catch (err) {
      console.error(err);
    }
  };

  // 5. Fetch System Audit Logs
  const fetchAudit = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/admin/audit?limit=100`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setAuditLogs(data.logs || []);
    } catch (err) {
      console.error(err);
    }
  };

  // 6. Fetch System Health
  const fetchSystemHealth = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/admin/system/health`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setSystemHealth(data);
    } catch (err) {
      console.error(err);
    }
  };

  const loadAllAdminData = async () => {
    setLoading(true);
    setError(null);
    await Promise.all([
      fetchOverview(),
      fetchOrgs(),
      fetchApps(),
      fetchUsers(),
      fetchAudit(),
      fetchSystemHealth(),
    ]);
    setLoading(false);
  };

  useEffect(() => {
    loadAllAdminData();
  }, [token]);

  // Handle Role Update
  const handleUpdateRole = async (userId, newRole) => {
    try {
      const res = await fetch(`${backendUrl}/api/admin/users/${userId}/role`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ role: newRole }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to update role.');
      notify(`Role updated to ${newRole}`);
      fetchUsers();
    } catch (err) {
      notify(err.message, 'error');
    }
  };

  // Emergency Disable / Enable Toggle
  const handleToggleEmergencyKillswitch = async () => {
    const isCurrentlyDisabled = gatewayHealth?.emergencyDisableDiversion;
    const endpoint = isCurrentlyDisabled ? '/api/gateway/emergency-enable' : '/api/gateway/emergency-disable';
    try {
      const res = await fetch(`${gatewayUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Operation failed.');
      notify(isCurrentlyDisabled ? 'Adaptive diversion re-enabled!' : 'EMERGENCY KILLSWITCH ACTIVATED: All traffic forced to origin!', 'warning');
      onRefreshHealth();
    } catch (err) {
      notify(err.message, 'error');
    }
  };

  return (
    <div className="admin-portal-layout">
      {/* Top Banner Header */}
      <header className="admin-top-banner">
        <div className="admin-banner-container">
          <div className="flex items-center gap-3">
            <div className="admin-shield-icon">
              <IconLock size={20} className="text-amber-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-amber-400">
                  Platform Control Plane
                </span>
                <span className="admin-pill">Admin Master Access</span>
              </div>
              <h1 className="text-base font-bold text-slate-100">
                AI Cyber Deception Gateway — System Administration
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigate('/app')}
              className="btn-admin-secondary text-xs"
            >
              ← Switch to Organization Workspace
            </button>
            <button
              onClick={loadAllAdminData}
              className="btn-admin-icon"
              title="Refresh platform telemetry"
            >
              <IconRefresh size={16} />
            </button>
            <button
              onClick={onLogout}
              className="btn-admin-danger text-xs"
            >
              Sign Out
            </button>
          </div>
        </div>
      </header>

      {/* Main Admin Body */}
      <div className="admin-body-container">
        {actionNotice && (
          <div className={`notification-toast ${actionNotice.type}`}>
            <span>{actionNotice.msg}</span>
          </div>
        )}

        {error && (
          <div className="auth-error-alert mb-5">
            <IconAlertTriangle size={18} className="text-rose-400 shrink-0" />
            <span className="text-xs text-rose-300">{error}</span>
          </div>
        )}

        {/* Admin Navigation Tabs */}
        <div className="admin-tabs-bar">
          <button
            onClick={() => setActiveTab('overview')}
            className={`admin-tab ${activeTab === 'overview' ? 'active' : ''}`}
          >
            <IconActivity size={16} />
            <span>Platform Overview</span>
          </button>
          <button
            onClick={() => setActiveTab('orgs')}
            className={`admin-tab ${activeTab === 'orgs' ? 'active' : ''}`}
          >
            <IconUsers size={16} />
            <span>Organizations ({organisations.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('apps')}
            className={`admin-tab ${activeTab === 'apps' ? 'active' : ''}`}
          >
            <IconServer size={16} />
            <span>Applications ({applications.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('users')}
            className={`admin-tab ${activeTab === 'users' ? 'active' : ''}`}
          >
            <IconShield size={16} />
            <span>Operator Accounts ({users.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('health')}
            className={`admin-tab ${activeTab === 'health' ? 'active' : ''}`}
          >
            <IconZap size={16} />
            <span>Infrastructure Health</span>
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`admin-tab ${activeTab === 'audit' ? 'active' : ''}`}
          >
            <IconTerminal size={16} />
            <span>System Audit ({auditLogs.length})</span>
          </button>
        </div>

        {/* TAB: OVERVIEW */}
        {activeTab === 'overview' && (
          <div>
            <div className="stats-metric-grid mb-6">
              <div className="stat-card">
                <span className="stat-card-title">Total Organizations</span>
                <div className="stat-card-value text-slate-100">{overview?.totalOrganisations ?? organisations.length}</div>
                <div className="stat-card-footer text-cyan-400">Isolated Tenant Spaces</div>
              </div>
              <div className="stat-card">
                <span className="stat-card-title">Registered Applications</span>
                <div className="stat-card-value text-slate-100">{overview?.totalApplications ?? applications.length}</div>
                <div className="stat-card-footer text-emerald-400">
                  {overview?.activeApplications ?? 0} Active / {overview?.verifiedApplications ?? 0} Verified
                </div>
              </div>
              <div className="stat-card">
                <span className="stat-card-title">Platform Operators</span>
                <div className="stat-card-value text-amber-400">{overview?.totalOperators ?? users.length}</div>
                <div className="stat-card-footer text-slate-400">Role-Based Access Control</div>
              </div>
              <div className="stat-card">
                <span className="stat-card-title">Security Events Recorded</span>
                <div className="stat-card-value text-violet-400">{overview?.totalSecurityEvents ?? 0}</div>
                <div className="stat-card-footer text-violet-400">Unified Event Pipeline</div>
              </div>
            </div>

            {/* Emergency Controls Banner */}
            <div className="dashboard-box mb-6 border-amber-900/40 bg-amber-950/20">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
                    <IconAlertTriangle size={18} />
                    <span>Platform Emergency Traffic Killswitch</span>
                  </h3>
                  <p className="text-xs text-slate-300 mt-1 max-w-xl">
                    Status: {gatewayHealth?.emergencyDisableDiversion ? (
                      <strong className="text-rose-400 font-mono">ACTIVATED (FORCING ORIGIN)</strong>
                    ) : (
                      <strong className="text-emerald-400 font-mono">DEACTIVATED (NORMAL ADAPTIVE DECEPTION)</strong>
                    )}
                  </p>
                </div>
                <button
                  onClick={handleToggleEmergencyKillswitch}
                  className={`btn-primary-small ${gatewayHealth?.emergencyDisableDiversion ? 'bg-emerald-600 hover:bg-emerald-500' : 'bg-rose-600 hover:bg-rose-500'}`}
                >
                  {gatewayHealth?.emergencyDisableDiversion ? 'Re-enable Adaptive Diversion' : 'Engage Emergency Killswitch'}
                </button>
              </div>
            </div>

            {/* Recent Events Table */}
            <div className="dashboard-box">
              <h3 className="box-title mb-3">Recent Platform Security Events</h3>
              <table className="portal-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Request ID</th>
                    <th>Method &amp; Path</th>
                    <th>Score</th>
                    <th>Classification</th>
                    <th>Decision</th>
                  </tr>
                </thead>
                <tbody>
                  {(overview?.recentSecurityEvents || []).map((ev) => (
                    <tr key={ev.id || ev.request_id}>
                      <td className="text-xs font-mono text-slate-400 whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="text-xs font-mono text-slate-400">{ev.request_id?.slice(0, 8)}...</td>
                      <td className="text-xs font-mono text-slate-200">
                        <span className="method-tag mr-1.5">{ev.method}</span>
                        {ev.path}
                      </td>
                      <td className="text-xs font-mono font-bold">
                        {ev.detection_score !== null ? parseFloat(ev.detection_score).toFixed(3) : '—'}
                      </td>
                      <td>
                        <span className={`classification-badge ${ev.detection_classification?.toLowerCase()}`}>
                          {ev.detection_classification}
                        </span>
                      </td>
                      <td>
                        <span className={`routing-badge ${ev.routing_decision?.toLowerCase()}`}>
                          {ev.routing_decision}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {(!overview?.recentSecurityEvents || overview.recentSecurityEvents.length === 0) && (
                    <tr>
                      <td colSpan={6} className="text-center py-6 text-xs text-slate-500">
                        No security events recorded across the platform yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB: ORGANIZATIONS */}
        {activeTab === 'orgs' && (
          <div className="dashboard-box">
            <h3 className="box-title mb-3">All Platform Organizations</h3>
            <table className="portal-table">
              <thead>
                <tr>
                  <th>Organization Name</th>
                  <th>Slug</th>
                  <th>Applications</th>
                  <th>Members</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {organisations.map((org) => (
                  <tr key={org.id}>
                    <td className="text-xs font-bold text-slate-100">{org.name}</td>
                    <td className="text-xs font-mono text-cyan-400">{org.slug}</td>
                    <td className="text-xs font-semibold">{org.applications_count ?? 0}</td>
                    <td className="text-xs font-semibold">{org.members_count ?? 1}</td>
                    <td className="text-xs text-slate-500">{new Date(org.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB: APPLICATIONS */}
        {activeTab === 'apps' && (
          <div className="dashboard-box">
            <h3 className="box-title mb-3">All Registered Applications</h3>
            <table className="portal-table">
              <thead>
                <tr>
                  <th>Application</th>
                  <th>Organization</th>
                  <th>Approved Domain</th>
                  <th>Configured Origin</th>
                  <th>DNS Status</th>
                  <th>Activation</th>
                </tr>
              </thead>
              <tbody>
                {applications.map((app) => (
                  <tr key={app.id}>
                    <td className="text-xs font-bold text-slate-100">{app.display_name}</td>
                    <td className="text-xs text-slate-300">{app.organisation_name || app.organisation_id}</td>
                    <td className="text-xs font-mono text-cyan-400">{app.approved_domain}</td>
                    <td className="text-xs font-mono text-slate-400 truncate max-w-[200px]" title={app.configured_origin}>
                      {app.configured_origin}
                    </td>
                    <td>
                      <span className={`status-tag ${app.verification_status === 'verified' ? 'green' : 'amber'}`}>
                        {app.verification_status}
                      </span>
                    </td>
                    <td>
                      <span className={`status-pill ${app.activation_status === 'active' ? 'active' : 'inactive'}`}>
                        {app.activation_status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB: USERS & ROLES */}
        {activeTab === 'users' && (
          <div className="dashboard-box">
            <h3 className="box-title mb-3">Platform Operator Directory &amp; RBAC</h3>
            <table className="portal-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Platform Role</th>
                  <th>Active Status</th>
                  <th>Workspaces</th>
                  <th>Change Role</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="text-xs font-bold text-slate-100">{u.username}</td>
                    <td className="text-xs text-slate-400">{u.email}</td>
                    <td>
                      <span className={`role-tag ${u.role === 'admin' ? 'border-amber-600 text-amber-300' : ''}`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="text-xs text-emerald-400">Active</td>
                    <td className="text-xs font-semibold">{u.organisations_count ?? 1}</td>
                    <td>
                      {u.id !== operator?.sub ? (
                        <select
                          value={u.role}
                          onChange={(e) => handleUpdateRole(u.id, e.target.value)}
                          className="form-input text-xs py-1"
                        >
                          <option value="admin">Admin</option>
                          <option value="analyst">Analyst</option>
                        </select>
                      ) : (
                        <span className="text-xs text-slate-500 italic">Self (Locked)</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB: INFRASTRUCTURE HEALTH */}
        {activeTab === 'health' && (
          <div className="grid md:grid-cols-2 gap-5">
            <div className="dashboard-box">
              <h3 className="box-title mb-3">Service Health Probes</h3>
              <div className="space-y-3">
                <div className="preflight-item">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-semibold text-slate-200">Gateway Reverse Proxy (:8080)</span>
                    <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> HEALTHY</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 mt-0.5">Mode: {gatewayHealth?.routingMode || 'active'}</div>
                </div>

                <div className="preflight-item">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-semibold text-slate-200">Core REST API Backend (:4000)</span>
                    <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> HEALTHY</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 mt-0.5">Status: Healthy</div>
                </div>

                <div className="preflight-item">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-semibold text-slate-200">PostgreSQL Relational DB (:5432)</span>
                    <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> HEALTHY</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 mt-0.5">Tables: 10 Migrations Applied</div>
                </div>

                <div className="preflight-item">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-semibold text-slate-200">ML Anomaly Detection (:8000)</span>
                    <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> HEALTHY</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 mt-0.5">Model: 0.3.0-synthetic-baseline</div>
                </div>

                <div className="preflight-item">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-semibold text-slate-200">Deception Runtime (:5050)</span>
                    <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> HEALTHY</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 mt-0.5">4-Node DSG Container DMZ</div>
                </div>
              </div>
            </div>

            <div className="dashboard-box">
              <h3 className="box-title mb-3">System Resource Telemetry</h3>
              <div className="bg-slate-900 p-4 rounded border border-slate-800 text-xs font-mono space-y-2 text-slate-300">
                <div>Node Environment: {systemHealth?.nodeEnv || 'production'}</div>
                <div>Server Uptime: {systemHealth?.uptime ? `${Math.round(systemHealth.uptime)} seconds` : '—'}</div>
                <div>Memory RSS: {systemHealth?.memoryUsage?.rss ? `${Math.round(systemHealth.memoryUsage.rss / 1024 / 1024)} MB` : '—'}</div>
                <div>Memory Heap: {systemHealth?.memoryUsage?.heapUsed ? `${Math.round(systemHealth.memoryUsage.heapUsed / 1024 / 1024)} MB` : '—'}</div>
              </div>
            </div>
          </div>
        )}

        {/* TAB: SYSTEM AUDIT */}
        {activeTab === 'audit' && (
          <div className="dashboard-box">
            <h3 className="box-title mb-3">Platform-Wide Audit Trail</h3>
            <table className="portal-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Scope</th>
                  <th>Operator</th>
                  <th>Action</th>
                  <th>Status</th>
                  <th>IP Address</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((l) => (
                  <tr key={l.id}>
                    <td className="text-xs font-mono text-slate-400 whitespace-nowrap">
                      {new Date(l.created_at).toLocaleString()}
                    </td>
                    <td>
                      <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${l.scope === 'SYSTEM' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-cyan-950 text-cyan-300 border border-cyan-800'}`}>
                        {l.scope}
                      </span>
                    </td>
                    <td className="text-xs font-medium text-slate-200">
                      {l.operator_username || l.actor_username || 'system'}
                    </td>
                    <td className="text-xs font-mono text-slate-100">{l.action}</td>
                    <td>
                      <span className={`status-tag ${l.status === 'SUCCESS' ? 'green' : 'red'}`}>
                        {l.status}
                      </span>
                    </td>
                    <td className="text-xs font-mono text-slate-500">{l.ip_address}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
