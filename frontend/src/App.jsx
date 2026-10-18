import React, { useState, useEffect } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:4000';
const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8080';

export default function App() {
  // Global & Health state
  const [backendHealth, setBackendHealth] = useState(null);
  const [gatewayHealth, setGatewayHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [backendError, setBackendError] = useState(null);
  const [gatewayError, setGatewayError] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);

  // Operator Auth state
  const [token, setToken] = useState(() => localStorage.getItem('operator_token') || '');
  const [operator, setOperator] = useState(() => {
    try {
      const saved = localStorage.getItem('operator_data');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  // Auth form state
  const [authMode, setAuthMode] = useState('login'); // 'login' | 'register'
  const [authUsername, setAuthUsername] = useState('sec_admin');
  const [authEmail, setAuthEmail] = useState('admin@deception.local');
  const [authPassword, setAuthPassword] = useState('SuperSecretAdminPassword123!');
  const [authRole, setAuthRole] = useState('admin');
  const [authError, setAuthError] = useState(null);
  const [authLoading, setAuthLoading] = useState(false);

  // Multi-tenant Org state
  const [organisations, setOrganisations] = useState([]);
  const [selectedOrgId, setSelectedOrgId] = useState('');
  const [orgLoading, setOrgLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('apps'); // 'apps' | 'members' | 'audit' | 'telemetry'

  // New Org form state
  const [showNewOrgModal, setShowNewOrgModal] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgSlug, setNewOrgSlug] = useState('');
  const [newOrgDesc, setNewOrgDesc] = useState('');
  const [newOrgError, setNewOrgError] = useState(null);

  // Applications state
  const [applications, setApplications] = useState([]);
  const [appsLoading, setAppsLoading] = useState(false);
  const [challenges, setChallenges] = useState({}); // { [appId]: challengeObj }
  const [verifyStatusMsg, setVerifyStatusMsg] = useState({});

  // Register App form state
  const [showNewAppModal, setShowNewAppModal] = useState(false);
  const [newAppDisplayName, setNewAppDisplayName] = useState('');
  const [newAppEnv, setNewAppEnv] = useState('production');
  const [newAppDomain, setNewAppDomain] = useState('');
  const [newAppOrigin, setNewAppOrigin] = useState('');
  const [newAppError, setNewAppError] = useState(null);

  // Members state
  const [members, setMembers] = useState([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [newMemberUsername, setNewMemberUsername] = useState('');
  const [newMemberRole, setNewMemberRole] = useState('security_analyst');
  const [memberActionError, setMemberActionError] = useState(null);

  // Audit state
  const [auditEvents, setAuditEvents] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);

  // Stage 8 Security Events & Observability State
  const [securityEvents, setSecurityEvents] = useState([]);
  const [eventsSummary, setEventsSummary] = useState(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventFilterDecision, setEventFilterDecision] = useState('ALL');
  const [gatewayMetrics, setGatewayMetrics] = useState(null);
  const [metricsLoading, setMetricsLoading] = useState(false);

  // 1. Fetch Health Metrics
  const fetchAllHealth = async () => {
    setHealthLoading(true);
    setBackendError(null);
    setGatewayError(null);

    try {
      const res = await fetch(`${BACKEND_URL}/health`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const data = await res.json();
      setBackendHealth(data);
    } catch (err) {
      setBackendError(err.message || 'Failed to connect to backend.');
      setBackendHealth(null);
    }

    try {
      const res = await fetch(`${GATEWAY_URL}/health`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const data = await res.json();
      setGatewayHealth(data);
    } catch (err) {
      setGatewayError(err.message || 'Failed to connect to gateway.');
      setGatewayHealth(null);
    }

    setLastChecked(new Date().toLocaleTimeString());
    setHealthLoading(false);
  };

  useEffect(() => {
    fetchAllHealth();
  }, []);

  // 2. Auth Actions
  const handleAuthSubmit = async (e) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError(null);

    try {
      if (authMode === 'register') {
        const regRes = await fetch(`${BACKEND_URL}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: authUsername,
            email: authEmail,
            password: authPassword,
            role: authRole,
          }),
        });
        const regData = await regRes.json();
        if (!regRes.ok) throw new Error(regData.message || 'Registration failed');
      }

      // Login
      const loginRes = await fetch(`${BACKEND_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: authUsername,
          password: authPassword,
        }),
      });
      const loginData = await loginRes.json();
      if (!loginRes.ok) throw new Error(loginData.message || 'Login failed');

      setToken(loginData.token);
      setOperator(loginData.operator);
      localStorage.setItem('operator_token', loginData.token);
      localStorage.setItem('operator_data', JSON.stringify(loginData.operator));
    } catch (err) {
      setAuthError(err.message || 'Authentication failed');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    setToken('');
    setOperator(null);
    localStorage.removeItem('operator_token');
    localStorage.removeItem('operator_data');
    setOrganisations([]);
    setSelectedOrgId('');
  };

  // 3. Fetch Organisations
  const fetchOrganisations = async () => {
    if (!token) return;
    setOrgLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setOrganisations(data.organisations || []);
        if (data.organisations?.length > 0 && !selectedOrgId) {
          setSelectedOrgId(data.organisations[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to load organisations:', err);
    } finally {
      setOrgLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      fetchOrganisations();
    }
  }, [token]);

  // 4. Create Organisation
  const handleCreateOrg = async (e) => {
    e.preventDefault();
    setNewOrgError(null);
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: newOrgName,
          slug: newOrgSlug || newOrgName.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
          description: newOrgDesc,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to create organisation');

      setShowNewOrgModal(false);
      setNewOrgName('');
      setNewOrgSlug('');
      setNewOrgDesc('');
      await fetchOrganisations();
      setSelectedOrgId(data.organisation.id);
    } catch (err) {
      setNewOrgError(err.message);
    }
  };

  // 5. Fetch Applications for selected Org
  const fetchApplications = async () => {
    if (!token || !selectedOrgId) return;
    setAppsLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/apps`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        const apps = data.applications || [];
        setApplications(apps);

        // Fetch challenge for each app
        for (const app of apps) {
          fetchChallengeForApp(app.id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch applications:', err);
    } finally {
      setAppsLoading(false);
    }
  };

  const fetchChallengeForApp = async (appId) => {
    if (!token || !selectedOrgId) return;
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/apps/${appId}/verification-challenges/latest`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setChallenges((prev) => ({ ...prev, [appId]: data.verificationChallenge || data.challenge }));
      }
    } catch (err) {
      // Challenge may not exist yet
    }
  };

  // 6. Register Application
  const handleRegisterApp = async (e) => {
    e.preventDefault();
    setNewAppError(null);
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/apps`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          displayName: newAppDisplayName,
          environment: newAppEnv,
          approvedDomain: newAppDomain,
          configuredOrigin: newAppOrigin,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to register application');

      setShowNewAppModal(false);
      setNewAppDisplayName('');
      setNewAppDomain('');
      setNewAppOrigin('');
      await fetchApplications();
    } catch (err) {
      setNewAppError(err.message);
    }
  };

  // 7. Verify DNS TXT Challenge
  const handleVerifyDns = async (appId) => {
    setVerifyStatusMsg((prev) => ({ ...prev, [appId]: { checking: true } }));
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/apps/${appId}/verify`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      setVerifyStatusMsg((prev) => ({
        ...prev,
        [appId]: {
          checking: false,
          verified: data.verified,
          message: data.message,
        },
      }));
      await fetchApplications();
    } catch (err) {
      setVerifyStatusMsg((prev) => ({
        ...prev,
        [appId]: { checking: false, verified: false, message: err.message },
      }));
    }
  };

  // 8. Application Activation & Disabling
  const handleActivateApp = async (appId) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/apps/${appId}/activate`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) alert(data.message || 'Failed to activate');
      await fetchApplications();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDisableApp = async (appId) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/apps/${appId}/disable`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) alert(data.message || 'Failed to disable');
      await fetchApplications();
    } catch (err) {
      alert(err.message);
    }
  };

  // 9. Fetch Members
  const fetchMembers = async () => {
    if (!token || !selectedOrgId) return;
    setMembersLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/members`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setMembers(data.members || []);
      }
    } catch (err) {
      console.error('Failed to load members:', err);
    } finally {
      setMembersLoading(false);
    }
  };

  // 10. Fetch Audit Log
  const fetchAuditEvents = async () => {
    if (!token || !selectedOrgId) return;
    setAuditLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/audit`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setAuditEvents(data.auditEvents || data.events || []);
      }
    } catch (err) {
      console.error('Failed to load audit events:', err);
    } finally {
      setAuditLoading(false);
    }
  };

  // 11. Fetch Security Events Pipeline (Stage 8)
  const fetchSecurityEvents = async () => {
    if (!token && !selectedOrgId) return;
    setEventsLoading(true);
    try {
      let url = `${BACKEND_URL}/api/orgs/${selectedOrgId}/events?limit=50`;
      if (eventFilterDecision && eventFilterDecision !== 'ALL') {
        url += `&routingDecision=${eventFilterDecision}`;
      }
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setSecurityEvents(data.events || []);
      } else {
        const gwRes = await fetch(`${GATEWAY_URL}/api/gateway/events?limit=50`);
        if (gwRes.ok) {
          const gwData = await gwRes.json();
          setSecurityEvents(gwData.events || []);
        }
      }

      // Fetch summary
      const sumRes = await fetch(`${BACKEND_URL}/api/orgs/${selectedOrgId}/events/summary`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (sumRes.ok) {
        const sumData = await sumRes.json();
        setEventsSummary(sumData.summary || null);
      }
    } catch (err) {
      console.error('Failed to load security events:', err);
    } finally {
      setEventsLoading(false);
    }
  };

  // 12. Fetch Gateway Operational Metrics (Stage 8)
  const fetchGatewayMetrics = async () => {
    setMetricsLoading(true);
    try {
      const res = await fetch(`${GATEWAY_URL}/api/gateway/metrics`);
      if (res.ok) {
        const data = await res.json();
        setGatewayMetrics(data);
      }
    } catch (err) {
      console.error('Failed to load gateway metrics:', err);
    } finally {
      setMetricsLoading(false);
    }
  };

  // Auto-fetch data on active org or tab change
  useEffect(() => {
    if (selectedOrgId && token) {
      if (activeTab === 'apps') fetchApplications();
      if (activeTab === 'members') fetchMembers();
      if (activeTab === 'audit') fetchAuditEvents();
      if (activeTab === 'events') fetchSecurityEvents();
      if (activeTab === 'telemetry') {
        fetchAllHealth();
        fetchGatewayMetrics();
      }
    }
  }, [selectedOrgId, activeTab, token, eventFilterDecision]);

  const activeOrg = organisations.find((o) => o.id === selectedOrgId);

  return (
    <div className="container">
      {/* Header */}
      <header className="header">
        <div className="badge">Stage 8: End-to-End Security Validation & Evaluation Framework</div>
        <h1>AI-Enabled Adaptive Cyber Deception Gateway</h1>
        <p className="subtitle">
          Real-Time Attacker Detection, Adaptive DSG Diversion, Unified Event Pipeline & Evaluation Metrics
        </p>
      </header>

      {/* Operator Session Bar */}
      <section className="card" style={{ marginBottom: '1.5rem', padding: '1rem 1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          {token && operator ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <span className="dot green"></span>
              <div>
                <strong>Operator:</strong> <code>{operator.username}</code>
                <span className="badge-pill badge-blue" style={{ marginLeft: '0.5rem' }}>
                  {operator.role.toUpperCase()}
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                  ({operator.email})
                </span>
              </div>
            </div>
          ) : (
            <div>
              <span className="dot yellow"></span>
              <strong style={{ marginLeft: '0.5rem' }}>Unauthenticated Session:</strong> Sign in as an operator to manage multi-tenant workspaces.
            </div>
          )}

          <div>
            {token ? (
              <button className="btn btn-secondary btn-small" onClick={handleLogout}>
                Sign Out
              </button>
            ) : (
              <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                Local Operator Auth Enforced
              </span>
            )}
          </div>
        </div>
      </section>

      {/* Main Content Area */}
      {!token ? (
        /* Sign In / Registration Form */
        <section className="card" style={{ maxWidth: '480px', margin: '0 auto' }}>
          <h2>{authMode === 'login' ? 'Operator Login' : 'Register Operator Account'}</h2>
          <p className="section-desc">
            Access multi-tenant organization workspaces and deception routing controls.
          </p>

          {authError && (
            <div className="status-box error" style={{ marginBottom: '1rem' }}>
              <span className="indicator red"></span>
              <div>{authError}</div>
            </div>
          )}

          <form onSubmit={handleAuthSubmit}>
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                className="input"
                value={authUsername}
                onChange={(e) => setAuthUsername(e.target.value)}
                required
              />
            </div>

            {authMode === 'register' && (
              <>
                <div className="form-group">
                  <label>Email</label>
                  <input
                    type="email"
                    className="input"
                    value={authEmail}
                    onChange={(e) => setAuthEmail(e.target.value)}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Operator Role</label>
                  <select
                    className="select"
                    value={authRole}
                    onChange={(e) => setAuthRole(e.target.value)}
                  >
                    <option value="admin">Administrator (Full Control)</option>
                    <option value="analyst">Security Analyst (Read Only)</option>
                  </select>
                </div>
              </>
            )}

            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                className="input"
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                required
              />
            </div>

            <button type="submit" className="btn" style={{ width: '100%', marginBottom: '1rem' }} disabled={authLoading}>
              {authLoading ? 'Authenticating...' : authMode === 'login' ? 'Sign In' : 'Create Operator Account'}
            </button>
          </form>

          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
            <button
              type="button"
              style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer' }}
              onClick={() => {
                setAuthMode(authMode === 'login' ? 'register' : 'login');
                setAuthError(null);
              }}
            >
              {authMode === 'login' ? 'Need an account? Register' : 'Already registered? Sign In'}
            </button>

            <button
              type="button"
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              onClick={() => {
                setAuthUsername('sec_admin');
                setAuthPassword('SuperSecretAdminPassword123!');
              }}
            >
              Use Admin Preset
            </button>
          </div>
        </section>
      ) : (
        /* Authenticated Multi-Tenant Operator Workspace */
        <main className="content">
          {/* Org Selector & Controls */}
          <section className="card" style={{ padding: '1.25rem 1.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', minWidth: '300px' }}>
                <label style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                  Active Tenant:
                </label>
                <select
                  className="select"
                  style={{ width: 'auto', minWidth: '220px' }}
                  value={selectedOrgId}
                  onChange={(e) => setSelectedOrgId(e.target.value)}
                >
                  {organisations.map((org) => (
                    <option key={org.id} value={org.id}>
                      {org.name} ({org.role || 'member'})
                    </option>
                  ))}
                  {organisations.length === 0 && <option value="">No organisations found</option>}
                </select>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button className="btn btn-secondary btn-small" onClick={() => setShowNewOrgModal(true)}>
                  + New Organisation
                </button>
              </div>
            </div>

            {activeOrg && (
              <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-color)', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                <strong>Slug:</strong> <code>{activeOrg.slug}</code> &nbsp;|&nbsp;
                <strong>Tenant Role:</strong> <span className="badge-pill badge-green">{activeOrg.role}</span> &nbsp;|&nbsp;
                <strong>Description:</strong> {activeOrg.description || 'Enterprise Tenant'}
              </div>
            )}
          </section>

          {/* New Org Modal */}
          {showNewOrgModal && (
            <div className="card" style={{ border: '1px solid var(--accent-cyan)' }}>
              <h3>Create New Organisation</h3>
              <form onSubmit={handleCreateOrg} style={{ marginTop: '1rem' }}>
                {newOrgError && <p style={{ color: 'var(--accent-red)', fontSize: '0.85rem' }}>{newOrgError}</p>}
                <div className="form-row">
                  <div className="form-group">
                    <label>Organisation Name</label>
                    <input
                      type="text"
                      className="input"
                      placeholder="e.g. Acme Cyber Corp"
                      value={newOrgName}
                      onChange={(e) => setNewOrgName(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Slug (URL Safe)</label>
                    <input
                      type="text"
                      className="input"
                      placeholder="acme-corp"
                      value={newOrgSlug}
                      onChange={(e) => setNewOrgSlug(e.target.value)}
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label>Description</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="Tenant description"
                    value={newOrgDesc}
                    onChange={(e) => setNewOrgDesc(e.target.value)}
                  />
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                  <button type="button" className="btn btn-secondary btn-small" onClick={() => setShowNewOrgModal(false)}>
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-small">
                    Create Organisation
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Workspace Tab Bar */}
          <div className="tab-bar">
            <button
              className={`tab-btn ${activeTab === 'apps' ? 'active' : ''}`}
              onClick={() => setActiveTab('apps')}
            >
              Protected Applications ({applications.length})
            </button>
            <button
              className={`tab-btn ${activeTab === 'events' ? 'active' : ''}`}
              onClick={() => setActiveTab('events')}
            >
              Security Events Pipeline ({securityEvents.length})
            </button>
            <button
              className={`tab-btn ${activeTab === 'telemetry' ? 'active' : ''}`}
              onClick={() => setActiveTab('telemetry')}
            >
              Observability & Metrics
            </button>
            <button
              className={`tab-btn ${activeTab === 'members' ? 'active' : ''}`}
              onClick={() => setActiveTab('members')}
            >
              Tenant Members ({members.length})
            </button>
            <button
              className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
              onClick={() => setActiveTab('audit')}
            >
              Organisation Audit Trail
            </button>
          </div>

          {/* TAB 1: APPLICATIONS & ONBOARDING */}
          {activeTab === 'apps' && (
            <section className="card">
              <div className="card-header">
                <div>
                  <h2>Registered Applications & Onboarding</h2>
                  <p className="section-desc" style={{ marginBottom: 0 }}>
                    Manage authorized application endpoints, domain challenges, and adaptive deception routing.
                  </p>
                </div>
                <button className="btn" onClick={() => setShowNewAppModal(true)}>
                  + Register Application
                </button>
              </div>

              {/* Register App Modal */}
              {showNewAppModal && (
                <div style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', marginBottom: '1.5rem', border: '1px solid var(--border-color)' }}>
                  <h3>Onboard New Application</h3>
                  <form onSubmit={handleRegisterApp} style={{ marginTop: '1rem' }}>
                    {newAppError && <p style={{ color: 'var(--accent-red)', fontSize: '0.85rem' }}>{newAppError}</p>}
                    <div className="form-row">
                      <div className="form-group">
                        <label>Application Display Name</label>
                        <input
                          type="text"
                          className="input"
                          placeholder="e.g. Customer Portal"
                          value={newAppDisplayName}
                          onChange={(e) => setNewAppDisplayName(e.target.value)}
                          required
                        />
                      </div>
                      <div className="form-group">
                        <label>Environment</label>
                        <select
                          className="select"
                          value={newAppEnv}
                          onChange={(e) => setNewAppEnv(e.target.value)}
                        >
                          <option value="production">Production</option>
                          <option value="staging">Staging</option>
                          <option value="development">Development</option>
                        </select>
                      </div>
                    </div>
                    <div className="form-row">
                      <div className="form-group">
                        <label>Approved Domain (FQDN)</label>
                        <input
                          type="text"
                          className="input"
                          placeholder="e.g. portal.acme.com"
                          value={newAppDomain}
                          onChange={(e) => setNewAppDomain(e.target.value)}
                          required
                        />
                      </div>
                      <div className="form-group">
                        <label>Configured Upstream Origin URL</label>
                        <input
                          type="text"
                          className="input"
                          placeholder="e.g. https://portal-internal.acme:8443 or http://test-origin:5000"
                          value={newAppOrigin}
                          onChange={(e) => setNewAppOrigin(e.target.value)}
                          required
                        />
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                      <button type="button" className="btn btn-secondary btn-small" onClick={() => setShowNewAppModal(false)}>
                        Cancel
                      </button>
                      <button type="submit" className="btn btn-small">
                        Submit Registration
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {/* Applications List */}
              {appsLoading && <p className="status-text muted">Loading applications...</p>}
              {!appsLoading && applications.length === 0 && (
                <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                  No applications registered yet. Click <strong>+ Register Application</strong> to begin.
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {applications.map((app) => {
                  const challenge = challenges[app.id];
                  const verifyState = verifyStatusMsg[app.id];
                  const isVerified = app.verification_status === 'verified';
                  const isActive = app.activation_status === 'active';

                  return (
                    <div key={app.id} style={{ background: 'var(--bg-card)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
                            <h3 style={{ fontSize: '1.1rem' }}>{app.display_name}</h3>
                            <span className="badge-pill badge-blue">{app.environment.toUpperCase()}</span>
                          </div>
                          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                            <strong>Domain:</strong> <code>{app.approved_domain}</code> &nbsp;|&nbsp;
                            <strong>Origin:</strong> <code>{app.configured_origin}</code>
                          </div>
                        </div>

                        {/* Badges & Actions */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          {isVerified ? (
                            <span className="badge-pill badge-green">VERIFIED</span>
                          ) : (
                            <span className="badge-pill badge-yellow">UNVERIFIED</span>
                          )}

                          {isActive ? (
                            <span className="badge-pill badge-green">ACTIVE</span>
                          ) : (
                            <span className="badge-pill badge-red">{app.activation_status?.toUpperCase() || 'INACTIVE'}</span>
                          )}

                          {/* Activation controls */}
                          {isActive ? (
                            <button
                              className="btn btn-danger btn-small"
                              onClick={() => handleDisableApp(app.id)}
                            >
                              Disable
                            </button>
                          ) : (
                            <button
                              className="btn btn-success btn-small"
                              onClick={() => handleActivateApp(app.id)}
                              disabled={!isVerified}
                              title={!isVerified ? 'Domain verification required before activation' : ''}
                            >
                              Activate Interception
                            </button>
                          )}
                        </div>
                      </div>

                      {/* DNS TXT Challenge Card for Unverified Apps */}
                      {!isVerified && challenge && (
                        <div className="challenge-card">
                          <div style={{ color: 'var(--accent-yellow)', fontWeight: 600, marginBottom: '0.5rem' }}>
                            Action Required: Verify Domain Ownership via DNS TXT Record
                          </div>
                          <div className="challenge-row">
                            <span className="challenge-label">Record Name:</span>
                            <code>{challenge.record_name || challenge.recordName}</code>
                          </div>
                          <div className="challenge-row">
                            <span className="challenge-label">Record Type:</span>
                            <code>TXT</code>
                          </div>
                          <div className="challenge-row">
                            <span className="challenge-label">Expected Value:</span>
                            <code>{challenge.token}</code>
                          </div>

                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.75rem', paddingTop: '0.5rem', borderTop: '1px dashed #304460' }}>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                              Attempts: {challenge.attempts_count ?? challenge.attemptsCount ?? 0} / 5 &nbsp;|&nbsp; Status: {challenge.status?.toUpperCase()}
                            </span>
                            <button
                              className="btn btn-small"
                              onClick={() => handleVerifyDns(app.id)}
                              disabled={verifyState?.checking}
                            >
                              {verifyState?.checking ? 'Checking DNS...' : 'Verify DNS Record'}
                            </button>
                          </div>

                          {verifyState && verifyState.message && (
                            <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: verifyState.verified ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                              {verifyState.message}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* TAB 2: TENANT MEMBERS */}
          {activeTab === 'members' && (
            <section className="card">
              <div className="card-header">
                <div>
                  <h2>Tenant Members & Roles</h2>
                  <p className="section-desc" style={{ marginBottom: 0 }}>
                    Manage access control and RBAC roles scoped to this organisation.
                  </p>
                </div>
              </div>

              {membersLoading && <p className="status-text muted">Loading tenant members...</p>}

              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Operator</th>
                      <th>Email</th>
                      <th>Organisation Role</th>
                      <th>Joined</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map((m) => (
                      <tr key={m.id}>
                        <td><strong>{m.username}</strong></td>
                        <td><code>{m.email}</code></td>
                        <td>
                          <span className={`badge-pill ${m.role === 'org_owner' ? 'badge-green' : m.role === 'security_admin' ? 'badge-blue' : 'badge-yellow'}`}>
                            {m.role?.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ color: 'var(--text-muted)' }}>
                          {new Date(m.created_at || m.createdAt).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                    {members.length === 0 && (
                      <tr>
                        <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                          No members found.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* TAB 3: AUDIT TRAIL */}
          {activeTab === 'audit' && (
            <section className="card">
              <div className="card-header">
                <div>
                  <h2>Organisation Audit Trail</h2>
                  <p className="section-desc" style={{ marginBottom: 0 }}>
                    Cryptographic record of security, onboarding and routing events for this tenant.
                  </p>
                </div>
                <button className="btn btn-secondary btn-small" onClick={fetchAuditEvents}>
                  Refresh
                </button>
              </div>

              {auditLoading && <p className="status-text muted">Loading audit events...</p>}

              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Action</th>
                      <th>Actor</th>
                      <th>Resource Type</th>
                      <th>Status</th>
                      <th>Client IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEvents.map((evt) => (
                      <tr key={evt.id}>
                        <td style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                          {new Date(evt.created_at).toLocaleTimeString()}
                        </td>
                        <td><code>{evt.action}</code></td>
                        <td>{evt.actor_username || 'system'}</td>
                        <td>{evt.resource_type}</td>
                        <td>
                          <span className={`badge-pill ${evt.status === 'SUCCESS' ? 'badge-green' : 'badge-red'}`}>
                            {evt.status}
                          </span>
                        </td>
                        <td style={{ color: 'var(--text-muted)' }}>{evt.ip_address}</td>
                      </tr>
                    ))}
                    {auditEvents.length === 0 && (
                      <tr>
                        <td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                          No audit events recorded yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* TAB: SECURITY EVENTS PIPELINE (STAGE 8) */}
          {activeTab === 'events' && (
            <section className="card">
              <div className="card-header">
                <div>
                  <h2>Security Events Pipeline & Ingestion</h2>
                  <p className="section-desc" style={{ marginBottom: 0 }}>
                    Auditable, tenant-isolated real-time security events captured across proxy routing decisions with credential redaction.
                  </p>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                  <select
                    className="select"
                    style={{ width: 'auto', fontSize: '0.85rem' }}
                    value={eventFilterDecision}
                    onChange={(e) => setEventFilterDecision(e.target.value)}
                  >
                    <option value="ALL">All Decisions</option>
                    <option value="ORIGIN">Origin Forwarded</option>
                    <option value="DECEPTION">Deception Diverted</option>
                    <option value="OBSERVE_ONLY">Observe Only</option>
                  </select>
                  <button className="btn btn-small" onClick={fetchSecurityEvents} disabled={eventsLoading}>
                    {eventsLoading ? 'Loading...' : 'Refresh'}
                  </button>
                </div>
              </div>

              {/* Summary Metric Cards */}
              <div className="stat-cards-grid">
                <div className="stat-card">
                  <div className="stat-card-val">{eventsSummary?.totalEvents ?? securityEvents.length}</div>
                  <div className="stat-card-label">Total Events</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-val" style={{ color: 'var(--accent-blue)' }}>
                    {eventsSummary?.byDecision?.ORIGIN ?? securityEvents.filter((e) => e.routing_decision === 'ORIGIN').length}
                  </div>
                  <div className="stat-card-label">Origin Forwarded</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-val" style={{ color: '#ba68c8' }}>
                    {eventsSummary?.byDecision?.DECEPTION ?? securityEvents.filter((e) => e.routing_decision === 'DECEPTION').length}
                  </div>
                  <div className="stat-card-label">Deception Diverted</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-val" style={{ color: 'var(--accent-yellow)' }}>
                    {eventsSummary?.byDecision?.OBSERVE_ONLY ?? securityEvents.filter((e) => e.routing_decision === 'OBSERVE_ONLY').length}
                  </div>
                  <div className="stat-card-label">Observe Only</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-val" style={{ color: 'var(--accent-red)' }}>
                    {eventsSummary?.quarantinedCount ?? securityEvents.filter((e) => e.quarantined).length}
                  </div>
                  <div className="stat-card-label">Quarantined</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-val" style={{ color: 'var(--accent-green)' }}>
                    {eventsSummary?.avgScore !== undefined && eventsSummary?.avgScore !== null
                      ? Number(eventsSummary.avgScore).toFixed(2)
                      : (securityEvents.length > 0
                          ? (securityEvents.reduce((acc, e) => acc + (Number(e.risk_score) || 0), 0) / securityEvents.length).toFixed(2)
                          : '0.00')}
                  </div>
                  <div className="stat-card-label">Avg Risk Score</div>
                </div>
              </div>

              {/* Events Table */}
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Method & Path</th>
                      <th>Decision</th>
                      <th>Score</th>
                      <th>Classification</th>
                      <th>Session ID</th>
                      <th>Target Upstream</th>
                      <th>Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    {securityEvents.map((evt) => {
                      const decisionBadge =
                        evt.routing_decision === 'DECEPTION'
                          ? 'badge-purple'
                          : evt.routing_decision === 'ORIGIN'
                          ? 'badge-blue'
                          : 'badge-yellow';

                      return (
                        <tr key={evt.id || `${evt.timestamp || evt.created_at}-${evt.session_id}-${Math.random()}`}>
                          <td style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                            {evt.created_at ? new Date(evt.created_at).toLocaleTimeString() : (evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'Just now')}
                          </td>
                          <td>
                            <strong>{evt.method}</strong>{' '}
                            <code style={{ fontSize: '0.8rem' }}>{evt.path}</code>
                          </td>
                          <td>
                            <span className={`badge-pill ${decisionBadge}`}>
                              {evt.routing_decision}
                            </span>
                            {evt.quarantined && (
                              <span className="badge-pill badge-red" style={{ marginLeft: '0.25rem' }}>
                                QUARANTINE
                              </span>
                            )}
                          </td>
                          <td>
                            <code>{typeof evt.risk_score === 'number' ? evt.risk_score.toFixed(3) : evt.risk_score}</code>
                          </td>
                          <td style={{ color: 'var(--text-muted)' }}>
                            {evt.classification || 'unknown'}
                          </td>
                          <td style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                            {evt.session_id ? `${evt.session_id.substring(0, 10)}...` : 'N/A'}
                          </td>
                          <td style={{ fontSize: '0.8rem' }}>
                            {evt.routing_decision === 'DECEPTION'
                              ? evt.deception_service || 'deception-runtime'
                              : evt.origin_upstream || 'test-origin'}
                          </td>
                          <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                            {evt.latency_ms !== undefined ? `${Math.round(evt.latency_ms)}ms` : '—'}
                          </td>
                        </tr>
                      );
                    })}
                    {securityEvents.length === 0 && (
                      <tr>
                        <td colSpan="8" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                          No security events recorded yet for this organisation.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* TAB: SYSTEM TELEMETRY & OBSERVABILITY */}
          {activeTab === 'telemetry' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Operational Metrics Section */}
              <section className="card">
                <div className="card-header">
                  <div>
                    <h2>Operational Observability & Latency Percentiles</h2>
                    <p className="section-desc" style={{ marginBottom: 0 }}>
                      Live in-memory telemetry for gateway dispatch, ML detection engine, and dynamic deception runtime.
                    </p>
                  </div>
                  <button className="btn btn-small" onClick={() => { fetchAllHealth(); fetchGatewayMetrics(); }} disabled={metricsLoading}>
                    {metricsLoading ? 'Refreshing...' : 'Refresh Metrics'}
                  </button>
                </div>

                {gatewayMetrics ? (
                  <>
                    <div className="stat-cards-grid">
                      <div className="stat-card">
                        <div className="stat-card-val">{gatewayMetrics.requests?.total ?? 0}</div>
                        <div className="stat-card-label">Total Handled</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-card-val" style={{ color: 'var(--accent-blue)' }}>
                          {gatewayMetrics.routingBreakdown?.ORIGIN ?? 0}
                        </div>
                        <div className="stat-card-label">Origin Routed</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-card-val" style={{ color: '#ba68c8' }}>
                          {gatewayMetrics.routingBreakdown?.DECEPTION ?? 0}
                        </div>
                        <div className="stat-card-label">Deception Routed</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-card-val" style={{ color: 'var(--accent-yellow)' }}>
                          {gatewayMetrics.routingBreakdown?.OBSERVE_ONLY ?? 0}
                        </div>
                        <div className="stat-card-label">Observe Only</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-card-val" style={{ color: 'var(--accent-cyan)' }}>
                          {gatewayMetrics.activeDeceptionSessions ?? 0}
                        </div>
                        <div className="stat-card-label">Active DSG Sessions</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-card-val" style={{ color: 'var(--accent-red)' }}>
                          {gatewayMetrics.errors?.quarantinedDeception ?? 0}
                        </div>
                        <div className="stat-card-label">Quarantined</div>
                      </div>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
                      <div className="card" style={{ background: 'var(--bg-card)', padding: '1rem' }}>
                        <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '0.5rem' }}>Gateway Latency</h4>
                        <div className="meta-grid">
                          <div><strong>Average:</strong> {gatewayMetrics.latencies?.gateway?.avgMs ? `${gatewayMetrics.latencies.gateway.avgMs.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>p50:</strong> {gatewayMetrics.latencies?.gateway?.p50Ms ? `${gatewayMetrics.latencies.gateway.p50Ms.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>p95:</strong> {gatewayMetrics.latencies?.gateway?.p95Ms ? `${gatewayMetrics.latencies.gateway.p95Ms.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>Sample Count:</strong> {gatewayMetrics.latencies?.gateway?.count ?? 0}</div>
                        </div>
                      </div>

                      <div className="card" style={{ background: 'var(--bg-card)', padding: '1rem' }}>
                        <h4 style={{ color: 'var(--accent-green)', marginBottom: '0.5rem' }}>Detection Engine</h4>
                        <div className="meta-grid">
                          <div><strong>Average:</strong> {gatewayMetrics.latencies?.detection?.avgMs ? `${gatewayMetrics.latencies.detection.avgMs.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>p50:</strong> {gatewayMetrics.latencies?.detection?.p50Ms ? `${gatewayMetrics.latencies.detection.p50Ms.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>p95:</strong> {gatewayMetrics.latencies?.detection?.p95Ms ? `${gatewayMetrics.latencies.detection.p95Ms.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>Detector Errors:</strong> {gatewayMetrics.errors?.detectionServiceErrors ?? 0}</div>
                        </div>
                      </div>

                      <div className="card" style={{ background: 'var(--bg-card)', padding: '1rem' }}>
                        <h4 style={{ color: '#ba68c8', marginBottom: '0.5rem' }}>Deception Runtime</h4>
                        <div className="meta-grid">
                          <div><strong>Average:</strong> {gatewayMetrics.latencies?.deception?.avgMs ? `${gatewayMetrics.latencies.deception.avgMs.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>p50:</strong> {gatewayMetrics.latencies?.deception?.p50Ms ? `${gatewayMetrics.latencies.deception.p50Ms.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>p95:</strong> {gatewayMetrics.latencies?.deception?.p95Ms ? `${gatewayMetrics.latencies.deception.p95Ms.toFixed(1)} ms` : '0 ms'}</div>
                          <div><strong>Deception Errors:</strong> {gatewayMetrics.errors?.deceptionServiceErrors ?? 0}</div>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <p style={{ color: 'var(--text-muted)' }}>Gateway operational metrics loading or unavailable.</p>
                )}
              </section>

              {/* Service Health Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
                {/* Gateway Health Card */}
                <section className="card health-card">
                  <div className="card-header">
                    <h2>Gateway Health (Port 8080)</h2>
                    <button className="btn btn-small" onClick={fetchAllHealth} disabled={healthLoading}>
                      {healthLoading ? 'Checking...' : 'Refresh'}
                    </button>
                  </div>
                  <div className="endpoint-info">
                    Target: <code>{GATEWAY_URL}/health</code>
                  </div>

                  {gatewayError && (
                    <div className="status-box error">
                      <span className="indicator red"></span>
                      <div>
                        <strong>Gateway Unreachable:</strong> {gatewayError}
                      </div>
                    </div>
                  )}

                  {gatewayHealth && (
                    <div className="status-box success">
                      <span className="indicator green"></span>
                      <div className="status-details">
                        <div className="status-title">
                          <strong>Status:</strong> {gatewayHealth.status.toUpperCase()}
                        </div>
                        <div className="meta-grid">
                          <div><strong>Service:</strong> {gatewayHealth.service}</div>
                          <div><strong>Stage:</strong> {gatewayHealth.stage}</div>
                          <div><strong>Routing Mode:</strong> {gatewayHealth.routingMode?.toUpperCase() || 'SHADOW'}</div>
                          <div><strong>Killswitch:</strong> {gatewayHealth.emergencyDisableDiversion ? 'ACTIVATED' : 'DISENGAGED'}</div>
                          <div><strong>Deception Upstream:</strong> {gatewayHealth.deceptionService}</div>
                          <div><strong>Deception Sessions:</strong> {gatewayHealth.activeDeceptionSessions ?? 0}</div>
                          <div><strong>Score Threshold:</strong> {gatewayHealth.deceptionThreshold ?? '0.70'}</div>
                          <div><strong>Last Checked:</strong> {lastChecked}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </section>

                {/* Backend Health Card */}
                <section className="card health-card">
                  <div className="card-header">
                    <h2>Backend Service (Port 4000)</h2>
                  </div>
                  <div className="endpoint-info">
                    Target: <code>{BACKEND_URL}/health</code>
                  </div>

                  {backendError && (
                    <div className="status-box error">
                      <span className="indicator red"></span>
                      <div>
                        <strong>Backend Unreachable:</strong> {backendError}
                      </div>
                    </div>
                  )}

                  {backendHealth && (
                    <div className="status-box success">
                      <span className="indicator green"></span>
                      <div className="status-details">
                        <div className="status-title">
                          <strong>Status:</strong> {backendHealth.status.toUpperCase()}
                        </div>
                        <div className="meta-grid">
                          <div><strong>Service:</strong> {backendHealth.service}</div>
                          <div><strong>Stage:</strong> {backendHealth.stage}</div>
                          <div><strong>Database:</strong> Connected (PostgreSQL)</div>
                          <div><strong>Pipeline:</strong> Security Events & Metrics</div>
                          <div><strong>Last Checked:</strong> {lastChecked}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </section>
              </div>
            </div>
          )}
        </main>
      )}

      {/* Footer */}
      <footer className="footer">
        <p>AI-Enabled Adaptive Cyber Deception Gateway — Stage 8 End-to-End Security Validation & Evaluation Framework</p>
      </footer>
    </div>
  );
}
