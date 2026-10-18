import React, { useState, useEffect } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:4000';
const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8080';

export default function App() {
  const [backendHealth, setBackendHealth] = useState(null);
  const [gatewayHealth, setGatewayHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [backendError, setBackendError] = useState(null);
  const [gatewayError, setGatewayError] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);

  const fetchAllHealth = async () => {
    setLoading(true);
    setBackendError(null);
    setGatewayError(null);

    // Fetch backend health
    try {
      const res = await fetch(`${BACKEND_URL}/health`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const data = await res.json();
      setBackendHealth(data);
    } catch (err) {
      setBackendError(err.message || 'Failed to connect to backend service.');
      setBackendHealth(null);
    }

    // Fetch gateway health
    try {
      const res = await fetch(`${GATEWAY_URL}/health`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const data = await res.json();
      setGatewayHealth(data);
    } catch (err) {
      setGatewayError(err.message || 'Failed to connect to gateway service.');
      setGatewayHealth(null);
    }

    setLastChecked(new Date().toLocaleTimeString());
    setLoading(false);
  };

  useEffect(() => {
    fetchAllHealth();
  }, []);

  return (
    <div className="container">
      <header className="header">
        <div className="badge">Stage 6: Security Hardening & Operator Authentication</div>
        <h1>AI-Enabled Adaptive Cyber Deception Gateway</h1>
        <p className="subtitle">
          Real-Time Attacker Detection, Policy-Controlled Traffic Diversion & Zero-Leak Deception Defense
        </p>
      </header>

      <main className="content">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
          {/* Gateway Health Card */}
          <section className="card health-card">
            <div className="card-header">
              <h2>Gateway Health (Port 8080)</h2>
              <button className="btn" onClick={fetchAllHealth} disabled={loading}>
                {loading ? 'Checking...' : 'Refresh'}
              </button>
            </div>
            <div className="endpoint-info">
              Target: <code>{GATEWAY_URL}/health</code>
            </div>

            {loading && !gatewayHealth && (
              <p className="status-text muted">Connecting to gateway health check...</p>
            )}

            {gatewayError && (
              <div className="status-box error">
                <span className="indicator red"></span>
                <div>
                  <strong>Gateway Unreachable:</strong> {gatewayError}
                  <div className="sub-note">Ensure the gateway container is running on port 8080.</div>
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
                    <div><strong>Failure Policy:</strong> {gatewayHealth.deceptionFailurePolicy?.toUpperCase() || 'QUARANTINE'}</div>
                    <div><strong>Operator Auth:</strong> Enforced (RBAC)</div>
                    <div><strong>Score Threshold:</strong> {gatewayHealth.deceptionThreshold ?? '0.70'}</div>
                    <div><strong>Uptime:</strong> {gatewayHealth.uptime ? `${Math.round(gatewayHealth.uptime)}s` : 'N/A'}</div>
                    <div><strong>Last Checked:</strong> {lastChecked}</div>
                  </div>
                </div>
              </div>
            )}
          </section>

          {/* Backend Health Card */}
          <section className="card health-card">
            <div className="card-header">
              <h2>Backend & Auth (Port 4000)</h2>
            </div>
            <div className="endpoint-info">
              Target: <code>{BACKEND_URL}/health</code>
            </div>

            {loading && !backendHealth && (
              <p className="status-text muted">Connecting to backend health check...</p>
            )}

            {backendError && (
              <div className="status-box error">
                <span className="indicator red"></span>
                <div>
                  <strong>Backend Unreachable:</strong> {backendError}
                  <div className="sub-note">Ensure the backend container is running on port 4000.</div>
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
                    <div><strong>Database:</strong> {backendHealth.database?.status || 'Connected'}</div>
                    <div><strong>Security Model:</strong> Bcrypt (12 rounds) + JWT</div>
                    <div><strong>RBAC Roles:</strong> Admin & Analyst</div>
                    <div><strong>Uptime:</strong> {backendHealth.uptime ? `${Math.round(backendHealth.uptime)}s` : 'N/A'}</div>
                    <div><strong>Last Checked:</strong> {lastChecked}</div>
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>

        {/* Modules & Roadmap Card */}
        <section className="card">
          <h2>Architecture Modules & Roadmap Status</h2>
          <p className="section-desc">
            Component readiness as defined in <code>docs/architecture.md</code>.
          </p>

          <div className="modules-grid">
            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>gateway/</h3>
              </div>
              <p>Reverse proxy with operator RBAC, session fixation protection, and zero-leak deception quarantine.</p>
              <span className="stage-pill">Stage 2-6: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>detection/</h3>
              </div>
              <p>Python FastAPI ML engine with dual deterministic & scikit-learn anomaly scoring.</p>
              <span className="stage-pill">Stage 3: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>deception/</h3>
              </div>
              <p>Isolated cyber deception runtime with Deception State Graph (DSG), session isolation & synthetic APIs.</p>
              <span className="stage-pill">Stage 4-6: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>backend/</h3>
              </div>
              <p>PostgreSQL-backed operator authentication, bcrypt password hashing, JWT sessions, and audit logging.</p>
              <span className="stage-pill">Stage 1 & 6: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>frontend/</h3>
              </div>
              <p>React + Vite operator console, health telemetry monitors, and security status visualization.</p>
              <span className="stage-pill">Stage 1-6: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>infra/</h3>
              </div>
              <p>Docker Compose orchestration with strictly internal deception network and isolated PostgreSQL.</p>
              <span className="stage-pill">Stage 1-6: Active</span>
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        <p>AI-Enabled Adaptive Cyber Deception Gateway — Stage 6 Security Hardening & Operator Authentication</p>
      </footer>
    </div>
  );
}
