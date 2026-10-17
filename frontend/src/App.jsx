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
        <div className="badge">Stage 2: Secure Reverse-Proxy Gateway</div>
        <h1>AI-Enabled Adaptive Cyber Deception Gateway</h1>
        <p className="subtitle">
          Real-Time Attacker Detection & Active Defense Platform
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
                    <div><strong>Upstream:</strong> {gatewayHealth.upstream}</div>
                    <div><strong>Uptime:</strong> {gatewayHealth.uptime ? `${Math.round(gatewayHealth.uptime)}s` : 'N/A'}</div>
                  </div>
                </div>
              </div>
            )}
          </section>

          {/* Backend Health Card */}
          <section className="card health-card">
            <div className="card-header">
              <h2>Backend Health (Port 4000)</h2>
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
              <p>Reverse-proxy traffic interception, SSRF defense & test origin routing.</p>
              <span className="stage-pill">Stage 2: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>backend/</h3>
              </div>
              <p>Express + TypeScript core API and health verification.</p>
              <span className="stage-pill">Stage 1: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>frontend/</h3>
              </div>
              <p>React + Vite operator console and service health monitors.</p>
              <span className="stage-pill">Stage 1: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>infra/</h3>
              </div>
              <p>Docker Compose multi-service orchestration (gateway, test-origin, backend, frontend, postgres).</p>
              <span className="stage-pill">Stage 1-2: Active</span>
            </div>

            <div className="module-item reserved">
              <div className="module-header">
                <span className="dot yellow"></span>
                <h3>detection/</h3>
              </div>
              <p>Python ML service for real-time anomaly detection and threat scoring.</p>
              <span className="stage-pill reserved">Stage 3: Reserved</span>
            </div>

            <div className="module-item reserved">
              <div className="module-header">
                <span className="dot yellow"></span>
                <h3>deception/</h3>
              </div>
              <p>Isolated deception runtime and dynamic honeypots.</p>
              <span className="stage-pill reserved">Stage 4: Reserved</span>
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        <p>AI-Enabled Adaptive Cyber Deception Gateway — Stage 2 Reverse-Proxy Gateway</p>
      </footer>
    </div>
  );
}
