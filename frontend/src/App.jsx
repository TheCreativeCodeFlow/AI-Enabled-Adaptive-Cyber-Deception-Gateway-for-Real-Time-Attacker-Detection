import React, { useState, useEffect } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:4000';

export default function App() {
  const [healthData, setHealthData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);

  const fetchHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${BACKEND_URL}/health`);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      const data = await res.json();
      setHealthData(data);
      setLastChecked(new Date().toLocaleTimeString());
    } catch (err) {
      setError(err.message || 'Failed to connect to backend service.');
      setHealthData(null);
      setLastChecked(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="container">
      <header className="header">
        <div className="badge">Stage 1: Foundation & Architecture</div>
        <h1>AI-Enabled Adaptive Cyber Deception Gateway</h1>
        <p className="subtitle">
          Real-Time Attacker Detection & Active Defense Platform
        </p>
      </header>

      <main className="content">
        <section className="card health-card">
          <div className="card-header">
            <h2>Backend Health Status</h2>
            <button className="btn" onClick={fetchHealth} disabled={loading}>
              {loading ? 'Checking...' : 'Refresh Status'}
            </button>
          </div>

          <div className="endpoint-info">
            Target Endpoint: <code>{BACKEND_URL}/health</code>
          </div>

          {loading && !healthData && (
            <p className="status-text muted">Connecting to backend health check...</p>
          )}

          {error && (
            <div className="status-box error">
              <span className="indicator red"></span>
              <div>
                <strong>Backend Unreachable:</strong> {error}
                <div className="sub-note">Ensure the backend service is running on port 4000.</div>
              </div>
            </div>
          )}

          {healthData && (
            <div className="status-box success">
              <span className="indicator green"></span>
              <div className="status-details">
                <div className="status-title">
                  <strong>Status:</strong> {healthData.status.toUpperCase()}
                </div>
                <div className="meta-grid">
                  <div><strong>Service:</strong> {healthData.service}</div>
                  <div><strong>Stage:</strong> {healthData.stage}</div>
                  <div><strong>Uptime:</strong> {healthData.uptime ? `${Math.round(healthData.uptime)}s` : 'N/A'}</div>
                  <div><strong>Last Checked:</strong> {lastChecked}</div>
                </div>
              </div>
            </div>
          )}
        </section>

        <section className="card">
          <h2>Architecture Modules & Roadmap Status</h2>
          <p className="section-desc">
            Component readiness as defined in <code>docs/architecture.md</code>. Future modules are reserved and uninitialized.
          </p>

          <div className="modules-grid">
            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>frontend/</h3>
              </div>
              <p>React + Vite landing page and dashboard foundation.</p>
              <span className="stage-pill">Stage 1: Active</span>
            </div>

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>backend/</h3>
              </div>
              <p>Express + TypeScript core API and health verification.</p>
              <span className="stage-pill">Stage 1: Active</span>
            </div>

            <div className="module-item reserved">
              <div className="module-header">
                <span className="dot yellow"></span>
                <h3>gateway/</h3>
              </div>
              <p>Reverse-proxy traffic interception and policy routing.</p>
              <span className="stage-pill reserved">Stage 2: Reserved</span>
            </div>

            <div className="module-item reserved">
              <div className="module-header">
                <span className="dot yellow"></span>
                <h3>detection/</h3>
              </div>
              <p>Python ML service for real-time anomaly detection.</p>
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

            <div className="module-item active">
              <div className="module-header">
                <span className="dot green"></span>
                <h3>infra/</h3>
              </div>
              <p>Docker Compose local development and service orchestration.</p>
              <span className="stage-pill">Stage 1: Active</span>
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        <p>AI-Enabled Adaptive Cyber Deception Gateway — Stage 1 Foundation</p>
      </footer>
    </div>
  );
}
