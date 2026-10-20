import React, { useState } from 'react';
import { IconShield, IconLock, IconArrowRight, IconAlertTriangle } from '../components/Icons';

export default function UserLoginPage({ onNavigate, onLoginSuccess, backendUrl }) {
  const [username, setUsername] = useState('sec_admin');
  const [password, setPassword] = useState('SuperSecretAdminPassword123!');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${backendUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Login failed. Please check your credentials.');
      }

      onLoginSuccess(data.token, data.user, false);
      onNavigate('/app');
    } catch (err) {
      setError(err.message || 'Network error connecting to backend service.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickFill = () => {
    setUsername('sec_admin');
    setPassword('SuperSecretAdminPassword123!');
    setError(null);
  };

  return (
    <div className="auth-page-root">
      <div className="auth-glow-bg"></div>

      <div className="auth-card-wrap">
        {/* Brand Header */}
        <div className="auth-header-block">
          <div className="auth-logo-badge" onClick={() => onNavigate('/')}>
            <IconShield size={28} className="text-cyan-400" />
          </div>
          <h2 className="auth-page-title">Sign In to Your Workspace</h2>
          <p className="auth-page-subtitle">Access your organization's cyber deception gateway console</p>
        </div>

        {/* Login Form */}
        <div className="auth-form-card">
          {error && (
            <div className="auth-error-alert">
              <IconAlertTriangle size={18} className="text-rose-400 shrink-0 mt-0.5" />
              <div className="text-sm text-rose-300">{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="auth-form-body">
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. sec_admin"
                className="form-input"
                required
                autoFocus
              />
            </div>

            <div className="form-group">
              <div className="flex items-center justify-between mb-1">
                <label className="form-label mb-0">Password</label>
                <button
                  type="button"
                  onClick={() => alert('Password reset in local mode: Use existing seeded credentials (sec_admin) or register a new user.')}
                  className="text-xs text-cyan-400 hover:underline bg-transparent border-0 p-0 cursor-pointer"
                >
                  Forgot password?
                </button>
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className="form-input font-mono"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-auth-submit"
            >
              {loading ? (
                <span>Authenticating...</span>
              ) : (
                <>
                  <span>Sign In to Dashboard</span>
                  <IconArrowRight size={16} />
                </>
              )}
            </button>
          </form>

          {/* Quick-fill Demo Box */}
          <div className="auth-demo-box">
            <div className="text-xs text-slate-400 mb-2 font-semibold">Local Testing Credentials:</div>
            <div className="flex items-center justify-between bg-slate-900/90 px-3 py-2 rounded border border-slate-800 text-xs font-mono text-slate-300">
              <span>sec_admin / SuperSecret...</span>
              <button
                type="button"
                onClick={handleQuickFill}
                className="text-cyan-400 hover:text-cyan-300 font-sans font-semibold text-xs bg-transparent border-0 cursor-pointer"
              >
                Auto-Fill
              </button>
            </div>
          </div>

          <div className="auth-footer-links">
            <span className="text-slate-400">Don't have an organization account?</span>{' '}
            <button
              onClick={() => onNavigate('/register')}
              className="text-cyan-400 hover:underline font-semibold bg-transparent border-0 cursor-pointer p-0"
            >
              Register here
            </button>
          </div>
        </div>

        {/* Link to Admin Console */}
        <div className="text-center mt-6">
          <button
            onClick={() => onNavigate('/admin/login')}
            className="text-xs text-slate-400 hover:text-amber-400 inline-flex items-center gap-1.5 transition-colors bg-transparent border-0 cursor-pointer"
          >
            <IconLock size={12} className="text-amber-400" />
            <span>Platform Administrator? Access Operator Control Plane</span>
          </button>
        </div>
      </div>
    </div>
  );
}
