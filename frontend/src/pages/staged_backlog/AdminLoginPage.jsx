import React, { useState } from 'react';
import { IconShield, IconLock, IconAlertTriangle, IconArrowRight, IconTerminal } from '../components/Icons';

export default function AdminLoginPage({ onNavigate, onLoginSuccess, backendUrl }) {
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
        throw new Error(data.message || 'Authentication failed.');
      }

      // CRITICAL SECURITY ENFORCEMENT: Only 'admin' role has platform-wide operator access
      if (data.user?.role !== 'admin') {
        throw new Error(
          `Access Denied: Account "${data.user?.username}" has role "${data.user?.role}". Platform Administrator console requires "admin" privilege.`
        );
      }

      onLoginSuccess(data.token, data.user, true);
      onNavigate('/admin');
    } catch (err) {
      setError(err.message || 'Network error connecting to authentication service.');
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
    <div className="admin-login-page-root">
      <div className="admin-glow-bg"></div>

      <div className="auth-card-wrap">
        {/* Administrator Badge Header */}
        <div className="auth-header-block">
          <div className="admin-logo-badge" onClick={() => onNavigate('/')}>
            <IconLock size={28} className="text-amber-400" />
          </div>
          <div className="admin-restricted-pill">
            <span className="live-dot red"></span>
            <span>Platform Operator Control Plane — Restricted</span>
          </div>
          <h2 className="auth-page-title text-slate-100">Administrator Sign In</h2>
          <p className="auth-page-subtitle text-slate-400">
            Cross-tenant cluster management, infrastructure telemetry, and emergency controls
          </p>
        </div>

        {/* Login Form */}
        <div className="admin-form-card">
          {error && (
            <div className="admin-error-alert">
              <IconAlertTriangle size={18} className="text-rose-400 shrink-0 mt-0.5" />
              <div className="text-sm text-rose-300">{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="auth-form-body">
            <div className="form-group">
              <label className="form-label text-slate-300">Operator Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. sec_admin"
                className="form-input admin-input"
                required
                autoFocus
              />
            </div>

            <div className="form-group">
              <label className="form-label text-slate-300">Master Operator Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Master password"
                className="form-input admin-input font-mono"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-admin-submit"
            >
              {loading ? (
                <span>Validating Security Privileges...</span>
              ) : (
                <>
                  <span>Enter Control Plane</span>
                  <IconArrowRight size={16} />
                </>
              )}
            </button>
          </form>

          {/* Quick-fill Demo Box */}
          <div className="auth-demo-box border-amber-900/40 bg-amber-950/20">
            <div className="text-xs text-amber-300/80 mb-2 font-semibold">Configured Master Admin:</div>
            <div className="flex items-center justify-between bg-black/60 px-3 py-2 rounded border border-amber-800/40 text-xs font-mono text-amber-200">
              <span>sec_admin / SuperSecret...</span>
              <button
                type="button"
                onClick={handleQuickFill}
                className="text-amber-400 hover:text-amber-300 font-sans font-semibold text-xs bg-transparent border-0 cursor-pointer"
              >
                Auto-Fill
              </button>
            </div>
          </div>

          <div className="audit-notice-box">
            <IconTerminal size={14} className="text-amber-400/80 shrink-0" />
            <span className="text-[11px] text-slate-400">
              Audit Invariant: Every operator authentication event is immutably logged to the PostgreSQL audit log table with client IP attribution.
            </span>
          </div>

          <div className="auth-footer-links border-t border-slate-800/60 pt-4 mt-4">
            <button
              onClick={() => onNavigate('/login')}
              className="text-xs text-slate-400 hover:text-slate-200 bg-transparent border-0 cursor-pointer p-0"
            >
              ← Return to Standard Organization Sign In
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
