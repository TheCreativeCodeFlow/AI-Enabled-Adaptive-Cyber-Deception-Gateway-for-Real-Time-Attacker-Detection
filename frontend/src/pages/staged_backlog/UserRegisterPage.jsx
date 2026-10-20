import React, { useState } from 'react';
import { IconShield, IconArrowRight, IconAlertTriangle, IconCheckCircle } from '../components/Icons';

export default function UserRegisterPage({ onNavigate, onLoginSuccess, backendUrl }) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  const [role, setRole] = useState('admin');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    // Validation
    if (username.trim().length < 3) {
      setError('Username must be at least 3 characters.');
      setLoading(false);
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      setLoading(false);
      return;
    }
    if (!orgName.trim()) {
      setError('Organisation name is required.');
      setLoading(false);
      return;
    }

    try {
      // 1. Register operator account
      const regRes = await fetch(`${backendUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          email: email.trim(),
          password,
          role,
        }),
      });

      const regData = await regRes.json();
      if (!regRes.ok) {
        throw new Error(regData.message || 'Registration failed.');
      }

      // 2. Automatically log in to get session JWT
      const loginRes = await fetch(`${backendUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          password,
        }),
      });

      const loginData = await loginRes.json();
      if (!loginRes.ok) {
        throw new Error('Account created, but automatic sign-in failed. Please log in manually.');
      }

      const token = loginData.token;
      const user = loginData.user;

      // 3. Create initial organization
      const slug = orgName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      const orgRes = await fetch(`${backendUrl}/api/orgs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: orgName.trim(),
          slug,
          description: `Primary workspace for ${orgName.trim()}`,
        }),
      });

      if (!orgRes.ok) {
        const orgErr = await orgRes.json();
        console.warn('Initial org creation warning:', orgErr);
      }

      onLoginSuccess(token, user, false);
      onNavigate('/app');
    } catch (err) {
      setError(err.message || 'Error occurred during registration.');
    } finally {
      setLoading(false);
    }
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
          <h2 className="auth-page-title">Register Your Organization</h2>
          <p className="auth-page-subtitle">Deploy real-time cyber deception to defend your web assets</p>
        </div>

        {/* Register Form */}
        <div className="auth-form-card">
          {error && (
            <div className="auth-error-alert">
              <IconAlertTriangle size={18} className="text-rose-400 shrink-0 mt-0.5" />
              <div className="text-sm text-rose-300">{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="auth-form-body">
            <div className="form-group">
              <label className="form-label">Organization Name</label>
              <input
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="e.g. Acme Cyber Systems"
                className="form-input"
                required
                autoFocus
              />
              <span className="text-[11px] text-slate-500 mt-1 block">Your team's isolated multi-tenant workspace</span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="form-group">
                <label className="form-label">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. alex_lead"
                  className="form-input"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Role</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="form-input"
                >
                  <option value="admin">Admin (Full Control)</option>
                  <option value="analyst">Security Analyst</option>
                </select>
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Work Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="alex@acmecyber.com"
                className="form-input"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Master Password (min 8 chars)</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Strong password"
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
                <span>Creating Workspace...</span>
              ) : (
                <>
                  <span>Create Workspace &amp; Continue</span>
                  <IconArrowRight size={16} />
                </>
              )}
            </button>
          </form>

          <div className="auth-footer-links">
            <span className="text-slate-400">Already registered?</span>{' '}
            <button
              onClick={() => onNavigate('/login')}
              className="text-cyan-400 hover:underline font-semibold bg-transparent border-0 cursor-pointer p-0"
            >
              Sign In
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
