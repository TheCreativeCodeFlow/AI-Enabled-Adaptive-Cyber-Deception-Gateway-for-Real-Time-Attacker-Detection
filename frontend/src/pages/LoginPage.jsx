import React, { useState } from 'react';
import AuthLayout from '../components/layout/AuthLayout';
import Button from '../components/ui/Button';
import Icon from '../components/ui/Icon';
import Card from '../components/ui/Card';
import { api } from '../services/api';
import { auth } from '../services/auth';

/**
 * Cyber Deception Gateway — User Login Screen (Stage 2)
 *
 * Implements real operator authentication against POST /api/auth/login.
 * Follows the Stage 1 design system with two-column responsive layout.
 */
export default function LoginPage({ onNavigate, onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(() => localStorage.getItem('remember_operator') === 'true');

  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Validate form fields
  const validate = () => {
    const newErrors = {};
    const trimmedUser = username.trim();

    if (!trimmedUser) {
      newErrors.username = 'Username or email is required.';
    }

    if (!password) {
      newErrors.password = 'Password is required.';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setServerError(null);

    if (!validate()) {
      return;
    }

    setIsSubmitting(true);

    try {
      const trimmedUser = username.trim();
      const res = await api.login(trimmedUser, password);

      if (res && res.token && res.user) {
        if (rememberMe) {
          localStorage.setItem('remember_operator', 'true');
        } else {
          localStorage.removeItem('remember_operator');
        }

        auth.setSession(res.token, res.user);
        if (onLoginSuccess) {
          onLoginSuccess(res.token, res.user);
        }
        onNavigate('/app');
      } else {
        throw new Error('Authentication succeeded but invalid response received.');
      }
    } catch (err) {
      setServerError(err.message || 'Invalid credentials or unable to reach backend.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickFill = () => {
    setUsername('sec_admin');
    setPassword('SuperSecretAdminPassword123!');
    setErrors({});
    setServerError(null);
  };

  return (
    <AuthLayout onNavigate={onNavigate}>
      <Card
        style={{
          padding: '2.5rem 2.25rem',
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.45)',
          border: '1px solid var(--border-medium)',
        }}
      >
        {/* Card Header */}
        <div style={{ marginBottom: '1.75rem', textAlign: 'left' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <h2
              style={{
                fontSize: '1.65rem',
                fontWeight: 700,
                color: 'var(--text-main)',
                letterSpacing: '-0.02em',
              }}
            >
              Welcome back
            </h2>
            <a
              href="/"
              onClick={(e) => {
                e.preventDefault();
                onNavigate('/');
              }}
              style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}
              className="hover-underline"
            >
              ← Home
            </a>
          </div>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            Sign in to your Cyber Deception Gateway workspace
          </p>
        </div>

        {/* Server Error Alert */}
        {serverError && (
          <div className="alert-box alert-error" role="alert">
            <Icon name="alert-triangle" size={18} color="#EF4444" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
            <div>
              <span style={{ fontWeight: 600, display: 'block' }}>Authentication Error</span>
              <span style={{ fontSize: '0.825rem' }}>{serverError}</span>
            </div>
          </div>
        )}

        {/* Demo Credentials Quick Fill Banner */}
        <div className="demo-creds-card">
          <div>
            <span style={{ fontWeight: 600, color: 'var(--text-main)', display: 'block' }}>
              Evaluation Credentials
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Pre-seeded account: <code style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>sec_admin</code>
            </span>
          </div>
          <button
            type="button"
            className="demo-creds-btn"
            onClick={handleQuickFill}
            aria-label="Auto-fill demo credentials"
          >
            Auto-fill
          </button>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} noValidate>
          {/* Identifier Field */}
          <div className="form-group">
            <label htmlFor="login-username" className="form-label">
              <span>Username or Email</span>
            </label>
            <div className="input-wrapper">
              <input
                id="login-username"
                name="username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  if (errors.username) setErrors({ ...errors, username: null });
                }}
                placeholder="e.g. sec_admin"
                className={`form-input ${errors.username ? 'form-input-error' : ''}`}
                aria-invalid={!!errors.username}
                aria-describedby={errors.username ? 'login-username-error' : undefined}
                disabled={isSubmitting}
                autoFocus
              />
            </div>
            {errors.username && (
              <span id="login-username-error" className="form-error-text" role="alert">
                <Icon name="alert-triangle" size={12} color="#EF4444" />
                {errors.username}
              </span>
            )}
          </div>

          {/* Password Field */}
          <div className="form-group">
            <label htmlFor="login-password" className="form-label">
              <span>Password</span>
            </label>
            <div className="input-wrapper">
              <input
                id="login-password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (errors.password) setErrors({ ...errors, password: null });
                }}
                placeholder="Enter your password"
                className={`form-input input-has-action ${errors.password ? 'form-input-error' : ''}`}
                aria-invalid={!!errors.password}
                aria-describedby={errors.password ? 'login-password-error' : undefined}
                disabled={isSubmitting}
              />
              <button
                type="button"
                className="input-action-btn"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                tabIndex={0}
              >
                <Icon name={showPassword ? 'eye-off' : 'eye'} size={18} />
              </button>
            </div>
            {errors.password && (
              <span id="login-password-error" className="form-error-text" role="alert">
                <Icon name="alert-triangle" size={12} color="#EF4444" />
                {errors.password}
              </span>
            )}
          </div>

          {/* Remember Me Option */}
          <div style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <label className="form-checkbox-row">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="form-checkbox-input"
                disabled={isSubmitting}
              />
              <span>Remember this session</span>
            </label>
          </div>

          {/* Submit Button */}
          <Button
            type="submit"
            variant="primary"
            size="lg"
            style={{ width: '100%', justifyContent: 'center', marginBottom: '1.5rem' }}
            disabled={isSubmitting}
            icon={isSubmitting ? null : <Icon name="arrow-right" size={18} color="#050A14" />}
            iconPosition="right"
          >
            {isSubmitting ? 'Signing in...' : 'Sign In'}
          </Button>

          {/* Registration Link */}
          <div style={{ textAlign: 'center', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Don't have an operator account?{' '}
            <a
              href="/register"
              onClick={(e) => {
                e.preventDefault();
                onNavigate('/register');
              }}
              style={{ color: 'var(--accent-primary)', fontWeight: 600 }}
              className="hover-underline"
            >
              Create workspace
            </a>
          </div>
        </form>
      </Card>
    </AuthLayout>
  );
}
