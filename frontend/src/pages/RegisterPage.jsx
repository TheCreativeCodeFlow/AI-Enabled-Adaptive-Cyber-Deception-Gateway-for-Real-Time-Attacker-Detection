import React, { useState } from 'react';
import AuthLayout from '../components/layout/AuthLayout';
import Button from '../components/ui/Button';
import Icon from '../components/ui/Icon';
import Card from '../components/ui/Card';
import { api } from '../services/api';
import { auth } from '../services/auth';

/**
 * Cyber Deception Gateway — Operator Registration Screen (Stage 2)
 *
 * Implements real account registration against POST /api/auth/register,
 * followed by session issuance via POST /api/auth/login and initial workspace setup.
 */
export default function RegisterPage({ onNavigate, onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [orgName, setOrgName] = useState('');

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,32}$/;
  const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // Frontend validation adhering to backend contracts
  const validate = () => {
    const newErrors = {};
    const trimmedUser = username.trim();
    const trimmedEmail = email.trim();

    if (!trimmedUser) {
      newErrors.username = 'Username is required.';
    } else if (!USERNAME_REGEX.test(trimmedUser)) {
      newErrors.username = 'Must be 3-32 characters (letters, numbers, underscores, dashes).';
    }

    if (!trimmedEmail) {
      newErrors.email = 'Work email is required.';
    } else if (!EMAIL_REGEX.test(trimmedEmail)) {
      newErrors.email = 'Please enter a valid email address.';
    }

    if (!password) {
      newErrors.password = 'Password is required.';
    } else if (password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters long.';
    }

    if (!confirmPassword) {
      newErrors.confirmPassword = 'Confirm your password.';
    } else if (confirmPassword !== password) {
      newErrors.confirmPassword = 'Passwords do not match.';
    }

    if (!orgName.trim()) {
      newErrors.orgName = 'Organization workspace name is required.';
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
      const cleanUser = username.trim().toLowerCase();
      const cleanEmail = email.trim().toLowerCase();
      const cleanOrg = orgName.trim();

      // 1. Submit Registration to Backend
      const regRes = await api.register(cleanUser, cleanEmail, password, 'admin');

      if (!regRes || regRes.error) {
        throw new Error(regRes?.message || 'Registration failed.');
      }

      // 2. Authenticate newly created operator
      const loginRes = await api.login(cleanUser, password);

      if (!loginRes || !loginRes.token) {
        throw new Error('Account created, but automatic session creation failed. Please log in manually.');
      }

      const token = loginRes.token;
      const user = loginRes.user;

      // 3. Set session in auth utility
      auth.setSession(token, user);

      // 4. Create initial organization workspace
      if (cleanOrg) {
        try {
          const slug = cleanOrg.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || `org-${Date.now()}`;
          await api.createOrganisation(cleanOrg, slug);
        } catch (orgErr) {
          console.warn('[Register] Initial organization setup warning:', orgErr);
        }
      }

      if (onLoginSuccess) {
        onLoginSuccess(token, user);
      }

      onNavigate('/app');
    } catch (err) {
      setServerError(err.message || 'Registration failed. Please verify your details.');
    } finally {
      setIsSubmitting(false);
    }
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
              Create workspace
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
            Register an operator account to deploy cyber deception protection
          </p>
        </div>

        {/* Server Error Alert */}
        {serverError && (
          <div className="alert-box alert-error" role="alert">
            <Icon name="alert-triangle" size={18} color="#EF4444" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
            <div>
              <span style={{ fontWeight: 600, display: 'block' }}>Registration Error</span>
              <span style={{ fontSize: '0.825rem' }}>{serverError}</span>
            </div>
          </div>
        )}

        {/* Registration Form */}
        <form onSubmit={handleSubmit} noValidate>
          {/* Organization Name */}
          <div className="form-group">
            <label htmlFor="reg-org" className="form-label">
              <span>Organization / Workspace Name</span>
            </label>
            <div className="input-wrapper">
              <input
                id="reg-org"
                name="orgName"
                type="text"
                value={orgName}
                onChange={(e) => {
                  setOrgName(e.target.value);
                  if (errors.orgName) setErrors({ ...errors, orgName: null });
                }}
                placeholder="e.g. Acme Security Team"
                className={`form-input ${errors.orgName ? 'form-input-error' : ''}`}
                aria-invalid={!!errors.orgName}
                aria-describedby={errors.orgName ? 'reg-org-error' : undefined}
                disabled={isSubmitting}
                autoFocus
              />
            </div>
            {errors.orgName && (
              <span id="reg-org-error" className="form-error-text" role="alert">
                <Icon name="alert-triangle" size={12} color="#EF4444" />
                {errors.orgName}
              </span>
            )}
          </div>

          {/* Operator Username */}
          <div className="form-group">
            <label htmlFor="reg-username" className="form-label">
              <span>Operator Username</span>
            </label>
            <div className="input-wrapper">
              <input
                id="reg-username"
                name="username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  if (errors.username) setErrors({ ...errors, username: null });
                }}
                placeholder="e.g. sec_lead_2026"
                className={`form-input ${errors.username ? 'form-input-error' : ''}`}
                aria-invalid={!!errors.username}
                aria-describedby={errors.username ? 'reg-username-error' : undefined}
                disabled={isSubmitting}
              />
            </div>
            {errors.username ? (
              <span id="reg-username-error" className="form-error-text" role="alert">
                <Icon name="alert-triangle" size={12} color="#EF4444" />
                {errors.username}
              </span>
            ) : (
              <span className="form-help-text">3-32 alphanumeric characters, dashes, or underscores.</span>
            )}
          </div>

          {/* Work Email */}
          <div className="form-group">
            <label htmlFor="reg-email" className="form-label">
              <span>Work Email</span>
            </label>
            <div className="input-wrapper">
              <input
                id="reg-email"
                name="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (errors.email) setErrors({ ...errors, email: null });
                }}
                placeholder="operator@company.com"
                className={`form-input ${errors.email ? 'form-input-error' : ''}`}
                aria-invalid={!!errors.email}
                aria-describedby={errors.email ? 'reg-email-error' : undefined}
                disabled={isSubmitting}
              />
            </div>
            {errors.email && (
              <span id="reg-email-error" className="form-error-text" role="alert">
                <Icon name="alert-triangle" size={12} color="#EF4444" />
                {errors.email}
              </span>
            )}
          </div>

          {/* Password & Confirm Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }} className="password-grid">
            {/* Password */}
            <div className="form-group">
              <label htmlFor="reg-password" className="form-label">
                <span>Password</span>
              </label>
              <div className="input-wrapper">
                <input
                  id="reg-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errors.password) setErrors({ ...errors, password: null });
                  }}
                  placeholder="Min 8 characters"
                  className={`form-input input-has-action ${errors.password ? 'form-input-error' : ''}`}
                  aria-invalid={!!errors.password}
                  aria-describedby={errors.password ? 'reg-password-error' : undefined}
                  disabled={isSubmitting}
                />
                <button
                  type="button"
                  className="input-action-btn"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  <Icon name={showPassword ? 'eye-off' : 'eye'} size={16} />
                </button>
              </div>
              {errors.password && (
                <span id="reg-password-error" className="form-error-text" role="alert">
                  <Icon name="alert-triangle" size={12} color="#EF4444" />
                  {errors.password}
                </span>
              )}
            </div>

            {/* Confirm Password */}
            <div className="form-group">
              <label htmlFor="reg-confirm-password" className="form-label">
                <span>Confirm</span>
              </label>
              <div className="input-wrapper">
                <input
                  id="reg-confirm-password"
                  name="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    if (errors.confirmPassword) setErrors({ ...errors, confirmPassword: null });
                  }}
                  placeholder="Re-enter password"
                  className={`form-input input-has-action ${errors.confirmPassword ? 'form-input-error' : ''}`}
                  aria-invalid={!!errors.confirmPassword}
                  aria-describedby={errors.confirmPassword ? 'reg-confirm-error' : undefined}
                  disabled={isSubmitting}
                />
                <button
                  type="button"
                  className="input-action-btn"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  <Icon name={showConfirmPassword ? 'eye-off' : 'eye'} size={16} />
                </button>
              </div>
              {errors.confirmPassword && (
                <span id="reg-confirm-error" className="form-error-text" role="alert">
                  <Icon name="alert-triangle" size={12} color="#EF4444" />
                  {errors.confirmPassword}
                </span>
              )}
            </div>
          </div>

          {/* Submit Button */}
          <Button
            type="submit"
            variant="primary"
            size="lg"
            style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem', marginBottom: '1.5rem' }}
            disabled={isSubmitting}
            icon={isSubmitting ? null : <Icon name="arrow-right" size={18} color="#050A14" />}
            iconPosition="right"
          >
            {isSubmitting ? 'Creating workspace...' : 'Create Workspace'}
          </Button>

          {/* Login Link */}
          <div style={{ textAlign: 'center', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Already registered as an operator?{' '}
            <a
              href="/login"
              onClick={(e) => {
                e.preventDefault();
                onNavigate('/login');
              }}
              style={{ color: 'var(--accent-primary)', fontWeight: 600 }}
              className="hover-underline"
            >
              Sign in
            </a>
          </div>
        </form>
      </Card>

      <style>{`
        @media (max-width: 600px) {
          .password-grid {
            grid-template-columns: 1fr !important;
            gap: 0 !important;
          }
        }
      `}</style>
    </AuthLayout>
  );
}
