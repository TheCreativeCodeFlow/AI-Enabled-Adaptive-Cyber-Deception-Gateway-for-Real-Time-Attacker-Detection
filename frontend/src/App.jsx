import React, { useState, useEffect } from 'react';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import OnboardingPage from './pages/OnboardingPage';
import DashboardPage from './pages/DashboardPage';
import ProtectedWorkspacePlaceholder from './pages/ProtectedWorkspacePlaceholder';
import { auth } from './services/auth';
import { api } from './services/api';

/**
 * Cyber Deception Gateway — Application Router (Stage 2)
 *
 * Implements:
 * - Public Landing Page (/)
 * - User Login (/login)
 * - User Registration (/register)
 * - Protected Workspace (/app)
 * - Role-Guarded Platform Administration (/admin)
 * - Automatic session synchronization and route guards
 */
export default function App() {
  const [currentPath, setCurrentPath] = useState(() => window.location.pathname || '/');
  const [token, setToken] = useState(() => auth.getToken());
  const [operator, setOperator] = useState(() => auth.getOperator());

  // Listen to browser popstate (back/forward)
  useEffect(() => {
    const handlePopState = () => {
      setCurrentPath(window.location.pathname || '/');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Verify active session validity with backend on mount
  useEffect(() => {
    if (token) {
      api.getCurrentOperator()
        .then((data) => {
          if (data && data.operator) {
            setOperator(data.operator);
            auth.setSession(token, data.operator);
          }
        })
        .catch(() => {
          // Token expired or invalid
          auth.clearSession();
          setToken('');
          setOperator(null);
        });
    }
  }, []);

  const navigate = (path) => {
    if (window.location.pathname !== path) {
      window.history.pushState(null, '', path);
    }
    setCurrentPath(path);
    window.scrollTo(0, 0);
  };

  const handleLoginSuccess = (newToken, newOperator) => {
    setToken(newToken);
    setOperator(newOperator);
    auth.setSession(newToken, newOperator);
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch (err) {
      // Ignore network errors on logout
    }
    auth.clearSession();
    setToken('');
    setOperator(null);
    navigate('/login');
  };

  // 1. Landing Page
  if (currentPath === '/' || currentPath === '') {
    return <LandingPage onNavigate={navigate} />;
  }

  // 2. User Login Page (/login)
  if (currentPath === '/login') {
    if (token && operator) {
      navigate('/app');
      return null;
    }
    return (
      <LoginPage
        onNavigate={navigate}
        onLoginSuccess={handleLoginSuccess}
      />
    );
  }

  // 3. User Registration Page (/register)
  if (currentPath === '/register') {
    if (token && operator) {
      navigate('/app');
      return null;
    }
    return (
      <RegisterPage
        onNavigate={navigate}
        onLoginSuccess={handleLoginSuccess}
      />
    );
  }

  // 4. Application Onboarding Wizard (/app/onboard)
  if (currentPath === '/app/onboard' || currentPath.startsWith('/app/onboard')) {
    if (!token || !operator) {
      navigate('/login');
      return null;
    }
    return (
      <OnboardingPage
        operator={operator}
        onNavigate={navigate}
        onLogout={handleLogout}
      />
    );
  }

  // 5. Tenant Operations Dashboard (/app, /app/applications, /app/events)
  if (currentPath.startsWith('/app')) {
    if (!token || !operator) {
      navigate('/login');
      return null;
    }
    const initialView =
      currentPath === '/app/applications'
        ? 'applications'
        : currentPath === '/app/events'
        ? 'events'
        : 'overview';
    return (
      <DashboardPage
        operator={operator}
        onNavigate={navigate}
        onLogout={handleLogout}
        initialView={initialView}
      />
    );
  }

  // 5. Protected Platform Administrator Console (/admin)
  if (currentPath.startsWith('/admin')) {
    if (!token || !operator) {
      navigate('/login');
      return null;
    }

    // Role Guard: Only admins can view admin routes
    if (operator.role !== 'admin') {
      return (
        <div
          style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2rem',
            backgroundColor: 'var(--bg-main)',
          }}
        >
          <div
            style={{
              maxWidth: '480px',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-medium)',
              borderRadius: 'var(--radius-lg)',
              padding: '3rem 2.5rem',
              textAlign: 'center',
            }}
          >
            <span
              style={{
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                color: 'var(--state-danger)',
                backgroundColor: 'var(--state-danger-subtle)',
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                display: 'inline-block',
                marginBottom: '1rem',
                fontWeight: 700,
                textTransform: 'uppercase',
              }}
            >
              403 Forbidden
            </span>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.75rem' }}>
              Access Denied
            </h2>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '2rem' }}>
              Your operator account (<code style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>{operator.username}</code>) is assigned the role <code style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>{operator.role}</code> and does not possess platform administrative authorization.
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem' }}>
              <button
                type="button"
                onClick={() => navigate('/app')}
                className="btn btn-primary"
              >
                Go to Organization Workspace
              </button>
            </div>
          </div>
        </div>
      );
    }

    return (
      <ProtectedWorkspacePlaceholder
        operator={operator}
        onNavigate={navigate}
        onLogout={handleLogout}
        title="Platform Administrator Console"
        subtitle="Cross-Tenant Application Directory & Operator Access Control"
        isAdminView={true}
      />
    );
  }

  // 6. 404 Fallback
  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '2rem',
        backgroundColor: 'var(--bg-main)',
        textAlign: 'center',
      }}
    >
      <div
        style={{
          maxWidth: '460px',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-medium)',
          borderRadius: 'var(--radius-lg)',
          padding: '3rem 2rem',
        }}
      >
        <span
          style={{
            fontSize: '3rem',
            fontFamily: 'var(--font-mono)',
            fontWeight: 800,
            color: 'var(--accent-primary)',
            display: 'block',
            marginBottom: '0.5rem',
          }}
        >
          404
        </span>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.75rem' }}>
          Page Not Found
        </h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: '1.75rem' }}>
          The requested path does not exist on this gateway instance.
        </p>
        <button
          type="button"
          onClick={() => navigate('/')}
          className="btn btn-primary"
        >
          Return to Landing Page
        </button>
      </div>
    </div>
  );
}
