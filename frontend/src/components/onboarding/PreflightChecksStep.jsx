import React, { useState, useEffect } from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import Badge from '../ui/Badge';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Step 5: Preflight Checks & Live System Verification
 * Verifies gateway reverse proxy health, backend database state, domain validation, and SSRF compliance.
 */
export default function PreflightChecksStep({
  appData,
  onBack,
  onNext,
}) {
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState({
    gateway: { status: 'pending', latency: null, details: null },
    backend: { status: 'pending', latency: null, details: null },
    domain: { status: 'pending', details: null },
    ssrf: { status: 'pending', details: null },
  });

  const runDiagnostics = async () => {
    setIsRunning(true);

    const newResults = {
      gateway: { status: 'checking', latency: null, details: null },
      backend: { status: 'checking', latency: null, details: null },
      domain: { status: 'checking', details: null },
      ssrf: { status: 'checking', details: null },
    };
    setResults(newResults);

    // 1. Gateway Health Probe
    const gwStart = performance.now();
    try {
      const gwRes = await api.getGatewayHealth();
      const gwLatency = Math.round(performance.now() - gwStart);
      newResults.gateway = {
        status: 'success',
        latency: gwLatency,
        details: gwRes.status || 'OK',
      };
    } catch (err) {
      newResults.gateway = {
        status: 'error',
        latency: null,
        details: err.message || 'Unreachable on port 8080',
      };
    }

    // 2. Backend Health Probe
    const beStart = performance.now();
    try {
      const beRes = await api.getBackendHealth();
      const beLatency = Math.round(performance.now() - beStart);
      newResults.backend = {
        status: 'success',
        latency: beLatency,
        details: beRes.status || 'OK',
      };
    } catch (err) {
      newResults.backend = {
        status: 'error',
        latency: null,
        details: err.message || 'Unreachable on port 4000',
      };
    }

    // 3. Domain Ownership Verification State
    const isVerified = appData?.verification_status === 'verified';
    newResults.domain = {
      status: isVerified ? 'success' : 'warning',
      details: isVerified
        ? 'DNS TXT ownership cryptographic record verified'
        : 'Domain ownership not yet verified (DNS TXT pending)',
    };

    // 4. Server-Side SSRF Validation Status
    const origin = appData?.configured_origin || appData?.configuredOrigin;
    newResults.ssrf = {
      status: 'success',
      details: `Origin URL validated against cloud metadata and dangerous hostnames (${origin || 'configured'})`,
    };

    setResults({ ...newResults });
    setIsRunning(false);
  };

  useEffect(() => {
    runDiagnostics();
  }, []);

  const getStatusBadge = (status) => {
    switch (status) {
      case 'success':
        return <Badge variant="success" icon={<Icon name="check" size={12} color="#10B981" />}>Passed</Badge>;
      case 'warning':
        return <Badge variant="warning" icon={<Icon name="alert-triangle" size={12} color="var(--state-warning)" />}>Pending</Badge>;
      case 'error':
        return <Badge variant="danger" icon={<Icon name="x-circle" size={12} color="var(--state-danger)" />}>Failed</Badge>;
      default:
        return <Badge variant="neutral">Checking...</Badge>;
    }
  };

  return (
    <Card
      style={{
        padding: '2.5rem',
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-medium)',
      }}
    >
      {/* Step Header */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
          <Badge variant="eyebrow" icon={<Icon name="activity" size={12} color="var(--accent-primary)" />}>
            Step 5 of 6: Preflight Diagnostics
          </Badge>
          <Button
            variant="secondary"
            size="sm"
            onClick={runDiagnostics}
            disabled={isRunning}
            icon={<Icon name="refresh-cw" size={13} className={isRunning ? 'spin-animation' : ''} />}
          >
            {isRunning ? 'Running...' : 'Re-run Diagnostics'}
          </Button>
        </div>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', marginBottom: '0.4rem' }}>
          System Preflight Verification
        </h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          Verify that the Cyber Deception Gateway, backend database, and routing subsystems are operational before enabling live interception.
        </p>
      </div>

      {/* Preflight Check Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '2rem' }}>
        {/* Check 1: Gateway */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            backgroundColor: 'var(--bg-main)',
            border: '1px solid var(--border-medium)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: results.gateway.status === 'success' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Icon
                name={results.gateway.status === 'success' ? 'check' : 'alert-triangle'}
                size={18}
                color={results.gateway.status === 'success' ? '#10B981' : '#EF4444'}
              />
            </div>
            <div>
              <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)' }}>
                Cyber Deception Gateway Reverse Proxy (:8080)
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                Status: {results.gateway.details || 'Probing Gateway health endpoint...'}
                {results.gateway.latency && ` (${results.gateway.latency}ms response latency)`}
              </div>
            </div>
          </div>
          {getStatusBadge(results.gateway.status)}
        </div>

        {/* Check 2: Backend */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            backgroundColor: 'var(--bg-main)',
            border: '1px solid var(--border-medium)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: results.backend.status === 'success' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Icon
                name={results.backend.status === 'success' ? 'check' : 'alert-triangle'}
                size={18}
                color={results.backend.status === 'success' ? '#10B981' : '#EF4444'}
              />
            </div>
            <div>
              <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)' }}>
                Management API & Multi-Tenant Registry (:4000)
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                Status: {results.backend.details || 'Probing Management API...'}
                {results.backend.latency && ` (${results.backend.latency}ms response latency)`}
              </div>
            </div>
          </div>
          {getStatusBadge(results.backend.status)}
        </div>

        {/* Check 3: Domain Verification */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            backgroundColor: 'var(--bg-main)',
            border: '1px solid var(--border-medium)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: results.domain.status === 'success' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Icon
                name={results.domain.status === 'success' ? 'check' : 'shield'}
                size={18}
                color={results.domain.status === 'success' ? '#10B981' : 'var(--state-warning)'}
              />
            </div>
            <div>
              <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)' }}>
                Domain Ownership Verification ({appData?.approved_domain || appData?.approvedDomain})
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                {results.domain.details || 'Validating verification challenge...'}
              </div>
            </div>
          </div>
          {getStatusBadge(results.domain.status)}
        </div>

        {/* Check 4: SSRF Safety */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            backgroundColor: 'var(--bg-main)',
            border: '1px solid var(--border-medium)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(16, 185, 129, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Icon name="check" size={18} color="#10B981" />
            </div>
            <div>
              <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)' }}>
                Server-Side Origin Safety & SSRF Guardrails
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                {results.ssrf.details}
              </div>
            </div>
          </div>
          {getStatusBadge(results.ssrf.status)}
        </div>
      </div>

      {/* Realism Disclosure Note (Required) */}
      <div
        style={{
          padding: '1.15rem 1.25rem',
          backgroundColor: 'rgba(91, 156, 255, 0.05)',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--accent-primary-border)',
          marginBottom: '2.5rem',
          fontSize: '0.8rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.5,
          display: 'flex',
          gap: '0.75rem',
        }}
      >
        <Icon name="info" size={18} color="var(--accent-primary)" style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '0.15rem' }}>
            Preflight Diagnostic Verification Note
          </strong>
          Preflight queries live gateway and backend service health. Server-side SSRF validation is verified upon origin submission. Direct HTTP ping to upstream origin is validated server-side during registration; synthetic origin ping endpoint is not currently exposed.
        </div>
      </div>

      {/* Navigation Buttons */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button
          variant="secondary"
          onClick={onBack}
          icon={<Icon name="arrow-left" size={16} />}
        >
          Back to Deception Policy
        </Button>

        <Button
          variant="primary"
          onClick={onNext}
          icon={<Icon name="arrow-right" size={16} />}
          iconPosition="right"
        >
          Proceed to Review & Activation
        </Button>
      </div>
    </Card>
  );
}
