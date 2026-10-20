import React, { useEffect, useState } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Icon from '../ui/Icon';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Onboarding Summary & Contextual Guidance Panel
 * Sticky right-hand overview showing real-time configuration state, security hints, and gateway status.
 */
export default function OnboardingSummary({
  currentStep,
  selectedOrg,
  appData,
  verificationChallenge,
  protectionData,
}) {
  const [gatewayStatus, setGatewayStatus] = useState({ checking: true, healthy: false, details: null });

  useEffect(() => {
    let isMounted = true;
    api.getGatewayHealth()
      .then((res) => {
        if (isMounted) {
          setGatewayStatus({ checking: false, healthy: true, details: res });
        }
      })
      .catch((err) => {
        if (isMounted) {
          setGatewayStatus({ checking: false, healthy: false, details: err.message });
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const securityInsights = {
    1: {
      title: 'Identity & Isolation',
      tip: 'Applications are strictly isolated by organisation tenant. Always specify an explicit FQDN without protocols to ensure proper reverse proxy routing.',
    },
    2: {
      title: 'Ownership Invariant',
      tip: 'DNS TXT verification guarantees you control the target domain, eliminating subdomain takeover vulnerabilities and unauthorized traffic interception.',
    },
    3: {
      title: 'Origin & SSRF Protection',
      tip: 'The gateway validates upstream origins against RFC1918 subnets, cloud metadata IPs (169.254.169.254), and prevents cross-tenant origin hijacking.',
    },
    4: {
      title: 'Deception Calibration',
      tip: 'A sensitivity of 0.70 (70% anomaly score) is the recommended enterprise default. Only high-confidence attacks are diverted to synthetic state graphs.',
    },
    5: {
      title: 'Preflight Verification',
      tip: 'Preflight diagnostics query real-time gateway health and backend state. Origin connectivity is validated server-side during registration.',
    },
    6: {
      title: 'Zero-Downtime Cutover',
      tip: 'Once verified, point your DNS CNAME to the Gateway. The Gateway immediately applies dynamic AI protection and routes benign requests cleanly.',
    },
  };

  const insight = securityInsights[currentStep] || securityInsights[1];

  const isVerified = appData?.verification_status === 'verified';
  const isActivated = appData?.activation_status === 'active';

  return (
    <aside style={{ position: 'sticky', top: '2rem' }}>
      <Card
        style={{
          padding: '1.75rem',
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-medium)',
          boxShadow: '0 12px 32px rgba(0, 0, 0, 0.35)',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Icon name="layers" size={18} color="var(--accent-primary)" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
              Configuration Blueprint
            </h3>
          </div>
          <span
            style={{
              fontSize: '0.72rem',
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-muted)',
              backgroundColor: 'rgba(255, 255, 255, 0.04)',
              padding: '0.2rem 0.5rem',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            Step {currentStep} of 6
          </span>
        </div>

        {/* Selected Organisation */}
        <div
          style={{
            padding: '0.75rem 0.85rem',
            backgroundColor: 'var(--bg-main)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            marginBottom: '1.25rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700 }}>
              Tenant Workspace
            </span>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)' }}>
              {selectedOrg?.name || 'Loading organization...'}
            </div>
          </div>
          <Badge variant="neutral" style={{ fontSize: '0.68rem' }}>
            {selectedOrg?.role || 'owner'}
          </Badge>
        </div>

        {/* Configuration Parameter Rows */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1.5rem' }}>
          {/* App Name */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Display Name</span>
            <span style={{ fontWeight: 600, color: 'var(--text-main)', textAlign: 'right' }}>
              {appData?.displayName || appData?.display_name || <em style={{ color: 'var(--text-dim)' }}>Not specified</em>}
            </span>
          </div>

          {/* Environment */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Environment</span>
            <span style={{ fontWeight: 600, textTransform: 'capitalize', color: 'var(--accent-primary)' }}>
              {appData?.environment || 'production'}
            </span>
          </div>

          {/* Approved Domain */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Approved Domain</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-main)', textAlign: 'right' }}>
              {appData?.approvedDomain || appData?.approved_domain || <em style={{ color: 'var(--text-dim)' }}>Pending</em>}
            </span>
          </div>

          {/* Configured Origin */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Upstream Origin</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-main)', textAlign: 'right', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={appData?.configuredOrigin || appData?.configured_origin}>
              {appData?.configuredOrigin || appData?.configured_origin || <em style={{ color: 'var(--text-dim)' }}>Pending</em>}
            </span>
          </div>

          {/* Divider */}
          <div style={{ height: '1px', backgroundColor: 'var(--border-subtle)', margin: '0.25rem 0' }} />

          {/* Verification Status */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Domain Ownership</span>
            <Badge
              variant={isVerified ? 'success' : 'warning'}
              style={{ fontSize: '0.68rem', padding: '0.15rem 0.5rem' }}
            >
              {isVerified ? 'Verified' : 'Verification Required'}
            </Badge>
          </div>

          {/* Routing Mode */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Routing Mode</span>
            <Badge
              variant={protectionData?.routingMode === 'active' ? 'eyebrow' : 'neutral'}
              style={{ fontSize: '0.68rem', padding: '0.15rem 0.5rem' }}
            >
              {protectionData?.routingMode === 'active' ? 'Active Deception' : 'Shadow Telemetry'}
            </Badge>
          </div>

          {/* Sensitivity */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Deception Sensitivity</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-secondary)' }}>
              {protectionData?.deceptionThreshold !== undefined ? `${Math.round(protectionData.deceptionThreshold * 100)}%` : '70%'}
            </span>
          </div>

          {/* Gateway Activation */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Interception Status</span>
            <Badge
              variant={isActivated ? 'success' : 'neutral'}
              style={{ fontSize: '0.68rem', padding: '0.15rem 0.5rem' }}
            >
              {isActivated ? 'Active' : 'Inactive'}
            </Badge>
          </div>
        </div>

        {/* Contextual Security Insight */}
        <div
          style={{
            padding: '1rem',
            backgroundColor: 'rgba(91, 156, 255, 0.05)',
            border: '1px solid var(--accent-primary-border)',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '1.25rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.35rem' }}>
            <Icon name="shield" size={14} color="var(--accent-primary)" />
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              {insight.title}
            </span>
          </div>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
            {insight.tip}
          </p>
        </div>

        {/* Gateway Health Indicator */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.65rem 0.85rem',
            backgroundColor: 'var(--bg-main)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            fontSize: '0.75rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span
              style={{
                width: '8px',
                height: '8px',
                borderRadius: 'var(--radius-full)',
                backgroundColor: gatewayStatus.healthy ? '#10B981' : '#EF4444',
                boxShadow: gatewayStatus.healthy ? '0 0 6px #10B981' : '0 0 6px #EF4444',
              }}
            />
            <span style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>
              Gateway Engine (:8080)
            </span>
          </div>
          <span style={{ color: gatewayStatus.healthy ? '#10B981' : '#EF4444', fontWeight: 600 }}>
            {gatewayStatus.checking ? 'Probing...' : gatewayStatus.healthy ? 'Online & Healthy' : 'Unreachable'}
          </span>
        </div>
      </Card>
    </aside>
  );
}
