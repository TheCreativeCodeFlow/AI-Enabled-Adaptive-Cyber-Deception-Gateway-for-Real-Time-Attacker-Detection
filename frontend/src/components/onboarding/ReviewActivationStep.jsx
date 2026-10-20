import React, { useState } from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import Badge from '../ui/Badge';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Step 6: Review & Gateway Activation
 * Displays complete blueprint, enforces domain verification safety gate, triggers activation, and provides CNAME cutover instructions.
 */
export default function ReviewActivationStep({
  orgId,
  appData,
  protectionData,
  onAppUpdated,
  onBack,
  onGoToStep,
  onFinish,
}) {
  const [isActivating, setIsActivating] = useState(false);
  const [isDisabling, setIsDisabling] = useState(false);
  const [copiedField, setCopiedField] = useState('');
  const [activationError, setActivationError] = useState('');
  const [activationSuccess, setActivationSuccess] = useState('');

  const isVerified = appData?.verification_status === 'verified';
  const isActive = appData?.activation_status === 'active';

  const domain = appData?.approvedDomain || appData?.approved_domain || 'example.com';
  const origin = appData?.configuredOrigin || appData?.configured_origin || 'http://localhost:5000';
  const cnameTarget = window.location.hostname === 'localhost' ? 'localhost:8080' : 'gateway.deception.local';

  const handleCopy = (field, text) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(''), 2000);
  };

  const handleActivate = async () => {
    setActivationError('');
    setActivationSuccess('');
    setIsActivating(true);

    try {
      const res = await api.activateApplication(orgId, appData.id);
      onAppUpdated(res.application);
      setActivationSuccess('Gateway interception successfully activated! Real-time AI deception routing is live.');
    } catch (err) {
      setActivationError(err.message || 'Failed to activate application interception.');
    } finally {
      setIsActivating(false);
    }
  };

  const handleDisable = async () => {
    setActivationError('');
    setActivationSuccess('');
    setIsDisabling(true);

    try {
      const res = await api.disableApplication(orgId, appData.id);
      onAppUpdated(res.application);
      setActivationSuccess('Gateway interception has been disabled. Traffic is no longer intercepted.');
    } catch (err) {
      setActivationError(err.message || 'Failed to disable application interception.');
    } finally {
      setIsDisabling(false);
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
          <Badge
            variant={isActive ? 'success' : isVerified ? 'eyebrow' : 'warning'}
            icon={<Icon name={isActive ? 'zap' : isVerified ? 'check-circle' : 'alert-triangle'} size={12} color={isActive ? '#10B981' : isVerified ? 'var(--accent-primary)' : 'var(--state-warning)'} />}
          >
            {isActive ? 'Interception Active' : 'Step 6 of 6: Review & Activate'}
          </Badge>
          <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
            App ID: {appData?.id ? `${appData.id.slice(0, 8)}...` : 'Pending'}
          </span>
        </div>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', marginBottom: '0.4rem' }}>
          Configuration Review & Activation
        </h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          Confirm your application parameters, activate gateway interception, and configure DNS CNAME routing.
        </p>
      </div>

      {activationSuccess && (
        <div className="alert-box alert-success" style={{ marginBottom: '1.75rem' }}>
          <Icon name="check-circle" size={20} color="#10B981" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>{activationSuccess}</div>
        </div>
      )}

      {activationError && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.75rem' }}>
          <Icon name="alert-triangle" size={20} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>Activation Guard Rejection: </strong>
            {activationError}
          </div>
        </div>
      )}

      {/* Domain Verification Safety Gate Banner */}
      {!isVerified && (
        <div
          style={{
            padding: '1.25rem',
            backgroundColor: 'rgba(245, 158, 11, 0.08)',
            border: '1px solid rgba(245, 158, 11, 0.35)',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '2rem',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.75rem',
          }}
        >
          <Icon name="alert-triangle" size={20} color="var(--state-warning)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div style={{ flexGrow: 1 }}>
            <strong style={{ fontSize: '0.9rem', color: 'var(--state-warning)', display: 'block', marginBottom: '0.2rem' }}>
              Gateway Activation Locked (Domain Ownership Unverified)
            </strong>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              The Gateway security invariant strictly forbids activating traffic interception for unverified domains. Return to Step 2 to verify your DNS TXT record before proceeding.
            </p>
            <button
              type="button"
              onClick={() => onGoToStep(2)}
              className="btn-subtle"
              style={{
                marginTop: '0.5rem',
                padding: '0.3rem 0.6rem',
                fontSize: '0.78rem',
                fontWeight: 600,
                color: 'var(--accent-primary)',
                border: '1px solid var(--accent-primary-border)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              Go to Step 2: Domain Verification ➔
            </button>
          </div>
        </div>
      )}

      {/* Summary Table */}
      <div
        style={{
          backgroundColor: 'var(--bg-main)',
          border: '1px solid var(--border-medium)',
          borderRadius: 'var(--radius-sm)',
          overflow: 'hidden',
          marginBottom: '2rem',
        }}
      >
        <div style={{ padding: '1rem 1.25rem', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-subtle)', fontWeight: 700, fontSize: '0.85rem', color: 'var(--text-main)' }}>
          Deployment Blueprint Summary
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)' }}>
          <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-subtle)', borderRight: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>Application Name</span>
            <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-main)' }}>{appData?.displayName || appData?.display_name}</span>
          </div>

          <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>Environment</span>
            <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--accent-primary)', textTransform: 'capitalize' }}>{appData?.environment}</span>
          </div>

          <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-subtle)', borderRight: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>Approved Public FQDN</span>
            <span style={{ fontSize: '0.825rem', fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>{domain}</span>
          </div>

          <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>Configured Origin</span>
            <span style={{ fontSize: '0.825rem', fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>{origin}</span>
          </div>

          <div style={{ padding: '0.85rem 1.25rem', borderRight: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>Routing Mode & Sensitivity</span>
            <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-main)' }}>
              {protectionData?.routingMode === 'active' ? 'Active Deception' : 'Shadow Telemetry'} (Threshold: {protectionData?.deceptionThreshold ? `${Math.round(protectionData.deceptionThreshold * 100)}%` : '70%'})
            </span>
          </div>

          <div style={{ padding: '0.85rem 1.25rem' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>Domain Ownership</span>
            <span style={{ fontSize: '0.875rem', fontWeight: 600, color: isVerified ? '#10B981' : 'var(--state-warning)' }}>
              {isVerified ? 'Cryptographically Verified' : 'Unverified (Pending TXT)'}
            </span>
          </div>
        </div>
      </div>

      {/* Activation Action Panel */}
      <div
        style={{
          padding: '1.75rem',
          backgroundColor: isActive ? 'rgba(16, 185, 129, 0.06)' : 'rgba(91, 156, 255, 0.05)',
          border: `1px solid ${isActive ? 'rgba(16, 185, 129, 0.35)' : 'var(--accent-primary-border)'}`,
          borderRadius: 'var(--radius-sm)',
          marginBottom: '2rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.2rem' }}>
            {isActive ? 'Gateway Interception is Active' : 'Activate Live Traffic Interception'}
          </div>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', margin: 0, maxWidth: '520px', lineHeight: 1.5 }}>
            {isActive
              ? 'The gateway is actively inspecting incoming traffic and dynamically routing attackers into synthetic environments.'
              : 'Enables the gateway reverse proxy rules in PostgreSQL and mounts adaptive deception routing for this application.'}
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          {isActive ? (
            <Button
              variant="secondary"
              onClick={handleDisable}
              disabled={isDisabling}
              icon={<Icon name="x" size={16} />}
              style={{ color: 'var(--state-danger)' }}
            >
              {isDisabling ? 'Disabling...' : 'Disable Interception'}
            </Button>
          ) : (
            <Button
              variant="primary"
              size="lg"
              onClick={handleActivate}
              disabled={!isVerified || isActivating}
              icon={isActivating ? <Icon name="refresh-cw" size={16} className="spin-animation" /> : <Icon name="zap" size={16} />}
            >
              {isActivating ? 'Activating Gateway...' : 'Activate Gateway Interception'}
            </Button>
          )}
        </div>
      </div>

      {/* DNS Cutover Instructions Box */}
      <div
        style={{
          backgroundColor: 'var(--bg-main)',
          border: '1px solid var(--border-medium)',
          borderRadius: 'var(--radius-sm)',
          padding: '1.5rem',
          marginBottom: '2.5rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Icon name="route" size={16} color="var(--accent-secondary)" />
            <span style={{ fontSize: '0.825rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Production Cutover: DNS CNAME Record
            </span>
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Point public traffic to the Deception Gateway
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 1fr', gap: '0.75rem', marginBottom: '1rem' }}>
          <div>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem', fontWeight: 600 }}>TYPE</span>
            <div style={{ padding: '0.5rem 0.75rem', backgroundColor: 'rgba(255, 255, 255, 0.03)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent-primary)' }}>
              CNAME
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>HOST / ALIAS</span>
              <button
                type="button"
                onClick={() => handleCopy('cnameHost', domain)}
                className="btn-subtle"
                style={{ fontSize: '0.68rem', padding: '0 0.3rem' }}
              >
                {copiedField === 'cnameHost' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div style={{ padding: '0.5rem 0.75rem', backgroundColor: 'rgba(255, 255, 255, 0.03)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {domain}
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>POINTS TO / TARGET</span>
              <button
                type="button"
                onClick={() => handleCopy('cnameTarget', cnameTarget)}
                className="btn-subtle"
                style={{ fontSize: '0.68rem', padding: '0 0.3rem' }}
              >
                {copiedField === 'cnameTarget' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div style={{ padding: '0.5rem 0.75rem', backgroundColor: 'rgba(255, 255, 255, 0.03)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {cnameTarget}
            </div>
          </div>
        </div>

        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.4, margin: 0 }}>
          Once your DNS CNAME record has propagated, all incoming requests for <strong>{domain}</strong> will traverse the Gateway. Clean requests will reach your origin with under 5ms added latency, while malicious probes will be trapped in dynamic deception state graphs.
        </p>
      </div>

      {/* Navigation Buttons */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button
          variant="secondary"
          onClick={onBack}
          icon={<Icon name="arrow-left" size={16} />}
        >
          Back to Preflight Checks
        </Button>

        <Button
          variant="primary"
          onClick={onFinish}
          icon={<Icon name="check" size={16} />}
          iconPosition="right"
        >
          Finish & Open Workspace
        </Button>
      </div>
    </Card>
  );
}
