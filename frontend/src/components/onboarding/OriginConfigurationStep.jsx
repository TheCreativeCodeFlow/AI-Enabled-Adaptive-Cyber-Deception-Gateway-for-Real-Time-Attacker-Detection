import React, { useState } from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import Badge from '../ui/Badge';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Step 3: Upstream Origin & Gateway Routing Topology
 * Configures upstream target, validates SSRF boundaries, and illustrates reverse proxy routing logic.
 */
export default function OriginConfigurationStep({
  orgId,
  appData,
  onAppUpdated,
  onBack,
  onNext,
}) {
  const [originUrl, setOriginUrl] = useState(appData?.configuredOrigin || appData?.configured_origin || '');
  const [isUpdating, setIsUpdating] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const domain = appData?.approvedDomain || appData?.approved_domain || 'example.com';

  const handleSaveOrigin = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSaveSuccess(false);

    if (!originUrl || !originUrl.trim()) {
      setErrorMsg('Upstream origin URL cannot be empty.');
      return;
    }

    try {
      new URL(originUrl.trim());
    } catch {
      setErrorMsg('Origin must be a valid absolute URL (e.g., https://backend.internal:443).');
      return;
    }

    setIsUpdating(true);
    try {
      const res = await api.updateApplication(orgId, appData.id, {
        displayName: appData.display_name || appData.displayName,
        environment: appData.environment,
        configuredOrigin: originUrl.trim(),
      });
      onAppUpdated(res.application);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to update origin configuration.');
    } finally {
      setIsUpdating(false);
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
        <Badge variant="eyebrow" icon={<Icon name="route" size={12} color="var(--accent-primary)" />}>
          Step 3 of 6: Upstream Origin & Routing
        </Badge>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', marginTop: '0.5rem', marginBottom: '0.4rem' }}>
          Upstream Architecture & SSRF Safeguards
        </h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          The Cyber Deception Gateway terminates external TLS traffic for <code style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>{domain}</code> and acts as an intelligent reverse proxy.
        </p>
      </div>

      {saveSuccess && (
        <div className="alert-box alert-success" style={{ marginBottom: '1.75rem' }}>
          <Icon name="check-circle" size={18} color="#10B981" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>Upstream origin configuration successfully updated and validated.</div>
        </div>
      )}

      {errorMsg && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.75rem' }}>
          <Icon name="alert-triangle" size={18} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>Origin Error: </strong>
            {errorMsg}
          </div>
        </div>
      )}

      {/* Upstream Origin Configuration Input */}
      <form onSubmit={handleSaveOrigin} style={{ marginBottom: '2.5rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor="originInput">
            <span>Configured Upstream Origin Address</span>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Protocol + Host + Port
            </span>
          </label>
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <input
              id="originInput"
              type="text"
              className="form-input"
              style={{ flexGrow: 1 }}
              placeholder="e.g. https://api-cluster.internal.corp:8443"
              value={originUrl}
              onChange={(e) => setOriginUrl(e.target.value)}
              disabled={isUpdating}
            />
            <Button
              type="submit"
              variant="secondary"
              disabled={isUpdating || originUrl === (appData?.configured_origin || appData?.configuredOrigin)}
            >
              {isUpdating ? 'Validating...' : 'Update Origin'}
            </Button>
          </div>
          <span className="form-help-text">
            All legitimate user requests are transparently forwarded to this internal endpoint.
          </span>
        </div>
      </form>

      {/* Visual Architectural Topology */}
      <div
        style={{
          backgroundColor: 'var(--bg-main)',
          border: '1px solid var(--border-medium)',
          borderRadius: 'var(--radius-sm)',
          padding: '1.75rem',
          marginBottom: '2rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
          <Icon name="cpu" size={18} color="var(--accent-primary)" />
          <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Traffic Routing Topology
          </span>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 40px 1.2fr 40px 1.2fr',
            alignItems: 'center',
            gap: '0.5rem',
            textAlign: 'center',
          }}
        >
          {/* Node 1: Public Internet */}
          <div
            style={{
              padding: '1.25rem 0.75rem',
              backgroundColor: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            <Icon name="globe" size={20} color="var(--text-secondary)" style={{ margin: '0 auto 0.4rem' }} />
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-main)' }}>Public Internet</div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{domain}</div>
          </div>

          {/* Flow Arrow */}
          <div style={{ color: 'var(--text-dim)', fontSize: '1.2rem', fontWeight: 700 }}>➔</div>

          {/* Node 2: Cyber Deception Gateway */}
          <div
            style={{
              padding: '1.25rem 0.75rem',
              backgroundColor: 'rgba(91, 156, 255, 0.08)',
              border: '1px solid var(--accent-primary-border)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            <Icon name="shield" size={20} color="var(--accent-primary)" style={{ margin: '0 auto 0.4rem' }} />
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-primary)' }}>Deception Gateway</div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>AI Anomaly Scoring</div>
          </div>

          {/* Flow Arrow */}
          <div style={{ color: 'var(--text-dim)', fontSize: '1.2rem', fontWeight: 700 }}>➔</div>

          {/* Node 3: Split Destinations */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            {/* Clean */}
            <div
              style={{
                padding: '0.65rem 0.75rem',
                backgroundColor: 'rgba(16, 185, 129, 0.06)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                borderRadius: 'var(--radius-sm)',
                textAlign: 'left',
              }}
            >
              <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#10B981', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <Icon name="check" size={12} color="#10B981" /> Clean Traffic
              </div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {originUrl || 'Upstream Origin'}
              </div>
            </div>

            {/* Deception */}
            <div
              style={{
                padding: '0.65rem 0.75rem',
                backgroundColor: 'rgba(245, 158, 11, 0.06)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                borderRadius: 'var(--radius-sm)',
                textAlign: 'left',
              }}
            >
              <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--state-warning)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <Icon name="radar" size={12} color="var(--state-warning)" /> Malicious Traffic
              </div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Synthetic Deception (DSG)
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* SSRF & Boundary Protections */}
      <div
        style={{
          padding: '1.25rem',
          backgroundColor: 'rgba(255, 255, 255, 0.02)',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border-subtle)',
          marginBottom: '2.5rem',
        }}
      >
        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: '0.75rem' }}>
          Server-Side Request Forgery (SSRF) Guardrails Active
        </span>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Icon name="check" size={14} color="#10B981" />
            <span>Cloud metadata blocked (169.254.169.254)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Icon name="check" size={14} color="#10B981" />
            <span>Cross-tenant origin sharing prohibited</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Icon name="check" size={14} color="#10B981" />
            <span>Loopback & multicast addresses guarded</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Icon name="check" size={14} color="#10B981" />
            <span>Embedded credentials in origin URLs stripped</span>
          </div>
        </div>
      </div>

      {/* Navigation Buttons */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button
          variant="secondary"
          onClick={onBack}
          icon={<Icon name="arrow-left" size={16} />}
        >
          Back to Verification
        </Button>

        <Button
          variant="primary"
          onClick={onNext}
          icon={<Icon name="arrow-right" size={16} />}
          iconPosition="right"
        >
          Continue to Deception Policy
        </Button>
      </div>
    </Card>
  );
}
