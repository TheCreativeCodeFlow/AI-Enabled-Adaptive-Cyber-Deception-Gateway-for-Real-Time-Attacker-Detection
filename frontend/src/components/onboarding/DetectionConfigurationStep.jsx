import React, { useState } from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import Badge from '../ui/Badge';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Step 4: Detection & Deception Sensitivity Calibration
 * Controls active vs shadow routing mode, ML anomaly threshold, and fail-safe quarantine behavior.
 */
export default function DetectionConfigurationStep({
  orgId,
  appData,
  protectionData,
  onProtectionUpdated,
  onBack,
  onNext,
}) {
  const [routingMode, setRoutingMode] = useState(protectionData?.routingMode || protectionData?.routing_mode || 'shadow');
  const [threshold, setThreshold] = useState(() => {
    const val = protectionData?.deceptionThreshold || protectionData?.deception_threshold;
    return val !== undefined ? parseFloat(val) : 0.70;
  });
  const [quarantineOnFailure, setQuarantineOnFailure] = useState(
    protectionData?.quarantineOnFailure !== undefined ? Boolean(protectionData.quarantineOnFailure) : true
  );
  const [emergencyDisable, setEmergencyDisable] = useState(
    protectionData?.emergencyDisable !== undefined ? Boolean(protectionData.emergencyDisable) : false
  );

  const [isSaving, setIsSaving] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const getThresholdLabel = (val) => {
    if (val < 0.50) return { label: 'Aggressive Containment', color: 'var(--state-warning)', desc: 'Higher risk of diverting edge-case benign requests. Recommended for high-security environments.' };
    if (val <= 0.75) return { label: 'Balanced (Enterprise Standard)', color: 'var(--accent-primary)', desc: 'Optimal trade-off. Accurately isolates attackers with near-zero false positive impact on legitimate users.' };
    return { label: 'Conservative Isolation', color: '#10B981', desc: 'Diverts only unmistakable, catastrophic attacks. Very safe for legacy unstandardized API clients.' };
  };

  const thresholdInfo = getThresholdLabel(threshold);

  const handleSave = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setIsSaving(true);

    try {
      const res = await api.updateProtection(orgId, appData.id, {
        routingMode,
        deceptionThreshold: threshold,
        quarantineOnFailure,
        emergencyDisable,
      });

      onProtectionUpdated({
        routingMode: res.protection.routing_mode,
        deceptionThreshold: parseFloat(res.protection.deception_threshold),
        quarantineOnFailure: res.protection.quarantine_on_failure,
        emergencyDisable: res.protection.emergency_disable,
      });

      onNext();
    } catch (err) {
      setErrorMsg(err.message || 'Failed to save deception policy.');
    } finally {
      setIsSaving(false);
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
        <Badge variant="eyebrow" icon={<Icon name="sliders" size={12} color="var(--accent-primary)" />}>
          Step 4 of 6: Detection & Deception Policy
        </Badge>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', marginTop: '0.5rem', marginBottom: '0.4rem' }}>
          Deception Routing & ML Sensitivity
        </h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          Calibrate the AI detection threshold and determine whether suspicious traffic is actively diverted into synthetic environments or passively logged.
        </p>
      </div>

      {errorMsg && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.75rem' }}>
          <Icon name="alert-triangle" size={18} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>{errorMsg}</div>
        </div>
      )}

      <form onSubmit={handleSave} noValidate>
        {/* Routing Mode Choice */}
        <div style={{ marginBottom: '2rem' }}>
          <label className="form-label" style={{ marginBottom: '0.75rem' }}>
            <span>Gateway Routing Policy</span>
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem' }}>
            {/* Active Deception */}
            <button
              type="button"
              onClick={() => setRoutingMode('active')}
              style={{
                padding: '1.25rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: routingMode === 'active' ? 'rgba(91, 156, 255, 0.08)' : 'var(--bg-main)',
                border: `1px solid ${routingMode === 'active' ? 'var(--accent-primary)' : 'var(--border-medium)'}`,
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.95rem', fontWeight: 700, color: routingMode === 'active' ? 'var(--accent-primary)' : 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Icon name="zap" size={16} color={routingMode === 'active' ? 'var(--accent-primary)' : 'var(--text-muted)'} />
                  Active Deception
                </span>
                <Badge variant={routingMode === 'active' ? 'eyebrow' : 'neutral'} style={{ fontSize: '0.68rem' }}>
                  Recommended
                </Badge>
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                High-confidence malicious requests are autonomously diverted to dynamic synthetic decoys, breadcrumbs, and honey-tokens.
              </p>
            </button>

            {/* Shadow Telemetry */}
            <button
              type="button"
              onClick={() => setRoutingMode('shadow')}
              style={{
                padding: '1.25rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: routingMode === 'shadow' ? 'rgba(255, 255, 255, 0.06)' : 'var(--bg-main)',
                border: `1px solid ${routingMode === 'shadow' ? 'var(--text-main)' : 'var(--border-medium)'}`,
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.95rem', fontWeight: 700, color: routingMode === 'shadow' ? 'var(--text-main)' : 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Icon name="eye" size={16} color={routingMode === 'shadow' ? 'var(--text-main)' : 'var(--text-muted)'} />
                  Shadow Telemetry
                </span>
                <Badge variant="neutral" style={{ fontSize: '0.68rem' }}>
                  Observe Only
                </Badge>
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                Requests are scored by the ML anomaly model and logged for analysis, but all requests are forwarded directly to the origin.
              </p>
            </button>
          </div>
        </div>

        {/* Sensitivity Threshold Slider */}
        <div
          style={{
            padding: '1.5rem',
            backgroundColor: 'var(--bg-main)',
            border: '1px solid var(--border-medium)',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '2rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
            <div>
              <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', display: 'block' }}>
                Deception Sensitivity Threshold
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Minimum anomaly confidence required to trigger deception diversion
              </span>
            </div>
            <div
              style={{
                padding: '0.4rem 0.85rem',
                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                fontFamily: 'var(--font-mono)',
                fontSize: '1.1rem',
                fontWeight: 700,
                color: thresholdInfo.color,
              }}
            >
              {(threshold * 100).toFixed(0)}%
            </div>
          </div>

          {/* Range Slider */}
          <input
            type="range"
            min="0.10"
            max="0.99"
            step="0.01"
            value={threshold}
            onChange={(e) => setThreshold(parseFloat(e.target.value))}
            style={{
              width: '100%',
              accentColor: 'var(--accent-primary)',
              cursor: 'pointer',
              marginBottom: '1rem',
            }}
          />

          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginBottom: '1rem' }}>
            <span>10% (Aggressive)</span>
            <span>50%</span>
            <span>70% (Standard)</span>
            <span>99% (Conservative)</span>
          </div>

          {/* Threshold Feedback Box */}
          <div
            style={{
              padding: '0.85rem 1rem',
              backgroundColor: 'rgba(255, 255, 255, 0.02)',
              borderLeft: `3px solid ${thresholdInfo.color}`,
              borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
              fontSize: '0.8rem',
            }}
          >
            <div style={{ fontWeight: 700, color: thresholdInfo.color, marginBottom: '0.2rem' }}>
              {thresholdInfo.label}
            </div>
            <div style={{ color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              {thresholdInfo.desc}
            </div>
          </div>
        </div>

        {/* Fail-Safe & Containment Policies */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '2.5rem' }}>
          <label className="form-checkbox-row" style={{ alignItems: 'flex-start' }}>
            <input
              type="checkbox"
              className="form-checkbox-input"
              checked={quarantineOnFailure}
              onChange={(e) => setQuarantineOnFailure(e.target.checked)}
              style={{ marginTop: '3px' }}
            />
            <div>
              <span style={{ fontWeight: 600, color: 'var(--text-main)', display: 'block', fontSize: '0.85rem' }}>
                Fail-Safe Quarantine on Subsystem Failure
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.4, display: 'block' }}>
                If the synthetic deception runtime is unreachable, drop suspicious requests immediately rather than falling back to the real upstream origin.
              </span>
            </div>
          </label>

          <label className="form-checkbox-row" style={{ alignItems: 'flex-start' }}>
            <input
              type="checkbox"
              className="form-checkbox-input"
              checked={emergencyDisable}
              onChange={(e) => setEmergencyDisable(e.target.checked)}
              style={{ marginTop: '3px' }}
            />
            <div>
              <span style={{ fontWeight: 600, color: emergencyDisable ? 'var(--state-danger)' : 'var(--text-main)', display: 'block', fontSize: '0.85rem' }}>
                Emergency Bypass (Pass-Through All Traffic)
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.4, display: 'block' }}>
                Completely disables anomaly interception and deception routing for this application during operational incident debugging.
              </span>
            </div>
          </label>
        </div>

        {/* Navigation Buttons */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Button
            variant="secondary"
            onClick={onBack}
            icon={<Icon name="arrow-left" size={16} />}
          >
            Back to Origin
          </Button>

          <Button
            type="submit"
            variant="primary"
            disabled={isSaving}
            icon={isSaving ? <Icon name="refresh-cw" size={16} className="spin-animation" /> : <Icon name="arrow-right" size={16} />}
            iconPosition="right"
          >
            {isSaving ? 'Saving Policy...' : 'Save & Continue to Preflight'}
          </Button>
        </div>
      </form>
    </Card>
  );
}
