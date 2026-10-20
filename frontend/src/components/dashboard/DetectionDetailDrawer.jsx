import React, { useState } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Threat Detection Detail Drawer
 * Provides in-depth inspection of a specific model detection verdict.
 * Separates ML model classification from gateway routing policy outcomes.
 */
export default function DetectionDetailDrawer({
  detection,
  isOpen = false,
  onClose,
  applications = [],
  onViewInTrafficEvents,
  onViewInApplications,
}) {
  const [copiedKey, setCopiedKey] = useState('');

  if (!isOpen || !detection) return null;

  const handleCopy = (key, text) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(''), 2000);
  };

  const matchedApp = detection.application_id
    ? applications.find((a) => a.id === detection.application_id)
    : null;

  const formatFullDate = (ts) => {
    try {
      const d = new Date(ts);
      return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
    } catch {
      return ts || '—';
    }
  };

  const getRelativeTime = (ts) => {
    try {
      const ms = Date.now() - new Date(ts).getTime();
      const mins = Math.floor(ms / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.floor(mins / 60);
      if (hrs < 24) return `${hrs}h ago`;
      const days = Math.floor(hrs / 24);
      return `${days}d ago`;
    } catch {
      return '';
    }
  };

  const score = typeof detection.detection_score === 'number' ? detection.detection_score : null;
  const classification = detection.detection_classification || (score !== null && score >= 0.7 ? 'MALICIOUS' : 'BENIGN');

  let classBadgeVariant = 'neutral';
  let scoreColor = '#10B981';
  if (classification === 'MALICIOUS') {
    classBadgeVariant = 'danger';
    scoreColor = '#EF4444';
  } else if (classification === 'SUSPICIOUS') {
    classBadgeVariant = 'warning';
    scoreColor = '#F59E0B';
  } else {
    classBadgeVariant = 'success';
    scoreColor = '#10B981';
  }

  const isDeceptionRoute = detection.routing_decision === 'DECEPTION';
  const isObserveRoute = detection.routing_decision === 'OBSERVE_ONLY';

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        display: 'flex',
        justifyContent: 'flex-end',
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="detection-drawer-title"
    >
      {/* Semi-transparent Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed',
          inset: 0,
          backgroundColor: 'rgba(5, 10, 20, 0.72)',
          backdropFilter: 'blur(4px)',
          animation: 'fadeIn 0.2s ease-out',
        }}
      />

      {/* Drawer Panel */}
      <div
        style={{
          position: 'relative',
          width: '100%',
          maxWidth: '560px',
          height: '100%',
          backgroundColor: 'var(--bg-secondary)',
          borderLeft: '1px solid var(--border-medium)',
          boxShadow: 'var(--shadow-xl)',
          display: 'flex',
          flexDirection: 'column',
          zIndex: 101,
          animation: 'slideInRight 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        {/* Drawer Header */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            backgroundColor: 'var(--bg-card)',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.25rem' }}>
              <Icon name="radar" size={18} color="var(--accent-primary)" />
              <h2
                id="detection-drawer-title"
                style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-main)', margin: 0 }}
              >
                Threat Detection Telemetry
              </h2>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              <span>Event: {detection.id ? detection.id.slice(0, 16) : '—'}...</span>
              <button
                type="button"
                onClick={() => handleCopy('detId', detection.id)}
                className="btn-subtle"
                style={{ padding: '0.1rem 0.35rem', fontSize: '0.7rem' }}
                title="Copy Detection Event ID"
              >
                {copiedKey === 'detId' ? '✓ Copied' : 'Copy'}
              </button>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="btn-subtle"
            style={{ padding: '0.4rem', borderRadius: 'var(--radius-sm)' }}
            aria-label="Close Detection Detail Drawer"
          >
            <Icon name="x" size={18} />
          </button>
        </div>

        {/* Drawer Body (Scrollable) */}
        <div style={{ padding: '1.5rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1.5rem', flexGrow: 1 }}>

          {/* Section 1: Classification & Anomaly Scoring Card */}
          <Card
            style={{
              padding: '1.25rem',
              backgroundColor: classification === 'MALICIOUS' ? 'rgba(239, 68, 68, 0.04)' : classification === 'SUSPICIOUS' ? 'rgba(245, 158, 11, 0.04)' : 'rgba(16, 185, 129, 0.04)',
              border: classification === 'MALICIOUS' ? '1px solid rgba(239, 68, 68, 0.35)' : classification === 'SUSPICIOUS' ? '1px solid rgba(245, 158, 11, 0.35)' : '1px solid rgba(16, 185, 129, 0.25)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.05em' }}>
                Model Classification Outcome
              </span>
              <Badge
                variant={classBadgeVariant}
                icon={<Icon name="radar" size={12} />}
                style={{ fontSize: '0.78rem', fontWeight: 700 }}
              >
                {classification}
              </Badge>
            </div>

            {/* Score Progress Bar */}
            <div style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '0.4rem', fontSize: '0.8rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>
                  Continuous Threat Risk Score:
                </span>
                <strong style={{ color: scoreColor, fontFamily: 'var(--font-mono)', fontSize: '0.95rem' }}>
                  {score !== null ? `${score.toFixed(4)} (${(score * 100).toFixed(1)}%)` : 'Not Scored'}
                </strong>
              </div>

              <div style={{ width: '100%', height: '8px', backgroundColor: 'rgba(255, 255, 255, 0.06)', borderRadius: '4px', overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${score !== null ? Math.round(score * 100) : 0}%`,
                    height: '100%',
                    backgroundColor: scoreColor,
                    transition: 'width 0.3s ease',
                  }}
                />
              </div>

              {/* Threshold Scale Guide */}
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginTop: '0.35rem' }}>
                <span>0.00 Nominal</span>
                <span>0.35 Suspicious Threshold</span>
                <span>0.70 Malicious Threshold</span>
                <span>1.00 Max</span>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem', fontSize: '0.825rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Inference Duration
                </span>
                <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                  {detection.detection_latency_ms !== null && detection.detection_latency_ms !== undefined
                    ? `${parseFloat(detection.detection_latency_ms).toFixed(2)} ms`
                    : '—'}
                </span>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Detector Model
                </span>
                <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>
                  RandomForest + Rules v0.3
                </span>
              </div>
            </div>

            {/* Feature Attribution Scope Disclosure */}
            <div
              style={{
                marginTop: '1rem',
                padding: '0.65rem 0.8rem',
                backgroundColor: 'rgba(0, 0, 0, 0.25)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                color: 'var(--text-dim)',
                lineHeight: 1.5,
              }}
            >
              <strong>Feature Pipeline Disclosure:</strong> The detection service extracts request entropy, directory depth, suspicious SQL/probe tokens, and header signatures. Feature-level attribution for this individual request is summarized in the blended score; individual model weight graphs are not persisted.
            </div>
          </Card>

          {/* Section 2: Gateway Interception & Routing Action */}
          <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
              <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', margin: 0 }}>
                Gateway Policy Decision
              </h3>
              <Badge
                variant={isDeceptionRoute ? 'warning' : isObserveRoute ? 'eyebrow' : 'neutral'}
                icon={<Icon name={isDeceptionRoute ? 'zap' : 'route'} size={12} />}
                style={{ fontSize: '0.75rem', fontWeight: 700 }}
              >
                {detection.routing_decision || 'ORIGIN'}
              </Badge>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem', fontSize: '0.825rem', marginBottom: '0.85rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Routing Reason
                </span>
                <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.8rem' }}>
                  {detection.routing_reason || 'EVALUATED'}
                </span>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Gateway Mode
                </span>
                <span style={{ color: 'var(--text-main)', textTransform: 'capitalize' }}>
                  {detection.routing_mode ? `${detection.routing_mode} mode` : 'Active'}
                </span>
              </div>
            </div>

            {/* Crucial Concept Separation Notice */}
            <div
              style={{
                padding: '0.65rem 0.75rem',
                backgroundColor: 'rgba(91, 156, 255, 0.05)',
                border: '1px solid var(--accent-primary-border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                color: 'var(--text-secondary)',
                lineHeight: 1.5,
              }}
            >
              <strong>Policy Separation:</strong> Detection classification represents ML model risk scoring. Downstream gateway routing is independently dictated by tenant protection settings (such as active vs shadow mode, emergency bypass, or deception thresholds).
            </div>
          </Card>

          {/* Section 3: Target Application & HTTP Request */}
          <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.85rem' }}>
              Inspected HTTP Request
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.825rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.25rem' }}>
                  Method & Path
                </span>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    backgroundColor: 'rgba(255, 255, 255, 0.02)',
                    padding: '0.5rem 0.75rem',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    wordBreak: 'break-all',
                  }}
                >
                  <Badge variant="neutral" style={{ fontSize: '0.68rem', fontWeight: 700 }}>
                    {detection.method || 'GET'}
                  </Badge>
                  <span style={{ color: 'var(--text-main)', flexGrow: 1 }}>
                    {detection.path || '/'}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy('path', detection.path || '/')}
                    className="btn-subtle"
                    style={{ padding: '0.15rem 0.4rem', fontSize: '0.7rem' }}
                    title="Copy Path"
                  >
                    {copiedKey === 'path' ? '✓' : 'Copy'}
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                    Client Address
                  </span>
                  <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>
                    {detection.client_ip || '127.0.0.1'}
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                    HTTP Status
                  </span>
                  <Badge variant={detection.status_code >= 400 ? 'warning' : 'success'} style={{ fontSize: '0.72rem' }}>
                    HTTP {detection.status_code || 200}
                  </Badge>
                </div>
              </div>

              {/* Target Application Card */}
              {matchedApp ? (
                <div
                  style={{
                    marginTop: '0.35rem',
                    padding: '0.75rem',
                    backgroundColor: 'rgba(255, 255, 255, 0.02)',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: '0.85rem' }}>
                      {matchedApp.display_name}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                      {matchedApp.approved_domain} ({matchedApp.environment})
                    </div>
                  </div>

                  {onViewInApplications && (
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => onViewInApplications(matchedApp.id)}
                      icon={<Icon name="external-link" size={13} />}
                    >
                      View App
                    </Button>
                  )}
                </div>
              ) : (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                  Target Application: Standalone Gateway Telemetry
                </div>
              )}
            </div>
          </Card>

          {/* Section 4: Audit & Trace Identifiers */}
          <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.85rem' }}>
              Correlation Tracing
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.8rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase' }}>
                    Request ID
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy('reqId', detection.request_id)}
                    className="btn-subtle"
                    style={{ padding: '0.1rem 0.35rem', fontSize: '0.68rem' }}
                  >
                    {copiedKey === 'reqId' ? '✓ Copied' : 'Copy'}
                  </button>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.78rem', wordBreak: 'break-all' }}>
                  {detection.request_id || '—'}
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase' }}>
                    Observed Timestamp
                  </span>
                </div>
                <div style={{ color: 'var(--text-main)', fontSize: '0.78rem' }}>
                  {formatFullDate(detection.timestamp)} ({getRelativeTime(detection.timestamp)})
                </div>
              </div>
            </div>
          </Card>

        </div>

        {/* Drawer Footer Actions */}
        <div
          style={{
            padding: '1rem 1.5rem',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-card)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '1rem',
          }}
        >
          {onViewInTrafficEvents ? (
            <Button
              variant="primary"
              size="sm"
              onClick={() => onViewInTrafficEvents(detection.id)}
              icon={<Icon name="activity" size={14} />}
            >
              View Full Event Telemetry ➔
            </Button>
          ) : (
            <div />
          )}

          <Button variant="secondary" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}
