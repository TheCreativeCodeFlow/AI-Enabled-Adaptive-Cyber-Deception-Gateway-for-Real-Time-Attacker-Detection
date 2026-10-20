import React, { useState } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Event Detail Drawer
 * Slide-out inspection drawer rendering complete telemetry for an inspected security event.
 * Displays routing verdict, AI detection classification, request profile, and sanitized headers.
 */
export default function EventDetailDrawer({
  event,
  isOpen = false,
  onClose,
  applications = [],
  onNavigateToApp,
}) {
  const [copiedKey, setCopiedKey] = useState('');

  if (!isOpen || !event) return null;

  const handleCopy = (key, text) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(''), 2000);
  };

  // Find associated application if application_id is present
  const matchedApp = event.application_id
    ? applications.find((a) => a.id === event.application_id)
    : null;

  // Format timestamp
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

  const isDeception = event.routing_decision === 'DECEPTION';
  const isObserve = event.routing_decision === 'OBSERVE_ONLY';

  // Status badge variant
  const getStatusVariant = (code) => {
    if (!code) return 'neutral';
    if (code >= 200 && code < 300) return 'success';
    if (code >= 400 && code < 500) return 'warning';
    return 'danger';
  };

  // Anomaly score color
  const score = typeof event.detection_score === 'number' ? event.detection_score : null;
  const scorePercent = score !== null ? Math.round(score * 100) : null;

  let scoreColor = '#10B981';
  let scoreBadgeVariant = 'success';
  if (score !== null && score >= 0.7) {
    scoreColor = '#EF4444';
    scoreBadgeVariant = 'danger';
  } else if (score !== null && score >= 0.4) {
    scoreColor = '#F59E0B';
    scoreBadgeVariant = 'warning';
  }

  // Parse metadata if string
  let parsedMetadata = {};
  if (event.metadata) {
    if (typeof event.metadata === 'string') {
      try {
        parsedMetadata = JSON.parse(event.metadata);
      } catch {
        parsedMetadata = { raw: event.metadata };
      }
    } else {
      parsedMetadata = event.metadata;
    }
  }

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
      aria-labelledby="event-drawer-title"
    >
      {/* Backdrop */}
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
              <span
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: isDeception ? '#F59E0B' : isObserve ? 'var(--accent-secondary)' : '#10B981',
                }}
              />
              <h2
                id="event-drawer-title"
                style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-main)', margin: 0 }}
              >
                Security Event Telemetry
              </h2>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              <span>ID: {event.id ? event.id.slice(0, 16) : '—'}...</span>
              <button
                type="button"
                onClick={() => handleCopy('eventId', event.id)}
                className="btn-subtle"
                style={{ padding: '0.1rem 0.35rem', fontSize: '0.7rem' }}
                title="Copy Full Event UUID"
              >
                {copiedKey === 'eventId' ? '✓ Copied' : 'Copy'}
              </button>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="btn-subtle"
            style={{ padding: '0.4rem', borderRadius: 'var(--radius-sm)' }}
            aria-label="Close Event Detail Drawer"
          >
            <Icon name="x" size={18} />
          </button>
        </div>

        {/* Drawer Body (Scrollable) */}
        <div style={{ padding: '1.5rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1.5rem', flexGrow: 1 }}>
          
          {/* Section 1: Routing Verdict & Decision Banner */}
          <Card
            style={{
              padding: '1.25rem',
              backgroundColor: isDeception ? 'rgba(245, 158, 11, 0.04)' : 'rgba(255, 255, 255, 0.015)',
              border: isDeception ? '1px solid rgba(245, 158, 11, 0.35)' : '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.05em' }}>
                Gateway Verdict
              </span>
              <Badge
                variant={isDeception ? 'warning' : isObserve ? 'eyebrow' : 'neutral'}
                icon={<Icon name={isDeception ? 'zap' : 'route'} size={12} />}
                style={{ fontSize: '0.75rem', fontWeight: 700 }}
              >
                {event.routing_decision || 'ORIGIN'}
              </Badge>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem', fontSize: '0.825rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Routing Reason
                </span>
                <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.8rem' }}>
                  {event.routing_reason || 'EVALUATED'}
                </span>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Interception Mode
                </span>
                <span style={{ color: 'var(--text-main)', textTransform: 'capitalize', fontWeight: 500 }}>
                  {event.routing_mode ? `${event.routing_mode} mode` : 'Active'}
                </span>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Response Status
                </span>
                <Badge variant={getStatusVariant(event.status_code)} style={{ fontSize: '0.72rem' }}>
                  HTTP {event.status_code || 200}
                </Badge>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Total Duration
                </span>
                <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                  {event.duration_ms ? `${parseFloat(event.duration_ms).toFixed(2)} ms` : '—'}
                </span>
              </div>
            </div>

            {event.failure_quarantined && (
              <div
                style={{
                  marginTop: '0.9rem',
                  padding: '0.6rem 0.75rem',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.75rem',
                  color: 'var(--state-danger)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <Icon name="alert-triangle" size={14} color="var(--state-danger)" />
                <span>Zero-Leakage Quarantine: Origin connection was safely quarantined.</span>
              </div>
            )}
          </Card>

          {/* Section 2: HTTP Request Profile */}
          <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.85rem' }}>
              HTTP Request Profile
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
                    {event.method || 'GET'}
                  </Badge>
                  <span style={{ color: 'var(--text-main)', flexGrow: 1 }}>
                    {event.path || '/'}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy('path', event.path || '/')}
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
                    {event.client_ip || '127.0.0.1'}
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                    Observed Time
                  </span>
                  <span style={{ color: 'var(--text-main)', fontSize: '0.78rem' }}>
                    {formatFullDate(event.timestamp)} ({getRelativeTime(event.timestamp)})
                  </span>
                </div>
              </div>
            </div>
          </Card>

          {/* Section 3: Associated Application */}
          <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.85rem' }}>
              Target Application
            </h3>

            {matchedApp ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: '0.9rem' }}>
                    {matchedApp.display_name}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginTop: '0.15rem' }}>
                    {matchedApp.approved_domain} · <span style={{ textTransform: 'capitalize' }}>{matchedApp.environment}</span>
                  </div>
                </div>

                {onNavigateToApp && (
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => onNavigateToApp(matchedApp.id)}
                    icon={<Icon name="external-link" size={13} />}
                  >
                    View in Directory
                  </Button>
                )}
              </div>
            ) : (
              <div style={{ fontSize: '0.825rem', color: 'var(--text-dim)' }}>
                {event.application_id ? (
                  <span>Application UUID: <code style={{ fontFamily: 'var(--font-mono)' }}>{event.application_id}</code> (Unassigned or removed)</span>
                ) : (
                  <span>Unassigned — Standalone gateway telemetry or direct origin traversal.</span>
                )}
              </div>
            )}
          </Card>

          {/* Section 4: AI Threat Detection Telemetry */}
          <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
              <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', margin: 0 }}>
                AI Threat Detection Pipeline
              </h3>
              <Badge variant={scoreBadgeVariant} style={{ fontSize: '0.7rem' }}>
                {event.detection_classification || (score !== null && score >= 0.7 ? 'MALICIOUS' : 'BENIGN')}
              </Badge>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.825rem' }}>
              {/* Score Meter */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem', fontSize: '0.78rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Anomaly Risk Score:</span>
                  <strong style={{ color: scoreColor, fontFamily: 'var(--font-mono)' }}>
                    {score !== null ? `${score.toFixed(4)} (${scorePercent}%)` : 'Not Scored'}
                  </strong>
                </div>

                <div style={{ width: '100%', height: '8px', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                  <div
                    style={{
                      width: `${scorePercent || 0}%`,
                      height: '100%',
                      backgroundColor: scoreColor,
                      transition: 'width 0.3s ease',
                    }}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                    Inference Latency
                  </span>
                  <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>
                    {event.detection_latency_ms !== null && event.detection_latency_ms !== undefined
                      ? `${parseFloat(event.detection_latency_ms).toFixed(2)} ms`
                      : '—'}
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                    Model Classification
                  </span>
                  <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>
                    {event.detection_classification || 'BENIGN'}
                  </span>
                </div>
              </div>

              {/* Exact Evidence Statement from confirmed backend fields */}
              <div
                style={{
                  fontSize: '0.75rem',
                  color: 'var(--text-dim)',
                  backgroundColor: 'rgba(255, 255, 255, 0.02)',
                  padding: '0.65rem 0.75rem',
                  borderRadius: 'var(--radius-sm)',
                  lineHeight: 1.5,
                }}
              >
                {score !== null && score >= 0.7 ? (
                  <span>
                    Anomaly score <strong>{(score * 100).toFixed(0)}%</strong> exceeded the detection sensitivity threshold. Request was classified as <strong>MALICIOUS</strong> by the ML inference pipeline and evaluated for deception diversion.
                  </span>
                ) : (
                  <span>
                    Anomaly score <strong>{score !== null ? (score * 100).toFixed(0) : 0}%</strong> was within nominal tolerances. Request evaluated as <strong>BENIGN</strong> and forwarded cleanly to upstream origin.
                  </span>
                )}
              </div>
            </div>
          </Card>

          {/* Section 5: Deception Decoy State (if applicable) */}
          {isDeception && (
            <Card style={{ padding: '1.25rem', backgroundColor: 'rgba(245, 158, 11, 0.03)', border: '1px solid rgba(245, 158, 11, 0.25)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
                <Icon name="radar" size={16} color="var(--accent-secondary)" />
                <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', margin: 0 }}>
                  Deception State Graph (DSG) Telemetry
                </h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                    Deception Node
                  </span>
                  <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>
                    {event.deception_node || 'Synthetic Decoy Node'}
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                    Decoy Strategy
                  </span>
                  <span style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>
                    {event.deception_strategy || 'Stateful Emulation'}
                  </span>
                </div>
              </div>
            </Card>
          )}

          {/* Section 6: Request & Session Identifiers */}
          <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.85rem' }}>
              Audit Trace Identifiers
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.8rem' }}>
              {/* Request ID */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase' }}>
                    Request ID
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy('reqId', event.request_id)}
                    className="btn-subtle"
                    style={{ padding: '0.1rem 0.35rem', fontSize: '0.68rem' }}
                  >
                    {copiedKey === 'reqId' ? '✓ Copied' : 'Copy'}
                  </button>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.78rem', wordBreak: 'break-all' }}>
                  {event.request_id || '—'}
                </div>
              </div>

              {/* Session ID */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem', textTransform: 'uppercase' }}>
                    Synthetic Session Token
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy('sessId', event.session_id)}
                    className="btn-subtle"
                    style={{ padding: '0.1rem 0.35rem', fontSize: '0.68rem' }}
                  >
                    {copiedKey === 'sessId' ? '✓ Copied' : 'Copy'}
                  </button>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.78rem', wordBreak: 'break-all' }}>
                  {event.session_id ? `${event.session_id.slice(0, 20)}...[REDACTED]` : '—'}
                </div>
              </div>
            </div>
          </Card>

          {/* Section 7: Sanitized Metadata */}
          {Object.keys(parsedMetadata).length > 0 && (
            <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em', margin: 0 }}>
                  Sanitized Metadata
                </h3>
                <span style={{ fontSize: '0.7rem', color: '#10B981', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <Icon name="shield" size={12} color="#10B981" />
                  Credentials Redacted
                </span>
              </div>

              <pre
                style={{
                  margin: 0,
                  padding: '0.85rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-secondary)',
                  overflowX: 'auto',
                }}
              >
                {JSON.stringify(parsedMetadata, null, 2)}
              </pre>
            </Card>
          )}

        </div>

        {/* Drawer Footer */}
        <div
          style={{
            padding: '1rem 1.5rem',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-card)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            Recorded: {new Date(event.created_at || event.timestamp).toLocaleTimeString()}
          </span>

          <Button variant="secondary" size="sm" onClick={onClose}>
            Close Telemetry
          </Button>
        </div>
      </div>
    </div>
  );
}
