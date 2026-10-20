import React from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Icon from '../ui/Icon';
import DashboardEmptyState from './DashboardEmptyState';

/**
 * Cyber Deception Gateway — Recent Security Events Feed
 * Displays the compact, telemetry-backed event log with real ML scores and routing reasons.
 */
export default function RecentSecurityEvents({
  events = [],
  loading = false,
  title = 'Recent Security Telemetry',
}) {
  if (loading) {
    return (
      <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
        <div style={{ height: '20px', width: '35%', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', marginBottom: '1.5rem' }} />
        <div style={{ height: '140px', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: '6px' }} />
      </Card>
    );
  }

  if (!events || events.length === 0) {
    return (
      <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
        <div style={{ marginBottom: '1.25rem' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
            {title}
          </h3>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
            Real-time audit log of HTTP requests, anomaly scores, and routing decisions.
          </p>
        </div>

        <DashboardEmptyState
          icon="shield"
          title="No Security Events Yet"
          description="The event log is currently clear. When clients or automated scanners send requests to your protected domains, detailed routing telemetry will appear here."
          compact={true}
        />
      </Card>
    );
  }

  const formatTime = (ts) => {
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts || 'just now';
    }
  };

  return (
    <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
            {title} ({events.length})
          </h3>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
            Inspected request anomalies, real-time routing outcomes, and attacker containment actions.
          </p>
        </div>
        <Badge variant="neutral" icon={<Icon name="activity" size={12} />} style={{ fontSize: '0.68rem' }}>
          Live Log Stream
        </Badge>
      </div>

      {/* Events Table Container */}
      <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
          <thead>
            <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              <th style={{ padding: '0.75rem 1rem' }}>Time</th>
              <th style={{ padding: '0.75rem 1rem' }}>Request Path</th>
              <th style={{ padding: '0.75rem 1rem' }}>Classification</th>
              <th style={{ padding: '0.75rem 1rem' }}>Routing Outcome</th>
              <th style={{ padding: '0.75rem 1rem' }}>Duration</th>
              <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Client IP</th>
            </tr>
          </thead>
          <tbody>
            {events.map((evt, idx) => {
              const isMalicious = evt.detectionClassification === 'MALICIOUS' || (evt.detectionScore !== undefined && evt.detectionScore >= 0.7);
              const isDeception = evt.routingDecision === 'DECEPTION';

              return (
                <tr
                  key={evt.requestId || evt.request_id || idx}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    transition: 'background-color var(--transition-fast)',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.015)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  {/* Timestamp */}
                  <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
                    {formatTime(evt.timestamp)}
                  </td>

                  {/* Method & Path */}
                  <td style={{ padding: '0.75rem 1rem', maxWidth: '280px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                      <span
                        style={{
                          fontSize: '0.68rem',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          padding: '0.15rem 0.4rem',
                          borderRadius: '2px',
                          backgroundColor: evt.method === 'POST' ? 'rgba(91, 156, 255, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                          color: evt.method === 'POST' ? 'var(--accent-primary)' : 'var(--text-main)',
                        }}
                      >
                        {evt.method}
                      </span>
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.78rem',
                          color: 'var(--text-main)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                        title={evt.path}
                      >
                        {evt.path}
                      </span>
                    </div>
                  </td>

                  {/* Classification */}
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <Badge
                      variant={isMalicious ? 'danger' : 'success'}
                      style={{ fontSize: '0.68rem', padding: '0.15rem 0.45rem' }}
                    >
                      {evt.detectionClassification || (isMalicious ? 'MALICIOUS' : 'BENIGN')}
                      {evt.detectionScore !== undefined && ` (${Math.round(evt.detectionScore * 100)}%)`}
                    </Badge>
                  </td>

                  {/* Decision */}
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <Badge
                      variant={isDeception ? 'warning' : 'neutral'}
                      icon={<Icon name={isDeception ? 'zap' : 'check'} size={11} color={isDeception ? 'var(--state-warning)' : 'var(--text-secondary)'} />}
                      style={{ fontSize: '0.68rem', padding: '0.15rem 0.45rem' }}
                    >
                      {evt.routingDecision || evt.routing_decision || 'ORIGIN'}
                    </Badge>
                  </td>

                  {/* Duration */}
                  <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                    {evt.durationMs ? `${Number(evt.durationMs).toFixed(1)} ms` : '—'}
                  </td>

                  {/* Client IP */}
                  <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)', textAlign: 'right' }}>
                    {evt.clientIp || evt.client_ip || '127.0.0.1'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
