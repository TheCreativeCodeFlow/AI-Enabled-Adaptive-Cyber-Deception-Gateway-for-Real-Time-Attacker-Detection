import React from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Live Gateway Health & Telemetry Card
 * Strictly probes the independent gateway reverse proxy endpoint (:8080/health and :8080/api/gateway/metrics).
 */
export default function GatewayHealthCard({
  gatewayHealth,
  gatewayMetrics,
  loading = false,
  error = null,
}) {
  const isHealthy = gatewayHealth?.status === 'healthy';
  const isRoutingActive = gatewayHealth?.routingMode === 'active';
  const detectionEnabled = gatewayHealth?.detectionEnabled !== false;
  const activeSessions = gatewayHealth?.activeDeceptionSessions || gatewayMetrics?.activeDeceptionSessions || 0;

  const uptimeFormatted = (seconds) => {
    if (!seconds) return '—';
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hrs}h ${mins}m`;
  };

  return (
    <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div
            style={{
              width: '32px',
              height: '32px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: isHealthy ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
              border: `1px solid ${isHealthy ? 'rgba(16, 185, 129, 0.35)' : 'rgba(239, 68, 68, 0.35)'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Icon
              name={isHealthy ? 'check-circle' : 'alert-triangle'}
              size={17}
              color={isHealthy ? '#10B981' : '#EF4444'}
            />
          </div>
          <div>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
              Gateway Engine Status
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Independent reverse proxy on port 8080
            </span>
          </div>
        </div>

        <Badge
          variant={loading ? 'neutral' : isHealthy ? 'success' : 'danger'}
          icon={<span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: isHealthy ? '#10B981' : '#EF4444' }} />}
          style={{ fontSize: '0.7rem' }}
        >
          {loading ? 'Probing...' : isHealthy ? 'Online & Healthy' : 'Unavailable'}
        </Badge>
      </div>

      {error ? (
        <div className="alert-box alert-error" style={{ marginBottom: 0 }}>
          <Icon name="alert-triangle" size={16} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div style={{ fontSize: '0.78rem' }}>
            <strong>Gateway Probe Failed: </strong>
            {error} (Verify deception-gateway container is listening on port 8080).
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {/* Row 1: Mode */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Routing Mode</span>
            <Badge variant={isRoutingActive ? 'eyebrow' : 'neutral'} style={{ fontSize: '0.68rem', padding: '0.15rem 0.5rem' }}>
              {isRoutingActive ? 'Active Deception' : 'Shadow Mode'}
            </Badge>
          </div>

          {/* Row 2: ML Engine */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>AI Anomaly Detector</span>
            <span style={{ color: detectionEnabled ? '#10B981' : 'var(--state-warning)', fontWeight: 600 }}>
              {detectionEnabled ? 'Online (100% Avail)' : 'Disabled'}
            </span>
          </div>

          {/* Row 3: Active Decoy Sessions */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Deception Traps Active</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-primary)' }}>
              {activeSessions} {activeSessions === 1 ? 'session' : 'sessions'}
            </span>
          </div>

          {/* Row 4: Uptime */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Engine Uptime</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              {uptimeFormatted(gatewayHealth?.uptime || gatewayMetrics?.uptimeSeconds)}
            </span>
          </div>

          {/* Row 5: P95 Latency */}
          {gatewayMetrics?.gatewayLatency?.p95Ms !== undefined && (
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>P95 Added Latency</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: '#10B981', fontWeight: 600 }}>
                {gatewayMetrics.gatewayLatency.p95Ms} ms
              </span>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
