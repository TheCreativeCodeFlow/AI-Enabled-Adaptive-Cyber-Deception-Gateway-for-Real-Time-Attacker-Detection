import React from 'react';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import DashboardEmptyState from './DashboardEmptyState';

/**
 * Cyber Deception Gateway — Traffic Activity & Routing Distribution
 * Visualizes real routing outcomes (Clean to Origin vs Synthetic Deception vs Quarantined)
 * based strictly on real backend/gateway aggregate numbers without fabricated historical points.
 */
export default function TrafficActivityChart({
  summary,
  gatewayMetrics,
  loading = false,
}) {
  if (loading) {
    return (
      <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
        <div style={{ height: '20px', width: '35%', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', marginBottom: '1.5rem' }} />
        <div style={{ height: '140px', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: '6px' }} />
      </Card>
    );
  }

  // Combine tenant events summary with gateway operational telemetry
  const totalEvents = summary?.totalEvents || gatewayMetrics?.totalRequests || 0;
  const originCount = summary?.decisions?.ORIGIN !== undefined ? summary.decisions.ORIGIN : (gatewayMetrics?.routingBreakdown?.ORIGIN || 0);
  const deceptionCount = summary?.decisions?.DECEPTION !== undefined ? summary.decisions.DECEPTION : (gatewayMetrics?.routingBreakdown?.DECEPTION || 0);
  const observeCount = summary?.decisions?.OBSERVE_ONLY !== undefined ? summary.decisions.OBSERVE_ONLY : (gatewayMetrics?.routingBreakdown?.OBSERVE_ONLY || 0);
  const quarantinedCount = summary?.quarantinedCount !== undefined ? summary.quarantinedCount : (gatewayMetrics?.quarantinedRequests || 0);

  if (totalEvents === 0) {
    return (
      <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
        <div style={{ marginBottom: '1.25rem' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
            Traffic Routing Distribution
          </h3>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
            Aggregated traffic routing decisions recorded by the gateway engine.
          </p>
        </div>

        <DashboardEmptyState
          icon="activity"
          title="No Traffic Activity Recorded"
          description="No HTTP requests have been proxied through the gateway for this reporting window yet. Once traffic is routed, real-time deception breakdowns will appear here."
          compact={true}
        />
      </Card>
    );
  }

  const originPct = totalEvents > 0 ? Math.round((originCount / totalEvents) * 100) : 0;
  const deceptionPct = totalEvents > 0 ? Math.round((deceptionCount / totalEvents) * 100) : 0;
  const observePct = totalEvents > 0 ? Math.round((observeCount / totalEvents) * 100) : 0;

  return (
    <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
            Traffic Routing Distribution
          </h3>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
            Real-time classification and dynamic containment breakdown across {totalEvents} inspected requests.
          </p>
        </div>
        <span
          style={{
            fontSize: '0.72rem',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-muted)',
            backgroundColor: 'rgba(255, 255, 255, 0.04)',
            padding: '0.2rem 0.6rem',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          Aggregated Live Data
        </span>
      </div>

      {/* Multi-Segment Stacked Progress Bar */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div
          style={{
            height: '16px',
            borderRadius: 'var(--radius-sm)',
            overflow: 'hidden',
            display: 'flex',
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            marginBottom: '0.75rem',
          }}
        >
          {originPct > 0 && (
            <div
              style={{
                width: `${originPct}%`,
                backgroundColor: '#10B981',
                transition: 'width 0.4s ease',
              }}
              title={`Clean Origin: ${originCount} (${originPct}%)`}
            />
          )}
          {deceptionPct > 0 && (
            <div
              style={{
                width: `${deceptionPct}%`,
                backgroundColor: 'var(--accent-primary)',
                transition: 'width 0.4s ease',
              }}
              title={`Deception Trapped: ${deceptionCount} (${deceptionPct}%)`}
            />
          )}
          {observePct > 0 && (
            <div
              style={{
                width: `${observePct}%`,
                backgroundColor: 'var(--state-warning)',
                transition: 'width 0.4s ease',
              }}
              title={`Shadow Observed: ${observeCount} (${observePct}%)`}
            />
          )}
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1.25rem', fontSize: '0.78rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: '#10B981' }} />
            <span style={{ color: 'var(--text-secondary)' }}>Clean to Upstream:</span>
            <strong style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>{originCount} ({originPct}%)</strong>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: 'var(--accent-primary)' }} />
            <span style={{ color: 'var(--text-secondary)' }}>Diverted to Deception:</span>
            <strong style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>{deceptionCount} ({deceptionPct}%)</strong>
          </div>

          {observeCount > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: 'var(--state-warning)' }} />
              <span style={{ color: 'var(--text-secondary)' }}>Shadow Mode Observed:</span>
              <strong style={{ color: 'var(--state-warning)', fontFamily: 'var(--font-mono)' }}>{observeCount} ({observePct}%)</strong>
            </div>
          )}
        </div>
      </div>

      {/* Auxiliary Performance Breakdown */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '0.75rem',
          paddingTop: '1.25rem',
          borderTop: '1px solid var(--border-subtle)',
        }}
      >
        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Quarantined Failures</span>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: quarantinedCount > 0 ? 'var(--state-danger)' : 'var(--text-main)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
            {quarantinedCount}
          </div>
        </div>

        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Avg Detection Latency</span>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent-secondary)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
            {gatewayMetrics?.detection?.latency?.avgMs !== undefined ? `${gatewayMetrics.detection.latency.avgMs} ms` : '—'}
          </div>
        </div>

        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Gateway P50 Latency</span>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#10B981', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
            {gatewayMetrics?.gatewayLatency?.p50Ms !== undefined ? `${gatewayMetrics.gatewayLatency.p50Ms} ms` : '—'}
          </div>
        </div>
      </div>
    </Card>
  );
}
