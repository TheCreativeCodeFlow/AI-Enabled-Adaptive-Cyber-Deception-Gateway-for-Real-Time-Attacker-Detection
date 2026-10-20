import React from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Standardized Metric Card
 * Displays real backend metrics with technical clarity, status badges, and loading/error states.
 */
export default function MetricCard({
  title,
  value,
  subtext,
  icon,
  badgeText,
  badgeVariant = 'neutral',
  loading = false,
  error = null,
}) {
  if (loading) {
    return (
      <Card
        style={{
          padding: '1.5rem',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
        }}
      >
        <div style={{ height: '12px', width: '45%', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', marginBottom: '0.85rem' }} />
        <div style={{ height: '28px', width: '60%', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', marginBottom: '0.5rem' }} />
        <div style={{ height: '12px', width: '75%', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px' }} />
      </Card>
    );
  }

  return (
    <Card
      style={{
        padding: '1.5rem',
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        transition: 'transform var(--transition-fast), border-color var(--transition-fast)',
      }}
    >
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {title}
          </span>
          {icon && (
            <div
              style={{
                width: '30px',
                height: '30px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-primary)',
              }}
            >
              <Icon name={icon} size={15} color="var(--accent-primary)" />
            </div>
          )}
        </div>

        {error ? (
          <div style={{ color: 'var(--state-danger)', fontSize: '0.85rem', fontWeight: 600 }}>
            Unavailable
          </div>
        ) : (
          <div
            style={{
              fontSize: '2rem',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-main)',
              lineHeight: 1.15,
              marginBottom: '0.5rem',
            }}
          >
            {value !== undefined && value !== null ? value : '—'}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.5rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255, 255, 255, 0.03)' }}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
          {error ? error : subtext || 'Current reporting window'}
        </span>
        {badgeText && !error && (
          <Badge variant={badgeVariant} style={{ fontSize: '0.68rem', padding: '0.15rem 0.5rem' }}>
            {badgeText}
          </Badge>
        )}
      </div>
    </Card>
  );
}
