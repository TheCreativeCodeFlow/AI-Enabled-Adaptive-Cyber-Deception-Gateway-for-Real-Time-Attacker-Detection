import React from 'react';
import Button from '../ui/Button';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Reusable Dashboard Empty State
 */
export default function DashboardEmptyState({
  icon = 'shield',
  title = 'No Data Available',
  description = 'No records match the current workspace criteria.',
  actionLabel = null,
  onAction = null,
  compact = false,
}) {
  return (
    <div
      style={{
        padding: compact ? '2rem 1.5rem' : '3.5rem 2rem',
        textAlign: 'center',
        backgroundColor: 'rgba(255, 255, 255, 0.015)',
        border: '1px dashed var(--border-medium)',
        borderRadius: 'var(--radius-md)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          width: '46px',
          height: '46px',
          borderRadius: 'var(--radius-sm)',
          backgroundColor: 'rgba(91, 156, 255, 0.08)',
          border: '1px solid var(--accent-primary-border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--accent-primary)',
          marginBottom: '1rem',
        }}
      >
        <Icon name={icon} size={22} color="var(--accent-primary)" />
      </div>

      <h3
        style={{
          fontSize: compact ? '1rem' : '1.15rem',
          fontWeight: 700,
          color: 'var(--text-main)',
          marginBottom: '0.35rem',
          letterSpacing: '-0.01em',
        }}
      >
        {title}
      </h3>

      <p
        style={{
          fontSize: '0.85rem',
          color: 'var(--text-secondary)',
          maxWidth: '420px',
          lineHeight: 1.5,
          marginBottom: actionLabel ? '1.5rem' : 0,
        }}
      >
        {description}
      </p>

      {actionLabel && onAction && (
        <Button
          variant="primary"
          size="sm"
          onClick={onAction}
          icon={<Icon name="plus" size={14} />}
        >
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
