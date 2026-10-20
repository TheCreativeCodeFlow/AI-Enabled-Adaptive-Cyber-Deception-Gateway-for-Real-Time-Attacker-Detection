import React from 'react';

/**
 * Cyber Deception Gateway — Reusable Eyebrow & Status Badge
 */
export default function Badge({
  children,
  variant = 'eyebrow', // 'eyebrow' | 'neutral' | 'success' | 'warning' | 'danger'
  icon = null,
  className = '',
}) {
  const styles = {
    eyebrow: {
      color: 'var(--accent-primary)',
      backgroundColor: 'var(--accent-primary-subtle)',
      borderColor: 'var(--accent-primary-border)',
    },
    neutral: {
      color: 'var(--text-secondary)',
      backgroundColor: 'rgba(255, 255, 255, 0.05)',
      borderColor: 'var(--border-subtle)',
    },
    success: {
      color: 'var(--state-success)',
      backgroundColor: 'var(--state-success-subtle)',
      borderColor: 'rgba(16, 185, 129, 0.3)',
    },
    warning: {
      color: 'var(--state-warning)',
      backgroundColor: 'var(--state-warning-subtle)',
      borderColor: 'rgba(245, 158, 11, 0.3)',
    },
    danger: {
      color: 'var(--state-danger)',
      backgroundColor: 'var(--state-danger-subtle)',
      borderColor: 'rgba(239, 68, 68, 0.3)',
    },
  };

  const currentStyle = styles[variant] || styles.eyebrow;

  return (
    <span
      className={`badge-eyebrow ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.45rem',
        fontSize: '0.75rem',
        fontWeight: 700,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        padding: '0.3rem 0.75rem',
        borderRadius: 'var(--radius-full)',
        border: `1px solid ${currentStyle.borderColor}`,
        backgroundColor: currentStyle.backgroundColor,
        color: currentStyle.color,
      }}
    >
      {icon && <span style={{ display: 'inline-flex', alignItems: 'center' }}>{icon}</span>}
      <span>{children}</span>
    </span>
  );
}
