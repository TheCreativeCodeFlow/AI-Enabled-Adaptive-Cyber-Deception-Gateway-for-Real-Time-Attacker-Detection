import React from 'react';
import Card from '../ui/Card';

/**
 * Cyber Deception Gateway — Skeleton Loading State
 * Restrained dark theme skeleton loaders for dashboard metrics and tables.
 */
export default function DashboardLoadingState() {
  const skeletonCardStyle = {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-subtle)',
    borderRadius: 'var(--radius-md)',
    padding: '1.5rem',
  };

  const skeletonLine = (width = '100%', height = '14px', marginBottom = '0.5rem') => (
    <div
      style={{
        width,
        height,
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderRadius: 'var(--radius-sm)',
        marginBottom,
        animation: 'pulse 1.5s ease-in-out infinite',
      }}
    />
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.6; }
          50% { opacity: 0.25; }
        }
      `}</style>

      {/* Metric Cards Skeleton */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1rem',
        }}
      >
        {[1, 2, 3, 4].map((i) => (
          <div key={i} style={skeletonCardStyle}>
            {skeletonLine('40%', '11px', '0.75rem')}
            {skeletonLine('65%', '28px', '0.5rem')}
            {skeletonLine('50%', '11px', '0')}
          </div>
        ))}
      </div>

      {/* Main Grid Skeleton */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '1.5rem',
        }}
      >
        <div style={skeletonCardStyle}>
          {skeletonLine('30%', '16px', '1rem')}
          {skeletonLine('100%', '36px', '0.5rem')}
          {skeletonLine('100%', '36px', '0.5rem')}
          {skeletonLine('100%', '36px', '0.5rem')}
        </div>
        <div style={skeletonCardStyle}>
          {skeletonLine('40%', '16px', '1rem')}
          {skeletonLine('100%', '120px', '0.5rem')}
        </div>
      </div>
    </div>
  );
}
