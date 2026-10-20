import React from 'react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Top Workspace Header
 * Shows authorized organization context, breadcrumb title, live refresh action, and admin console switcher.
 */
export default function WorkspaceHeader({
  organization,
  operator,
  title = 'Security Overview',
  onRefresh,
  isRefreshing = false,
  onNavigate,
  onOpenMobileMenu,
}) {
  return (
    <header
      style={{
        height: 'var(--nav-height)',
        backgroundColor: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 2rem',
        position: 'sticky',
        top: 0,
        zIndex: 20,
      }}
    >
      {/* Left: Organization Context & Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {/* Mobile menu button */}
        <button
          type="button"
          onClick={onOpenMobileMenu}
          className="btn-subtle mobile-menu-btn"
          style={{ display: 'none', padding: '0.4rem' }}
          title="Toggle Navigation"
        >
          <Icon name="menu" size={18} />
        </button>

        {/* Organization Workspace Badge */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.35rem 0.75rem',
            backgroundColor: 'var(--bg-main)',
            border: '1px solid var(--border-medium)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--accent-secondary)' }} />
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)' }}>
            {organization?.name || 'Workspace'}
          </span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            ({organization?.slug || 'tenant'})
          </span>
        </div>

        <span style={{ color: 'var(--border-medium)' }}>/</span>

        {/* Breadcrumb Title */}
        <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
          {title}
        </div>
      </div>

      {/* Right: Controls & Operator Navigation */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        {/* Refresh Action */}
        <Button
          variant="secondary"
          size="sm"
          onClick={onRefresh}
          disabled={isRefreshing}
          icon={<Icon name="refresh-cw" size={13} className={isRefreshing ? 'spin-animation' : ''} />}
          title="Reload metrics and events"
        >
          {isRefreshing ? 'Refreshing...' : 'Refresh'}
        </Button>

        {/* Platform Admin Switcher (Admin role only) */}
        {operator?.role === 'admin' && (
          <Button
            variant="subtle"
            size="sm"
            onClick={() => onNavigate('/admin')}
            icon={<Icon name="shield" size={13} color="var(--accent-primary)" />}
            style={{ fontSize: '0.8rem', border: '1px solid var(--border-subtle)' }}
          >
            Platform Admin
          </Button>
        )}
      </div>
    </header>
  );
}
