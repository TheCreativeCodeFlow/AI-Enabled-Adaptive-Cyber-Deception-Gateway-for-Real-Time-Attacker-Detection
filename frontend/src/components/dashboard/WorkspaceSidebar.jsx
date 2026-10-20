import React from 'react';
import Icon from '../ui/Icon';
import Badge from '../ui/Badge';

/**
 * Cyber Deception Gateway — Reusable Authenticated Workspace Sidebar
 * Implements persistent collapsible navigation, tenant context, and active screen state.
 */
export default function WorkspaceSidebar({
  currentView = 'overview',
  onSelectView,
  onNavigate,
  onLogout,
  operator,
  isCollapsed = false,
  onToggleCollapse,
}) {
  const navItems = [
    { id: 'overview', label: 'Security Overview', icon: 'grid', badge: null },
    { id: 'applications', label: 'Protected Apps', icon: 'server', badge: null },
    { id: 'events', label: 'Traffic & Events', icon: 'activity', badge: null },
    { id: 'detections', label: 'Threat Detections', icon: 'radar', badge: null },
    { id: 'sessions', label: 'Attacker Sessions', icon: 'users', badge: 'DSG' },
    { id: 'deception', label: 'Deception Activity', icon: 'zap', badge: 'Decoys' },
    { id: 'audit', label: 'Audit Logs', icon: 'file-text', badge: null, roles: ['admin', 'analyst'] },
    { id: 'settings', label: 'Settings', icon: 'settings', badge: null },
  ];

  const visibleItems = navItems.filter(
    (item) => !item.roles || (operator?.role && item.roles.includes(operator.role))
  );

  return (
    <aside
      style={{
        width: isCollapsed ? '72px' : '260px',
        backgroundColor: 'var(--bg-secondary)',
        borderRight: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        transition: 'width var(--transition-normal)',
        position: 'relative',
        zIndex: 30,
        flexShrink: 0,
      }}
    >
      {/* Brand & Top Header */}
      <div>
        <div
          style={{
            height: 'var(--nav-height)',
            display: 'flex',
            alignItems: 'center',
            padding: isCollapsed ? '0 1rem' : '0 1.25rem',
            borderBottom: '1px solid var(--border-subtle)',
            gap: '0.75rem',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              width: '34px',
              height: '34px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-primary-subtle)',
              border: '1px solid var(--accent-primary-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-primary)',
              flexShrink: 0,
            }}
          >
            <Icon name="shield" size={18} color="var(--accent-primary)" />
          </div>

          {!isCollapsed && (
            <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
              <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                Deception Gateway
              </span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                Tenant Operations
              </span>
            </div>
          )}
        </div>

        {/* Action: Onboard New Application Button */}
        <div style={{ padding: isCollapsed ? '1rem 0.5rem' : '1.25rem 1rem 0.5rem' }}>
          <button
            type="button"
            onClick={() => onNavigate('/app/onboard')}
            className="btn btn-primary"
            style={{
              width: '100%',
              padding: isCollapsed ? '0.65rem 0' : '0.65rem 0.85rem',
              fontSize: '0.825rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: isCollapsed ? 'center' : 'flex-start',
              gap: '0.5rem',
            }}
            title="Onboard New Application"
          >
            <Icon name="plus" size={15} />
            {!isCollapsed && <span>Onboard App</span>}
          </button>
        </div>

        {/* Navigation Item List */}
        <nav style={{ padding: '0.75rem 0.5rem' }}>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            {visibleItems.map((item) => {
              const isActive = currentView === item.id;

              return (
                <li key={item.id}>
                  <button
                    type="button"
                    onClick={() => onSelectView(item.id)}
                    style={{
                      width: '100%',
                      padding: isCollapsed ? '0.7rem 0' : '0.65rem 0.85rem',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: isActive ? 'rgba(91, 156, 255, 0.1)' : 'transparent',
                      color: isActive ? 'var(--accent-primary)' : 'var(--text-secondary)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: isCollapsed ? 'center' : 'space-between',
                      border: isActive ? '1px solid var(--accent-primary-border)' : '1px solid transparent',
                      cursor: 'pointer',
                      transition: 'all var(--transition-fast)',
                      textAlign: 'left',
                    }}
                    title={isCollapsed ? item.label : undefined}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                      <Icon
                        name={item.icon}
                        size={17}
                        color={isActive ? 'var(--accent-primary)' : 'var(--text-muted)'}
                      />
                      {!isCollapsed && (
                        <span style={{ fontSize: '0.85rem', fontWeight: isActive ? 600 : 500 }}>
                          {item.label}
                        </span>
                      )}
                    </div>

                    {!isCollapsed && item.badge && (
                      <span
                        style={{
                          fontSize: '0.65rem',
                          fontFamily: 'var(--font-mono)',
                          padding: '0.1rem 0.35rem',
                          borderRadius: '2px',
                          backgroundColor: 'rgba(255, 255, 255, 0.05)',
                          color: 'var(--text-dim)',
                        }}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>
      </div>

      {/* Footer Profile & Sign Out */}
      <div style={{ padding: '1rem', borderTop: '1px solid var(--border-subtle)' }}>
        {!isCollapsed && (
          <div
            style={{
              padding: '0.65rem 0.75rem',
              backgroundColor: 'rgba(255, 255, 255, 0.02)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
              marginBottom: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '0.825rem', fontWeight: 600, color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {operator?.username}
              </span>
              <Badge variant="eyebrow" style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem' }}>
                {operator?.role || 'analyst'}
              </Badge>
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button
            type="button"
            onClick={onLogout}
            className="btn btn-subtle"
            style={{
              flexGrow: 1,
              padding: isCollapsed ? '0.5rem 0' : '0.5rem 0.75rem',
              fontSize: '0.8rem',
              color: '#F87171',
              display: 'flex',
              alignItems: 'center',
              justifyContent: isCollapsed ? 'center' : 'flex-start',
              gap: '0.5rem',
            }}
            title="Sign Out Session"
          >
            <Icon name="log-out" size={15} color="#F87171" />
            {!isCollapsed && <span>Sign Out</span>}
          </button>

          <button
            type="button"
            onClick={onToggleCollapse}
            className="btn btn-subtle"
            style={{
              padding: '0.5rem',
              color: 'var(--text-dim)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
            title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <Icon name={isCollapsed ? 'chevron-right' : 'chevron-left'} size={15} />
          </button>
        </div>
      </div>
    </aside>
  );
}
