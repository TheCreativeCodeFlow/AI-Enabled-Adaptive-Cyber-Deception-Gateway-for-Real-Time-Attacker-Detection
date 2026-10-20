import React from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import DashboardEmptyState from './DashboardEmptyState';

/**
 * Cyber Deception Gateway — Protected Applications Table
 * Displays tenant-scoped applications with verification state, routing mode, and status badges.
 */
export default function ApplicationTable({
  applications = [],
  loading = false,
  onOnboardNew,
  onManageApp,
}) {
  if (loading) {
    return (
      <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
        <div style={{ height: '20px', width: '30%', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', marginBottom: '1.5rem' }} />
        <div style={{ height: '140px', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: '6px' }} />
      </Card>
    );
  }

  if (!applications || applications.length === 0) {
    return (
      <Card style={{ padding: '2rem', backgroundColor: 'var(--bg-card)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
              Protected Applications
            </h3>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
              Web applications configured for gateway interception in this workspace.
            </p>
          </div>
          <Button
            variant="primary"
            size="sm"
            onClick={onOnboardNew}
            icon={<Icon name="plus" size={14} />}
          >
            Onboard Application
          </Button>
        </div>

        <DashboardEmptyState
          icon="server"
          title="No Applications Registered Yet"
          description="Your organization has not connected any web applications. Register your primary domain and upstream origin to begin intercepting reconnaissance."
          actionLabel="Onboard New Application"
          onAction={onOnboardNew}
          compact={true}
        />
      </Card>
    );
  }

  return (
    <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
            Protected Applications ({applications.length})
          </h3>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
            Configured endpoints receiving gateway traffic inspection and deception routing.
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          onClick={onOnboardNew}
          icon={<Icon name="plus" size={13} />}
        >
          Add Application
        </Button>
      </div>

      {/* Table Container */}
      <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              <th style={{ padding: '0.85rem 1rem' }}>Application</th>
              <th style={{ padding: '0.85rem 1rem' }}>Approved Domain</th>
              <th style={{ padding: '0.85rem 1rem' }}>Environment</th>
              <th style={{ padding: '0.85rem 1rem' }}>Domain Verification</th>
              <th style={{ padding: '0.85rem 1rem' }}>Gateway Status</th>
              <th style={{ padding: '0.85rem 1rem', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {applications.map((app) => {
              const isVerified = app.verification_status === 'verified';
              const isActive = app.activation_status === 'active';

              return (
                <tr
                  key={app.id}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    transition: 'background-color var(--transition-fast)',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.015)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  {/* Name */}
                  <td style={{ padding: '0.9rem 1rem' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>
                      {app.display_name}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                      {app.id.slice(0, 13)}...
                    </div>
                  </td>

                  {/* Domain */}
                  <td style={{ padding: '0.9rem 1rem' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                      {app.approved_domain}
                    </span>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '160px' }}>
                      ➔ {app.configured_origin}
                    </div>
                  </td>

                  {/* Environment */}
                  <td style={{ padding: '0.9rem 1rem' }}>
                    <Badge variant="neutral" style={{ fontSize: '0.68rem', textTransform: 'capitalize' }}>
                      {app.environment}
                    </Badge>
                  </td>

                  {/* Verification */}
                  <td style={{ padding: '0.9rem 1rem' }}>
                    <Badge
                      variant={isVerified ? 'success' : 'warning'}
                      icon={<Icon name={isVerified ? 'check-circle' : 'shield'} size={11} color={isVerified ? '#10B981' : 'var(--state-warning)'} />}
                      style={{ fontSize: '0.68rem' }}
                    >
                      {isVerified ? 'Verified' : 'Unverified'}
                    </Badge>
                  </td>

                  {/* Interception Status */}
                  <td style={{ padding: '0.9rem 1rem' }}>
                    <Badge
                      variant={isActive ? 'eyebrow' : 'neutral'}
                      icon={<span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: isActive ? 'var(--accent-primary)' : 'var(--text-dim)' }} />}
                      style={{ fontSize: '0.68rem' }}
                    >
                      {isActive ? 'Active Interception' : 'Inactive'}
                    </Badge>
                  </td>

                  {/* Actions */}
                  <td style={{ padding: '0.9rem 1rem', textAlign: 'right' }}>
                    {!isVerified ? (
                      <button
                        type="button"
                        onClick={() => onManageApp && onManageApp(app)}
                        className="btn-subtle"
                        style={{
                          fontSize: '0.75rem',
                          color: 'var(--state-warning)',
                          fontWeight: 600,
                          padding: '0.3rem 0.6rem',
                          border: '1px solid rgba(245, 158, 11, 0.35)',
                          borderRadius: 'var(--radius-sm)',
                        }}
                      >
                        Verify TXT
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onManageApp && onManageApp(app)}
                        className="btn-subtle"
                        style={{
                          fontSize: '0.75rem',
                          color: 'var(--accent-primary)',
                          fontWeight: 600,
                          padding: '0.3rem 0.6rem',
                          border: '1px solid var(--accent-primary-border)',
                          borderRadius: 'var(--radius-sm)',
                        }}
                      >
                        Configure
                      </button>
                    )}
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
