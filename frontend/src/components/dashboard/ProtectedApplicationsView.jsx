import React, { useState, useMemo } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import DashboardEmptyState from './DashboardEmptyState';
import ApplicationDetailDrawer from './ApplicationDetailDrawer';

/**
 * Cyber Deception Gateway — Protected Applications Management View
 * Features search, multi-attribute filtering, sorting, responsive table, and lifecycle detail drawer.
 */
export default function ProtectedApplicationsView({
  applications = [],
  loading = false,
  orgId,
  onOnboardNew,
  onRefresh,
}) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterEnvironment, setFilterEnvironment] = useState('all');
  const [filterVerification, setFilterVerification] = useState('all');
  const [filterActivation, setFilterActivation] = useState('all');
  const [sortBy, setSortBy] = useState('created_desc'); // 'created_desc' | 'created_asc' | 'name_asc' | 'name_desc'

  const [selectedAppId, setSelectedAppId] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [copiedAppId, setCopiedAppId] = useState('');

  const isFilteringActive =
    searchQuery.trim() !== '' ||
    filterEnvironment !== 'all' ||
    filterVerification !== 'all' ||
    filterActivation !== 'all';

  const handleResetFilters = () => {
    setSearchQuery('');
    setFilterEnvironment('all');
    setFilterVerification('all');
    setFilterActivation('all');
    setSortBy('created_desc');
  };

  const handleCopyId = (e, id) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedAppId(id);
    setTimeout(() => setCopiedAppId(''), 2000);
  };

  // Client-side search, filtering, and sorting over the authorized tenant applications list
  const filteredApplications = useMemo(() => {
    let result = [...applications];

    // 1. Text Search across name and domain
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter(
        (app) =>
          (app.display_name && app.display_name.toLowerCase().includes(q)) ||
          (app.approved_domain && app.approved_domain.toLowerCase().includes(q)) ||
          (app.configured_origin && app.configured_origin.toLowerCase().includes(q))
      );
    }

    // 2. Filter Environment
    if (filterEnvironment !== 'all') {
      result = result.filter((app) => app.environment === filterEnvironment);
    }

    // 3. Filter Verification Status
    if (filterVerification !== 'all') {
      result = result.filter((app) => app.verification_status === filterVerification);
    }

    // 4. Filter Activation Status
    if (filterActivation !== 'all') {
      if (filterActivation === 'active') {
        result = result.filter((app) => app.activation_status === 'active');
      } else {
        result = result.filter((app) => app.activation_status !== 'active');
      }
    }

    // 5. Sorting
    result.sort((a, b) => {
      if (sortBy === 'name_asc') {
        return (a.display_name || '').localeCompare(b.display_name || '');
      }
      if (sortBy === 'name_desc') {
        return (b.display_name || '').localeCompare(a.display_name || '');
      }
      if (sortBy === 'created_asc') {
        return new Date(a.created_at || 0).getTime() - new Date(b.created_at || 0).getTime();
      }
      // default: created_desc
      return new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime();
    });

    return result;
  }, [applications, searchQuery, filterEnvironment, filterVerification, filterActivation, sortBy]);

  const handleOpenDrawer = (appId) => {
    setSelectedAppId(appId);
    setDrawerOpen(true);
  };

  const handleCloseDrawer = () => {
    setDrawerOpen(false);
    setSelectedAppId(null);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* View Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
            Protected Applications
          </h1>
          <p style={{ fontSize: '0.925rem', color: 'var(--text-secondary)', marginTop: '0.25rem', marginBottom: 0 }}>
            Manage registered applications, verification status, and gateway protection.
          </p>
        </div>

        <Button
          variant="primary"
          onClick={onOnboardNew}
          icon={<Icon name="plus" size={15} />}
        >
          Onboard New Application
        </Button>
      </div>

      {/* Filter and Search Bar Card */}
      <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Row 1: Search + Quick Stats */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
            {/* Search Input */}
            <div style={{ position: 'relative', flexGrow: 1, maxWidth: '460px' }}>
              <Icon
                name="search"
                size={16}
                color="var(--text-muted)"
                style={{ position: 'absolute', left: '0.85rem', top: '50%', transform: 'translateY(-50%)' }}
              />
              <input
                type="text"
                className="form-input"
                style={{ paddingLeft: '2.5rem', width: '100%', fontSize: '0.875rem' }}
                placeholder="Search by name, approved domain, or origin URL..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  className="btn-subtle"
                  style={{ position: 'absolute', right: '0.5rem', top: '50%', transform: 'translateY(-50%)', padding: '0.2rem' }}
                >
                  <Icon name="x" size={14} />
                </button>
              )}
            </div>

            {/* Counts Counter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Showing <strong>{filteredApplications.length}</strong> of <strong>{applications.length}</strong> apps
              </span>
              {isFilteringActive && (
                <button
                  type="button"
                  onClick={handleResetFilters}
                  className="btn-subtle"
                  style={{
                    fontSize: '0.75rem',
                    color: 'var(--accent-primary)',
                    padding: '0.25rem 0.5rem',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--accent-primary-border)',
                  }}
                >
                  Reset Filters
                </button>
              )}
            </div>
          </div>

          {/* Row 2: Filter Selectors & Sort */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid rgba(255, 255, 255, 0.04)' }}>
            {/* Environment */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Environment
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterEnvironment}
                onChange={(e) => setFilterEnvironment(e.target.value)}
              >
                <option value="all">All Environments</option>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>

            {/* Verification */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Domain Verification
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterVerification}
                onChange={(e) => setFilterVerification(e.target.value)}
              >
                <option value="all">All Verification States</option>
                <option value="verified">Verified Only</option>
                <option value="unverified">Unverified Only</option>
              </select>
            </div>

            {/* Activation */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Gateway Interception
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterActivation}
                onChange={(e) => setFilterActivation(e.target.value)}
              >
                <option value="all">All Interception States</option>
                <option value="active">Active Only</option>
                <option value="inactive">Inactive / Disabled</option>
              </select>
            </div>

            {/* Sort */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Sort By
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
              >
                <option value="created_desc">Newest Registered</option>
                <option value="created_asc">Oldest Registered</option>
                <option value="name_asc">Application Name (A-Z)</option>
                <option value="name_desc">Application Name (Z-A)</option>
              </select>
            </div>
          </div>
        </div>
      </Card>

      {/* Main Content Area: Applications Table or Empty States */}
      {loading ? (
        <Card style={{ padding: '2rem', backgroundColor: 'var(--bg-card)' }}>
          <div style={{ height: '36px', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', marginBottom: '1.25rem' }} />
          <div style={{ height: '220px', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: '6px' }} />
        </Card>
      ) : applications.length === 0 ? (
        /* Genuinely Empty Workspace */
        <DashboardEmptyState
          icon="server"
          title="No Applications Registered in this Workspace"
          description="Your organization has not registered any web applications yet. Configure your approved domain and internal origin to activate automated AI cyber deception."
          actionLabel="Onboard New Application"
          onAction={onOnboardNew}
        />
      ) : filteredApplications.length === 0 ? (
        /* No Match for Search / Filter Query */
        <DashboardEmptyState
          icon="filter"
          title="No Matching Applications Found"
          description="No registered applications matched your active search term or filter parameters. Try clearing your filters."
          actionLabel="Clear All Filters"
          onAction={handleResetFilters}
          compact={true}
        />
      ) : (
        /* Filtered Applications Table */
        <Card style={{ padding: '0', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  <th style={{ padding: '1rem 1.25rem' }}>Application Name</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Approved Public FQDN</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Upstream Target</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Environment</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Domain Verification</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Interception Status</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Registered Date</th>
                  <th style={{ padding: '1rem 1.25rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredApplications.map((app) => {
                  const isVerified = app.verification_status === 'verified';
                  const isActive = app.activation_status === 'active';

                  return (
                    <tr
                      key={app.id}
                      onClick={() => handleOpenDrawer(app.id)}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        transition: 'background-color var(--transition-fast)',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(91, 156, 255, 0.04)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      {/* Name & ID */}
                      <td style={{ padding: '1rem 1.25rem' }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: '0.9rem' }}>
                          {app.display_name}
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.2rem' }}>
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                            {app.id.slice(0, 8)}...
                          </span>
                          <button
                            type="button"
                            onClick={(e) => handleCopyId(e, app.id)}
                            className="btn-subtle"
                            style={{ fontSize: '0.65rem', padding: '0 0.3rem', color: copiedAppId === app.id ? '#10B981' : 'var(--text-dim)' }}
                            title="Copy Application UUID"
                          >
                            {copiedAppId === app.id ? 'Copied' : <Icon name="copy" size={10} />}
                          </button>
                        </div>
                      </td>

                      {/* Approved Domain */}
                      <td style={{ padding: '1rem 1.25rem' }}>
                        <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.825rem', color: 'var(--accent-primary)' }}>
                          {app.approved_domain}
                        </code>
                      </td>

                      {/* Upstream Origin */}
                      <td style={{ padding: '1rem 1.25rem', maxWidth: '200px' }}>
                        <div
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.78rem',
                            color: 'var(--text-secondary)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={app.configured_origin}
                        >
                          {app.configured_origin}
                        </div>
                      </td>

                      {/* Environment */}
                      <td style={{ padding: '1rem 1.25rem' }}>
                        <Badge variant="neutral" style={{ fontSize: '0.68rem', textTransform: 'capitalize' }}>
                          {app.environment}
                        </Badge>
                      </td>

                      {/* Verification Status */}
                      <td style={{ padding: '1rem 1.25rem' }}>
                        <Badge
                          variant={isVerified ? 'success' : 'warning'}
                          icon={<Icon name={isVerified ? 'check-circle' : 'shield'} size={11} color={isVerified ? '#10B981' : 'var(--state-warning)'} />}
                          style={{ fontSize: '0.68rem' }}
                        >
                          {isVerified ? 'Verified' : 'Unverified'}
                        </Badge>
                      </td>

                      {/* Interception Status */}
                      <td style={{ padding: '1rem 1.25rem' }}>
                        <Badge
                          variant={isActive ? 'eyebrow' : 'neutral'}
                          icon={<span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: isActive ? 'var(--accent-primary)' : 'var(--text-dim)' }} />}
                          style={{ fontSize: '0.68rem' }}
                        >
                          {isActive ? 'Active Interception' : 'Inactive'}
                        </Badge>
                      </td>

                      {/* Registered Date */}
                      <td style={{ padding: '1rem 1.25rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        {app.created_at ? new Date(app.created_at).toLocaleDateString() : '—'}
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '1rem 1.25rem', textAlign: 'right' }}>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDrawer(app.id);
                          }}
                          className="btn-subtle"
                          style={{
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            color: 'var(--accent-primary)',
                            padding: '0.35rem 0.65rem',
                            border: '1px solid var(--accent-primary-border)',
                            borderRadius: 'var(--radius-sm)',
                          }}
                        >
                          View Details ➔
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Slide-out Application Detail Drawer */}
      <ApplicationDetailDrawer
        appId={selectedAppId}
        orgId={orgId}
        isOpen={drawerOpen}
        onClose={handleCloseDrawer}
        onAppUpdated={() => onRefresh && onRefresh()}
        onAppDeleted={() => onRefresh && onRefresh()}
      />
    </div>
  );
}
