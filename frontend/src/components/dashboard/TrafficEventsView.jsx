import React, { useState, useEffect, useMemo, useCallback } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import MetricCard from './MetricCard';
import DashboardEmptyState from './DashboardEmptyState';
import EventDetailDrawer from './EventDetailDrawer';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Traffic & Events Explorer (/app/events)
 * Full audit feed of incoming HTTP requests, ML threat classifications, and deception verdicts.
 */
export default function TrafficEventsView({
  orgId,
  applications = [],
  onNavigateToApp,
}) {
  // Data states
  const [events, setEvents] = useState([]);
  const [eventsSummary, setEventsSummary] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [lastRefreshedAt, setLastRefreshedAt] = useState(null);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState('');
  const [filterDecision, setFilterDecision] = useState('all'); // 'all' | 'ORIGIN' | 'DECEPTION' | 'OBSERVE_ONLY'
  const [filterAppId, setFilterAppId] = useState('all');
  const [filterMethod, setFilterMethod] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all'); // 'all' | '2xx' | '4xx' | '5xx'
  const [sortBy, setSortBy] = useState('newest'); // 'newest' | 'oldest' | 'score_desc' | 'duration_desc'

  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  // Drawer state
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Fetch tenant events & summary
  const loadEventsData = useCallback(async (showFullLoading = false) => {
    if (!orgId) return;
    if (showFullLoading) setIsLoading(true);
    setIsRefreshing(true);
    setErrorMsg('');

    try {
      const [eventsRes, summaryRes] = await Promise.allSettled([
        api.getEvents(orgId, { limit: 100 }),
        api.getEventsSummary(orgId),
      ]);

      if (eventsRes.status === 'fulfilled') {
        const loadedEvents = eventsRes.value.events || [];
        setEvents(loadedEvents);
      } else {
        setErrorMsg(eventsRes.reason?.message || 'Failed to load tenant security events.');
      }

      if (summaryRes.status === 'fulfilled') {
        setEventsSummary(summaryRes.value.summary || null);
      }

      setLastRefreshedAt(new Date());
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [orgId]);

  useEffect(() => {
    loadEventsData(true);
  }, [loadEventsData]);

  // Check if any filter is active
  const isFilteringActive =
    searchQuery.trim() !== '' ||
    filterDecision !== 'all' ||
    filterAppId !== 'all' ||
    filterMethod !== 'all' ||
    filterStatus !== 'all' ||
    sortBy !== 'newest';

  const handleResetFilters = () => {
    setSearchQuery('');
    setFilterDecision('all');
    setFilterAppId('all');
    setFilterMethod('all');
    setFilterStatus('all');
    setSortBy('newest');
    setCurrentPage(1);
  };

  // Build application map for fast ID lookup
  const appMap = useMemo(() => {
    const map = new Map();
    for (const app of applications) {
      map.set(app.id, app);
    }
    return map;
  }, [applications]);

  // Filter & sort logic
  const filteredEvents = useMemo(() => {
    let result = [...events];

    // 1. Text Search across path, request_id, client_ip, app name
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter((e) => {
        const pathMatch = e.path && e.path.toLowerCase().includes(q);
        const reqMatch = e.request_id && e.request_id.toLowerCase().includes(q);
        const ipMatch = e.client_ip && e.client_ip.toLowerCase().includes(q);
        const app = e.application_id ? appMap.get(e.application_id) : null;
        const appMatch = app && (app.display_name?.toLowerCase().includes(q) || app.approved_domain?.toLowerCase().includes(q));
        return pathMatch || reqMatch || ipMatch || appMatch;
      });
    }

    // 2. Filter Decision
    if (filterDecision !== 'all') {
      result = result.filter((e) => e.routing_decision === filterDecision);
    }

    // 3. Filter Application
    if (filterAppId !== 'all') {
      result = result.filter((e) => e.application_id === filterAppId);
    }

    // 4. Filter HTTP Method
    if (filterMethod !== 'all') {
      result = result.filter((e) => (e.method || '').toUpperCase() === filterMethod);
    }

    // 5. Filter Status Code
    if (filterStatus !== 'all') {
      result = result.filter((e) => {
        const code = e.status_code || 200;
        if (filterStatus === '2xx') return code >= 200 && code < 300;
        if (filterStatus === '4xx') return code >= 400 && code < 500;
        if (filterStatus === '5xx') return code >= 500 && code < 600;
        return true;
      });
    }

    // 6. Sorting
    result.sort((a, b) => {
      if (sortBy === 'oldest') {
        return new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime();
      }
      if (sortBy === 'score_desc') {
        return (b.detection_score || 0) - (a.detection_score || 0);
      }
      if (sortBy === 'duration_desc') {
        return (b.duration_ms || 0) - (a.duration_ms || 0);
      }
      // default: newest
      return new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime();
    });

    return result;
  }, [events, searchQuery, filterDecision, filterAppId, filterMethod, filterStatus, sortBy, appMap]);

  // Paginated slice
  const totalPages = Math.ceil(filteredEvents.length / pageSize) || 1;
  const paginatedEvents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredEvents.slice(start, start + pageSize);
  }, [filteredEvents, currentPage, pageSize]);

  // Drawer handlers
  const handleOpenDrawer = (event) => {
    setSelectedEvent(event);
    setDrawerOpen(true);
  };

  const handleCloseDrawer = () => {
    setDrawerOpen(false);
    setSelectedEvent(null);
  };

  // Status badge style helper
  const getStatusBadge = (code) => {
    if (!code) return <Badge variant="neutral">200</Badge>;
    let variant = 'success';
    if (code >= 400 && code < 500) variant = 'warning';
    if (code >= 500) variant = 'danger';
    return (
      <Badge variant={variant} style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
        {code}
      </Badge>
    );
  };

  // Decision badge style helper
  const getDecisionBadge = (decision) => {
    if (decision === 'DECEPTION') {
      return (
        <Badge
          variant="warning"
          icon={<Icon name="zap" size={11} color="var(--state-warning)" />}
          style={{ fontSize: '0.72rem', fontWeight: 700 }}
        >
          DECEPTION
        </Badge>
      );
    }
    if (decision === 'OBSERVE_ONLY') {
      return (
        <Badge
          variant="eyebrow"
          icon={<Icon name="eye" size={11} />}
          style={{ fontSize: '0.72rem', fontWeight: 600 }}
        >
          OBSERVE
        </Badge>
      );
    }
    return (
      <Badge
        variant="neutral"
        icon={<Icon name="route" size={11} color="var(--accent-primary)" />}
        style={{ fontSize: '0.72rem' }}
      >
        ORIGIN
      </Badge>
    );
  };

  // Summary counts
  const totalEventsCount = eventsSummary?.totalEvents !== undefined ? eventsSummary.totalEvents : events.length;
  const deceptionCount = eventsSummary?.decisions?.DECEPTION !== undefined ? eventsSummary.decisions.DECEPTION : events.filter((e) => e.routing_decision === 'DECEPTION').length;
  const originCount = eventsSummary?.decisions?.ORIGIN !== undefined ? eventsSummary.decisions.ORIGIN : events.filter((e) => e.routing_decision === 'ORIGIN').length;
  const avgScore = eventsSummary?.avgDetectionScore !== undefined ? (eventsSummary.avgDetectionScore * 100).toFixed(0) : '0';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      
      {/* Header Banner */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.35rem' }}>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
              Traffic & Events
            </h1>
            <Badge variant="eyebrow" style={{ fontSize: '0.68rem' }}>
              Persistent Audit Log
            </Badge>
          </div>
          <p style={{ fontSize: '0.925rem', color: 'var(--text-secondary)', margin: 0 }}>
            Inspect gateway traffic, review routing decisions, and investigate recorded security events.
          </p>
        </div>

        {/* Refresh & Timestamp */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {lastRefreshedAt && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              Updated {lastRefreshedAt.toLocaleTimeString()}
            </span>
          )}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => loadEventsData(false)}
            disabled={isRefreshing}
            icon={
              <Icon
                name="refresh-cw"
                size={14}
                style={{
                  animation: isRefreshing ? 'spin 1s linear infinite' : 'none',
                }}
              />
            }
          >
            {isRefreshing ? 'Refreshing...' : 'Refresh Feed'}
          </Button>
        </div>
      </div>

      {/* Summary Metrics Row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1.25rem',
        }}
      >
        <MetricCard
          title="Recorded Events"
          value={totalEventsCount}
          subtext="Indexed in PostgreSQL audit store"
          icon="activity"
          badgeText={totalEventsCount > 0 ? 'Active Stream' : 'Empty'}
          badgeVariant={totalEventsCount > 0 ? 'eyebrow' : 'neutral'}
        />

        <MetricCard
          title="Deception Diverts"
          value={deceptionCount}
          subtext="Trapped in synthetic DSG decoys"
          icon="zap"
          badgeText={deceptionCount > 0 ? 'Threats Trapped' : 'Clean'}
          badgeVariant={deceptionCount > 0 ? 'warning' : 'success'}
        />

        <MetricCard
          title="Origin Forwarded"
          value={originCount}
          subtext="Traversed to customer origin"
          icon="server"
          badgeText="Legitimate"
          badgeVariant="neutral"
        />

        <MetricCard
          title="Avg Threat Score"
          value={`${avgScore}%`}
          subtext={eventsSummary?.avgDurationMs ? `Avg latency: ${eventsSummary.avgDurationMs}ms` : 'Inference pipeline metric'}
          icon="radar"
          badgeText="ML Evaluator"
          badgeVariant={parseFloat(avgScore) >= 70 ? 'danger' : 'success'}
        />
      </div>

      {/* Filter and Search Bar Card */}
      <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          
          {/* Row 1: Search Input & Result Counter */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
            <div style={{ position: 'relative', flexGrow: 1, maxWidth: '480px' }}>
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
                placeholder="Search by path, request ID, client IP, or application..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
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

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Showing <strong>{filteredEvents.length}</strong> of <strong>{events.length}</strong> events
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

          {/* Row 2: Selectors Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
              gap: '0.75rem',
              paddingTop: '0.75rem',
              borderTop: '1px solid rgba(255, 255, 255, 0.04)',
            }}
          >
            {/* Routing Decision */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Routing Verdict
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterDecision}
                onChange={(e) => {
                  setFilterDecision(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Verdicts</option>
                <option value="DECEPTION">DECEPTION (Decoy Divert)</option>
                <option value="ORIGIN">ORIGIN (Forwarded)</option>
                <option value="OBSERVE_ONLY">OBSERVE_ONLY</option>
              </select>
            </div>

            {/* Target Application */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Application
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterAppId}
                onChange={(e) => {
                  setFilterAppId(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Applications</option>
                {applications.map((app) => (
                  <option key={app.id} value={app.id}>
                    {app.display_name} ({app.approved_domain})
                  </option>
                ))}
              </select>
            </div>

            {/* HTTP Method */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                HTTP Method
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterMethod}
                onChange={(e) => {
                  setFilterMethod(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>

            {/* Response Status */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Response Status
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterStatus}
                onChange={(e) => {
                  setFilterStatus(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Statuses</option>
                <option value="2xx">2xx Success</option>
                <option value="4xx">4xx Client Error</option>
                <option value="5xx">5xx Server Error</option>
              </select>
            </div>

            {/* Sort Order */}
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
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="score_desc">Highest Threat Score</option>
                <option value="duration_desc">Highest Latency</option>
              </select>
            </div>
          </div>
        </div>
      </Card>

      {/* Error Banner */}
      {errorMsg && (
        <div
          style={{
            padding: '1rem',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--state-danger)',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Icon name="alert-triangle" size={16} color="var(--state-danger)" />
            <span>{errorMsg}</span>
          </div>
          <Button variant="secondary" size="sm" onClick={() => loadEventsData(true)}>
            Retry
          </Button>
        </div>
      )}

      {/* Loading Skeleton */}
      {isLoading ? (
        <Card style={{ padding: '2rem', backgroundColor: 'var(--bg-card)' }}>
          <div style={{ height: '24px', width: '25%', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', marginBottom: '1.5rem' }} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} style={{ height: '48px', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: '4px' }} />
            ))}
          </div>
        </Card>
      ) : events.length === 0 ? (
        /* Empty State: No events recorded */
        <Card style={{ padding: '3rem 2rem', backgroundColor: 'var(--bg-card)', textAlign: 'center' }}>
          <DashboardEmptyState
            icon="activity"
            title="No Security Events Recorded"
            description="Your organization has not recorded any gateway traffic yet. When incoming HTTP requests traverse the cyber deception gateway, complete security audit telemetry will appear here."
            compact={false}
          />
        </Card>
      ) : filteredEvents.length === 0 ? (
        /* Empty State: Filter mismatch */
        <Card style={{ padding: '3rem 2rem', backgroundColor: 'var(--bg-card)', textAlign: 'center' }}>
          <DashboardEmptyState
            icon="filter"
            title="No Events Match Active Filters"
            description="No security telemetry matched your active search or filter criteria. Adjust your criteria or reset filters to display recorded traffic."
            actionLabel="Reset All Filters"
            onAction={handleResetFilters}
            compact={true}
          />
        </Card>
      ) : (
        /* Main Events Table Card */
        <Card style={{ padding: 0, backgroundColor: 'var(--bg-card)', overflow: 'hidden', border: '1px solid var(--border-subtle)' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr
                  style={{
                    backgroundColor: 'rgba(255, 255, 255, 0.02)',
                    borderBottom: '1px solid var(--border-subtle)',
                    color: 'var(--text-muted)',
                    fontSize: '0.72rem',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                  }}
                >
                  <th style={{ padding: '0.9rem 1.25rem' }}>Timestamp</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Application</th>
                  <th style={{ padding: '0.9rem 1rem' }}>HTTP Request</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Routing Verdict</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Status</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Threat Score</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Latency</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Client IP</th>
                  <th style={{ padding: '0.9rem 1.25rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedEvents.map((evt) => {
                  const app = evt.application_id ? appMap.get(evt.application_id) : null;
                  const score = typeof evt.detection_score === 'number' ? evt.detection_score : null;
                  const scoreColor = score !== null && score >= 0.7 ? '#EF4444' : score !== null && score >= 0.4 ? '#F59E0B' : '#10B981';

                  return (
                    <tr
                      key={evt.id}
                      onClick={() => handleOpenDrawer(evt)}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        transition: 'background-color var(--transition-fast)',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.02)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      {/* Timestamp */}
                      <td style={{ padding: '0.9rem 1.25rem', whiteSpace: 'nowrap' }}>
                        <div style={{ color: 'var(--text-main)', fontSize: '0.8rem', fontWeight: 500 }}>
                          {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </div>
                        <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                          {new Date(evt.timestamp).toLocaleDateString()}
                        </div>
                      </td>

                      {/* Application */}
                      <td style={{ padding: '0.9rem 1rem', maxWidth: '160px' }}>
                        {app ? (
                          <div>
                            <div style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: '0.82rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {app.display_name}
                            </div>
                            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {app.approved_domain}
                            </div>
                          </div>
                        ) : (
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                            Standalone Gateway
                          </span>
                        )}
                      </td>

                      {/* HTTP Method & Sanitized Path */}
                      <td style={{ padding: '0.9rem 1rem', maxWidth: '280px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                          <span
                            style={{
                              fontSize: '0.65rem',
                              fontWeight: 700,
                              fontFamily: 'var(--font-mono)',
                              padding: '0.15rem 0.4rem',
                              borderRadius: '3px',
                              backgroundColor: 'rgba(255, 255, 255, 0.06)',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {evt.method || 'GET'}
                          </span>
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.78rem',
                              color: 'var(--text-main)',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={evt.path}
                          >
                            {evt.path || '/'}
                          </span>
                        </div>
                      </td>

                      {/* Routing Decision */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap' }}>
                        {getDecisionBadge(evt.routing_decision)}
                      </td>

                      {/* Status Code */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap' }}>
                        {getStatusBadge(evt.status_code)}
                      </td>

                      {/* Threat Score */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap' }}>
                        {score !== null ? (
                          <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: scoreColor }}>
                            {(score * 100).toFixed(0)}%
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </td>

                      {/* Latency */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {evt.duration_ms ? `${parseFloat(evt.duration_ms).toFixed(1)} ms` : '—'}
                      </td>

                      {/* Client IP */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        {evt.client_ip || '—'}
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '0.9rem 1.25rem', textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDrawer(evt);
                          }}
                          className="btn-subtle"
                          style={{
                            fontSize: '0.75rem',
                            color: 'var(--accent-primary)',
                            padding: '0.3rem 0.55rem',
                            borderRadius: 'var(--radius-sm)',
                            border: '1px solid var(--accent-primary-border)',
                          }}
                        >
                          Inspect ➔
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls Footer */}
          <div
            style={{
              padding: '1rem 1.25rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              borderTop: '1px solid var(--border-subtle)',
              backgroundColor: 'rgba(255, 255, 255, 0.01)',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}
          >
            <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              Showing {Math.min((currentPage - 1) * pageSize + 1, filteredEvents.length)}–
              {Math.min(currentPage * pageSize, filteredEvents.length)} of {filteredEvents.length} events
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Button
                variant="secondary"
                size="sm"
                disabled={currentPage <= 1}
                onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
                icon={<Icon name="chevron-left" size={14} />}
              >
                Previous
              </Button>

              <span style={{ fontSize: '0.78rem', color: 'var(--text-main)', padding: '0 0.5rem', fontFamily: 'var(--font-mono)' }}>
                Page {currentPage} of {totalPages}
              </span>

              <Button
                variant="secondary"
                size="sm"
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
                icon={<Icon name="chevron-right" size={14} />}
              >
                Next
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Slide-out Event Detail Drawer */}
      <EventDetailDrawer
        event={selectedEvent}
        isOpen={drawerOpen}
        onClose={handleCloseDrawer}
        applications={applications}
        onNavigateToApp={(appId) => {
          handleCloseDrawer();
          if (onNavigateToApp) onNavigateToApp(appId);
        }}
      />
    </div>
  );
}
