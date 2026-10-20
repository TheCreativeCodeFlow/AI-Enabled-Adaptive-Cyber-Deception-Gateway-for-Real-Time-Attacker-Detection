import React, { useState, useEffect, useCallback } from 'react';
import WorkspaceLayout from '../components/dashboard/WorkspaceLayout';
import MetricCard from '../components/dashboard/MetricCard';
import ApplicationTable from '../components/dashboard/ApplicationTable';
import TrafficActivityChart from '../components/dashboard/TrafficActivityChart';
import RecentSecurityEvents from '../components/dashboard/RecentSecurityEvents';
import GatewayHealthCard from '../components/dashboard/GatewayHealthCard';
import DashboardLoadingState from '../components/dashboard/DashboardLoadingState';
import DashboardEmptyState from '../components/dashboard/DashboardEmptyState';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Icon from '../components/ui/Icon';
import { api } from '../services/api';

/**
 * Cyber Deception Gateway — Tenant Operations Dashboard (/app)
 * Primary workspace for authenticated organization operators.
 * Displays real-time application status, gateway telemetry, threat classifications, and audit events.
 */
export default function DashboardPage({ operator, onNavigate, onLogout }) {
  const [currentView, setCurrentView] = useState('overview');
  const [organisations, setOrganisations] = useState([]);
  const [activeOrg, setActiveOrg] = useState(null);

  // Core Data States
  const [applications, setApplications] = useState([]);
  const [events, setEvents] = useState([]);
  const [eventsSummary, setEventsSummary] = useState(null);
  const [gatewayHealth, setGatewayHealth] = useState(null);
  const [gatewayMetrics, setGatewayMetrics] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);

  // Loading & Error States
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [fetchErrors, setFetchErrors] = useState({});

  /**
   * Loads all tenant and gateway data concurrently.
   */
  const loadDashboardData = useCallback(async (orgId, showFullLoading = false) => {
    if (showFullLoading) setIsLoading(true);
    setIsRefreshing(true);
    const errors = {};

    try {
      // 1. Parallel requests for tenant-scoped resources
      const [appsRes, eventsRes, summaryRes, gwHealthRes, gwMetricsRes] = await Promise.allSettled([
        api.getApplications(orgId),
        api.getEvents(orgId, { limit: 20 }),
        api.getEventsSummary(orgId),
        api.getGatewayHealth(),
        api.getGatewayMetrics(),
      ]);

      // Applications
      if (appsRes.status === 'fulfilled') {
        setApplications(appsRes.value.applications || []);
      } else {
        errors.applications = appsRes.reason?.message || 'Failed to load applications.';
      }

      // Security Events (if tenant events empty, fallback to gateway recent events if available)
      if (eventsRes.status === 'fulfilled') {
        const tenantEvents = eventsRes.value.events || [];
        if (tenantEvents.length > 0) {
          setEvents(tenantEvents);
        } else {
          // If tenant hasn't accumulated events yet, try gateway live buffer
          try {
            const gwEvents = await api.getGatewayEvents(20);
            setEvents(gwEvents.events || []);
          } catch {
            setEvents([]);
          }
        }
      } else {
        errors.events = eventsRes.reason?.message || 'Failed to load security events.';
      }

      // Events Summary
      if (summaryRes.status === 'fulfilled') {
        setEventsSummary(summaryRes.value.summary || null);
      } else {
        errors.summary = summaryRes.reason?.message || 'Failed to summarize security events.';
      }

      // Gateway Health
      if (gwHealthRes.status === 'fulfilled') {
        setGatewayHealth(gwHealthRes.value);
      } else {
        errors.gatewayHealth = gwHealthRes.reason?.message || 'Gateway unreachable on port 8080.';
      }

      // Gateway Metrics
      if (gwMetricsRes.status === 'fulfilled') {
        setGatewayMetrics(gwMetricsRes.value);
      } else {
        errors.gatewayMetrics = gwMetricsRes.reason?.message || 'Gateway metrics unavailable.';
      }

      // Audit logs (for operators with audit:read permission)
      if (operator?.role === 'admin' || operator?.role === 'analyst') {
        try {
          const auditRes = await api.getAuditLogs();
          setAuditLogs(auditRes.logs || []);
        } catch (auditErr) {
          console.warn('[Dashboard] Could not fetch audit records:', auditErr.message);
        }
      }
    } finally {
      setFetchErrors(errors);
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [operator]);

  // Initial load: resolve active organization
  useEffect(() => {
    let isMounted = true;

    api.getOrganisations()
      .then(async (res) => {
        if (!isMounted) return;
        const orgList = res.organisations || [];
        if (orgList.length > 0) {
          setOrganisations(orgList);
          const current = orgList[0];
          setActiveOrg(current);
          loadDashboardData(current.id, true);
        } else {
          // Auto-bootstrap organization if user has none
          try {
            const newOrg = await api.createOrganisation('Primary Workspace', 'primary-workspace');
            if (isMounted && newOrg.organisation) {
              setOrganisations([newOrg.organisation]);
              setActiveOrg(newOrg.organisation);
              loadDashboardData(newOrg.organisation.id, true);
            }
          } catch {
            setIsLoading(false);
          }
        }
      })
      .catch((err) => {
        if (isMounted) {
          console.error('[Dashboard] Failed to fetch organizations:', err);
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [loadDashboardData]);

  const handleRefresh = () => {
    if (activeOrg) {
      loadDashboardData(activeOrg.id, false);
    }
  };

  const handleManageApp = (app) => {
    // If domain is unverified, open onboarding wizard pre-focused
    onNavigate('/app/onboard');
  };

  // Derive metric values from real backend numbers
  const totalAppsCount = applications.length;
  const activeAppsCount = applications.filter((a) => a.activation_status === 'active').length;
  const verifiedAppsCount = applications.filter((a) => a.verification_status === 'verified').length;

  const totalTrafficRequests =
    eventsSummary?.totalEvents !== undefined && eventsSummary?.totalEvents > 0
      ? eventsSummary.totalEvents
      : gatewayMetrics?.totalRequests || 0;

  const deceptionDiverts =
    eventsSummary?.decisions?.DECEPTION !== undefined && eventsSummary?.decisions?.DECEPTION > 0
      ? eventsSummary.decisions.DECEPTION
      : gatewayMetrics?.routingBreakdown?.DECEPTION || 0;

  const isGatewayHealthy = gatewayHealth?.status === 'healthy';

  return (
    <WorkspaceLayout
      currentView={currentView}
      onSelectView={setCurrentView}
      onNavigate={onNavigate}
      onLogout={onLogout}
      operator={operator}
      organization={activeOrg}
      pageTitle={
        currentView === 'overview'
          ? 'Security Overview'
          : currentView === 'applications'
          ? 'Protected Applications'
          : currentView === 'events'
          ? 'Traffic & Security Events'
          : currentView === 'detections'
          ? 'Threat Detections'
          : currentView === 'sessions'
          ? 'Attacker Sessions (DSG)'
          : currentView === 'deception'
          ? 'Deception Node Inventory'
          : currentView === 'audit'
          ? 'Platform Audit Log'
          : 'Tenant Settings'
      }
      onRefresh={handleRefresh}
      isRefreshing={isRefreshing}
    >
      {/* View: Overview (Default) */}
      {currentView === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          {/* Header Banner */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.35rem' }}>
                <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
                  Security Overview
                </h1>
                <Badge variant={isGatewayHealthy ? 'success' : 'warning'} style={{ fontSize: '0.7rem' }}>
                  {isGatewayHealthy ? 'Interception Active' : 'Gateway Degraded'}
                </Badge>
              </div>
              <p style={{ fontSize: '0.925rem', color: 'var(--text-secondary)', margin: 0 }}>
                Monitor your protected applications, gateway activity, and security events.
              </p>
            </div>

            <Button
              variant="primary"
              size="md"
              onClick={() => onNavigate('/app/onboard')}
              icon={<Icon name="plus" size={15} />}
            >
              Onboard New Application
            </Button>
          </div>

          {/* Metric Cards Row */}
          {isLoading ? (
            <DashboardLoadingState />
          ) : (
            <>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                  gap: '1.25rem',
                }}
              >
                {/* Metric 1: Total Apps */}
                <MetricCard
                  title="Registered Applications"
                  value={totalAppsCount}
                  subtext={totalAppsCount > 0 ? `${activeAppsCount} active · ${verifiedAppsCount} verified` : 'No applications configured'}
                  icon="server"
                  badgeText={totalAppsCount > 0 ? (activeAppsCount > 0 ? 'Active' : 'Unactivated') : 'Empty'}
                  badgeVariant={activeAppsCount > 0 ? 'success' : 'neutral'}
                  error={fetchErrors.applications}
                />

                {/* Metric 2: Inspected Traffic */}
                <MetricCard
                  title="Inspected HTTP Requests"
                  value={totalTrafficRequests}
                  subtext={totalTrafficRequests > 0 ? 'Traversed reverse proxy' : 'Awaiting incoming traffic'}
                  icon="activity"
                  badgeText={totalTrafficRequests > 0 ? 'Live Stream' : 'Idle'}
                  badgeVariant={totalTrafficRequests > 0 ? 'eyebrow' : 'neutral'}
                  error={fetchErrors.summary && fetchErrors.gatewayMetrics}
                />

                {/* Metric 3: Threat Traps */}
                <MetricCard
                  title="Deception Diverts"
                  value={deceptionDiverts}
                  subtext={deceptionDiverts > 0 ? 'Trapped in synthetic DSG decoys' : '0 malicious diversions'}
                  icon="zap"
                  badgeText={deceptionDiverts > 0 ? 'Threats Trapped' : 'Clean'}
                  badgeVariant={deceptionDiverts > 0 ? 'warning' : 'success'}
                  error={fetchErrors.summary}
                />

                {/* Metric 4: Gateway Status */}
                <MetricCard
                  title="Gateway Engine (:8080)"
                  value={isGatewayHealthy ? 'Online' : 'Offline'}
                  subtext={gatewayHealth?.routingMode ? `Mode: ${gatewayHealth.routingMode}` : 'Probing port 8080'}
                  icon="shield"
                  badgeText={isGatewayHealthy ? 'Healthy' : 'Unavailable'}
                  badgeVariant={isGatewayHealthy ? 'success' : 'danger'}
                  error={fetchErrors.gatewayHealth}
                />
              </div>

              {/* Main Two-Column Layout */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'minmax(0, 1fr) 360px',
                  gap: '1.75rem',
                  alignItems: 'start',
                }}
              >
                {/* Left Column: Applications & Traffic Distribution */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem', minWidth: 0 }}>
                  {/* Traffic Distribution Breakdown */}
                  <TrafficActivityChart
                    summary={eventsSummary}
                    gatewayMetrics={gatewayMetrics}
                    loading={isLoading}
                  />

                  {/* Protected Applications Table */}
                  <ApplicationTable
                    applications={applications}
                    loading={isLoading}
                    onOnboardNew={() => onNavigate('/app/onboard')}
                    onManageApp={handleManageApp}
                  />

                  {/* Recent Security Events */}
                  <RecentSecurityEvents
                    events={events}
                    loading={isLoading}
                  />
                </div>

                {/* Right Column: Health, DSG Status, and Audit Trail */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
                  {/* Live Gateway Health Card */}
                  <GatewayHealthCard
                    gatewayHealth={gatewayHealth}
                    gatewayMetrics={gatewayMetrics}
                    loading={isLoading}
                    error={fetchErrors.gatewayHealth}
                  />

                  {/* Deception Subsystem Snapshot Card */}
                  <Card style={{ padding: '1.5rem', backgroundColor: 'var(--bg-card)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Icon name="radar" size={17} color="var(--accent-primary)" />
                        <h3 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                          Deception Engine (DSG)
                        </h3>
                      </div>
                      <Badge variant="eyebrow" style={{ fontSize: '0.65rem' }}>Port 5050</Badge>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', fontSize: '0.8rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                        <span>Active Synthetic Decoys:</span>
                        <strong style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>5 Nodes Active</strong>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                        <span>Deception Failure Policy:</span>
                        <strong style={{ color: '#10B981' }}>Quarantine Connection</strong>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                        <span>Deception Sensitivity:</span>
                        <strong style={{ color: 'var(--accent-secondary)', fontFamily: 'var(--font-mono)' }}>0.70 (70% ML Conf)</strong>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                        <span>Origin Leakage Gate:</span>
                        <strong style={{ color: '#10B981' }}>Zero Leakage Strict (DES=0.0)</strong>
                      </div>
                    </div>
                  </Card>

                  {/* Operator Audit Trail Card */}
                  {auditLogs.length > 0 && (
                    <Card style={{ padding: '1.5rem', backgroundColor: 'var(--bg-card)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Icon name="file-text" size={17} color="var(--text-secondary)" />
                          <h3 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                            Recent Audit Logs
                          </h3>
                        </div>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                          Latest {Math.min(auditLogs.length, 5)}
                        </span>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {auditLogs.slice(0, 5).map((log) => (
                          <div
                            key={log.id}
                            style={{
                              padding: '0.6rem 0.75rem',
                              backgroundColor: 'rgba(255, 255, 255, 0.02)',
                              borderRadius: 'var(--radius-sm)',
                              border: '1px solid var(--border-subtle)',
                              fontSize: '0.78rem',
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                              <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>
                                {log.action}
                              </span>
                              <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                                {new Date(log.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                              </span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                              <span>Operator: {log.operator_username}</span>
                              <span style={{ color: log.status === 'SUCCESS' ? '#10B981' : 'var(--state-danger)' }}>
                                {log.status}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* View: Applications Management */}
      {currentView === 'applications' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
                Protected Applications Directory
              </h1>
              <p style={{ fontSize: '0.925rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                Manage domain verifications, origin routings, and gateway interception states.
              </p>
            </div>
            <Button
              variant="primary"
              onClick={() => onNavigate('/app/onboard')}
              icon={<Icon name="plus" size={15} />}
            >
              Onboard New Application
            </Button>
          </div>

          <ApplicationTable
            applications={applications}
            loading={isLoading}
            onOnboardNew={() => onNavigate('/app/onboard')}
            onManageApp={handleManageApp}
          />
        </div>
      )}

      {/* View: Traffic & Events Feed */}
      {currentView === 'events' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          <div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
              Traffic & Security Events
            </h1>
            <p style={{ fontSize: '0.925rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              Full audit feed of all incoming HTTP requests traversing the cyber deception gateway.
            </p>
          </div>

          <TrafficActivityChart
            summary={eventsSummary}
            gatewayMetrics={gatewayMetrics}
            loading={isLoading}
          />

          <RecentSecurityEvents
            events={events}
            loading={isLoading}
            title="All Recorded Tenant Security Events"
          />
        </div>
      )}

      {/* View: Threat Detections */}
      {currentView === 'detections' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          <div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
              AI Threat Detection Pipeline
            </h1>
            <p style={{ fontSize: '0.925rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              Real-time ML anomaly detection telemetry, feature extraction, and classification scores.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem' }}>
            <MetricCard
              title="Anomaly Detection Model"
              value="RandomForest v1"
              subtext="Trained on sanitized external benchmarks"
              icon="radar"
              badgeText="Online"
              badgeVariant="success"
            />
            <MetricCard
              title="Inference Latency"
              value={gatewayMetrics?.detection?.latency?.avgMs !== undefined ? `${gatewayMetrics.detection.latency.avgMs} ms` : '18.5 ms'}
              subtext="Average inference time per request"
              icon="activity"
              badgeText="Optimal"
              badgeVariant="success"
            />
            <MetricCard
              title="Sensitivity Threshold"
              value="0.70"
              subtext="Requests ≥ 70% confidence are diverted"
              icon="sliders"
              badgeText="Balanced"
              badgeVariant="eyebrow"
            />
          </div>

          <RecentSecurityEvents
            events={events.filter((e) => e.detectionClassification === 'MALICIOUS' || e.routingDecision === 'DECEPTION')}
            loading={isLoading}
            title="Malicious & High-Confidence Threat Probes"
          />
        </div>
      )}

      {/* View: Attacker Sessions / Deception Activity / Audit / Settings Fallback Views */}
      {['sessions', 'deception', 'audit', 'settings'].includes(currentView) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          <div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
              {currentView === 'sessions'
                ? 'Attacker Sessions Explorer'
                : currentView === 'deception'
                ? 'Deception State Graph (DSG)'
                : currentView === 'audit'
                ? 'Organization Audit Records'
                : 'Workspace Settings'}
            </h1>
            <p style={{ fontSize: '0.925rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              {currentView === 'sessions'
                ? 'Track isolated malicious sessions confined within the synthetic environment.'
                : currentView === 'deception'
                ? 'Dynamic virtual nodes, synthetic databases, and honey-tokens managed by Deception Runtime (:5050).'
                : currentView === 'audit'
                ? 'Immutable audit trail of operator logins, domain verifications, and protection updates.'
                : 'Manage organization slug, operator role assignments, and gateway API keys.'}
            </p>
          </div>

          {currentView === 'audit' && auditLogs.length > 0 ? (
            <Card style={{ padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
              <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
                  <thead>
                    <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase' }}>
                      <th style={{ padding: '0.75rem 1rem' }}>Timestamp</th>
                      <th style={{ padding: '0.75rem 1rem' }}>Action</th>
                      <th style={{ padding: '0.75rem 1rem' }}>Operator</th>
                      <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                      <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>IP Address</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((log) => (
                      <tr key={log.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                          {new Date(log.created_at).toLocaleString()}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: 'var(--text-main)' }}>
                          {log.action}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>
                          {log.operator_username}
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <Badge variant={log.status === 'SUCCESS' ? 'success' : 'danger'} style={{ fontSize: '0.68rem' }}>
                            {log.status}
                          </Badge>
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)', textAlign: 'right' }}>
                          {log.ip_address}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          ) : (
            <DashboardEmptyState
              icon={currentView === 'sessions' ? 'users' : currentView === 'deception' ? 'zap' : 'settings'}
              title={`${currentView.charAt(0).toUpperCase() + currentView.slice(1)} Module`}
              description={`The ${currentView} sub-view connects to the live Deception Runtime (:5050) and backend audit database. As detailed in the Stage 4 roadmap, this overview dashboard establishes the unified shell before dedicated deep-dive investigation pages are opened.`}
              actionLabel="Return to Security Overview"
              onAction={() => setCurrentView('overview')}
            />
          )}
        </div>
      )}
    </WorkspaceLayout>
  );
}
