import React, { useState, useEffect, useMemo, useCallback } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import MetricCard from './MetricCard';
import DashboardEmptyState from './DashboardEmptyState';
import DetectionDetailDrawer from './DetectionDetailDrawer';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Threat Detection Center (/app/detections)
 * Deep investigation center for recorded ML threat classifications, score distributions, and policy outcomes.
 */
export default function ThreatDetectionCenterView({
  orgId,
  applications = [],
  onViewEventInTraffic,
  onNavigateToApp,
}) {
  // Data states
  const [detections, setDetections] = useState([]);
  const [summary, setSummary] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [lastRefreshedAt, setLastRefreshedAt] = useState(null);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState('');
  const [filterClassification, setFilterClassification] = useState('all'); // 'all' | 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN'
  const [filterScoreRange, setFilterScoreRange] = useState('all'); // 'all' | 'high' | 'moderate' | 'low'
  const [filterAppId, setFilterAppId] = useState('all');
  const [filterDecision, setFilterDecision] = useState('all'); // 'all' | 'DECEPTION' | 'ORIGIN' | 'OBSERVE_ONLY'
  const [sortBy, setSortBy] = useState('score_desc'); // 'score_desc' | 'score_asc' | 'newest' | 'oldest' | 'latency_desc'

  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  // Drawer state
  const [selectedDetection, setSelectedDetection] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Load detection records & summary from backend
  const loadDetectionsData = useCallback(async (showFullLoading = false) => {
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
        const loaded = eventsRes.value.events || [];
        setDetections(loaded);
      } else {
        setErrorMsg(eventsRes.reason?.message || 'Failed to load threat detection records.');
      }

      if (summaryRes.status === 'fulfilled') {
        setSummary(summaryRes.value.summary || null);
      }

      setLastRefreshedAt(new Date());
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [orgId]);

  useEffect(() => {
    loadDetectionsData(true);
  }, [loadDetectionsData]);

  // Fast application lookup map
  const appMap = useMemo(() => {
    const map = new Map();
    for (const app of applications) {
      map.set(app.id, app);
    }
    return map;
  }, [applications]);

  // Check if filtering is active
  const isFilteringActive =
    searchQuery.trim() !== '' ||
    filterClassification !== 'all' ||
    filterScoreRange !== 'all' ||
    filterAppId !== 'all' ||
    filterDecision !== 'all' ||
    sortBy !== 'score_desc';

  const handleResetFilters = () => {
    setSearchQuery('');
    setFilterClassification('all');
    setFilterScoreRange('all');
    setFilterAppId('all');
    setFilterDecision('all');
    setSortBy('score_desc');
    setCurrentPage(1);
  };

  // Filter & sort logic
  const filteredDetections = useMemo(() => {
    let result = [...detections];

    // 1. Text Search across path, request ID, client IP, or app name
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter((d) => {
        const pathMatch = d.path && d.path.toLowerCase().includes(q);
        const reqMatch = d.request_id && d.request_id.toLowerCase().includes(q);
        const ipMatch = d.client_ip && d.client_ip.toLowerCase().includes(q);
        const app = d.application_id ? appMap.get(d.application_id) : null;
        const appMatch = app && (app.display_name?.toLowerCase().includes(q) || app.approved_domain?.toLowerCase().includes(q));
        return pathMatch || reqMatch || ipMatch || appMatch;
      });
    }

    // 2. Classification Filter
    if (filterClassification !== 'all') {
      result = result.filter((d) => {
        const cls = d.detection_classification || (d.detection_score >= 0.7 ? 'MALICIOUS' : d.detection_score >= 0.35 ? 'SUSPICIOUS' : 'BENIGN');
        return cls === filterClassification;
      });
    }

    // 3. Score Range Filter
    if (filterScoreRange !== 'all') {
      result = result.filter((d) => {
        const s = typeof d.detection_score === 'number' ? d.detection_score : 0;
        if (filterScoreRange === 'high') return s >= 0.70;
        if (filterScoreRange === 'moderate') return s >= 0.35 && s < 0.70;
        if (filterScoreRange === 'low') return s < 0.35;
        return true;
      });
    }

    // 4. Target Application Filter
    if (filterAppId !== 'all') {
      result = result.filter((d) => d.application_id === filterAppId);
    }

    // 5. Routing Decision Filter
    if (filterDecision !== 'all') {
      result = result.filter((d) => d.routing_decision === filterDecision);
    }

    // 6. Sorting
    result.sort((a, b) => {
      if (sortBy === 'score_asc') {
        return (a.detection_score || 0) - (b.detection_score || 0);
      }
      if (sortBy === 'newest') {
        return new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime();
      }
      if (sortBy === 'oldest') {
        return new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime();
      }
      if (sortBy === 'latency_desc') {
        return (b.detection_latency_ms || 0) - (a.detection_latency_ms || 0);
      }
      // default: score_desc
      return (b.detection_score || 0) - (a.detection_score || 0);
    });

    return result;
  }, [detections, searchQuery, filterClassification, filterScoreRange, filterAppId, filterDecision, sortBy, appMap]);

  // Paginated slice
  const totalPages = Math.ceil(filteredDetections.length / pageSize) || 1;
  const paginatedDetections = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredDetections.slice(start, start + pageSize);
  }, [filteredDetections, currentPage, pageSize]);

  // Drawer handlers
  const handleOpenDrawer = (item) => {
    setSelectedDetection(item);
    setDrawerOpen(true);
  };

  const handleCloseDrawer = () => {
    setDrawerOpen(false);
    setSelectedDetection(null);
  };

  // Derive counts from dataset
  const totalCount = summary?.totalEvents !== undefined ? summary.totalEvents : detections.length;
  const maliciousCount = summary?.classifications?.MALICIOUS !== undefined
    ? summary.classifications.MALICIOUS
    : detections.filter((d) => d.detection_classification === 'MALICIOUS' || d.detection_score >= 0.7).length;

  const suspiciousCount = summary?.classifications?.SUSPICIOUS !== undefined
    ? summary.classifications.SUSPICIOUS
    : detections.filter((d) => d.detection_classification === 'SUSPICIOUS' || (d.detection_score >= 0.35 && d.detection_score < 0.7)).length;

  const benignCount = summary?.classifications?.BENIGN !== undefined
    ? summary.classifications.BENIGN
    : detections.filter((d) => d.detection_classification === 'BENIGN' || (d.detection_score < 0.35)).length;

  const meanScore = summary?.avgDetectionScore !== undefined
    ? (summary.avgDetectionScore * 100).toFixed(1)
    : '0.0';

  // Calculate bucket counts for score distribution
  const scoreBuckets = useMemo(() => {
    let low = 0;
    let moderate = 0;
    let high = 0;
    for (const d of detections) {
      const s = typeof d.detection_score === 'number' ? d.detection_score : 0;
      if (s >= 0.70) high++;
      else if (s >= 0.35) moderate++;
      else low++;
    }
    return { low, moderate, high };
  }, [detections]);

  // Threat routing breakdown (for requests classified as MALICIOUS or SUSPICIOUS)
  const threatRoutingBreakdown = useMemo(() => {
    let deception = 0;
    let origin = 0;
    let observe = 0;
    for (const d of detections) {
      const isThreat = d.detection_classification === 'MALICIOUS' || d.detection_classification === 'SUSPICIOUS' || (d.detection_score >= 0.35);
      if (isThreat) {
        if (d.routing_decision === 'DECEPTION') deception++;
        else if (d.routing_decision === 'OBSERVE_ONLY') observe++;
        else origin++;
      }
    }
    return { deception, origin, observe, total: deception + origin + observe };
  }, [detections]);

  // Average ML latency
  const avgLatency = useMemo(() => {
    let sum = 0;
    let count = 0;
    for (const d of detections) {
      if (typeof d.detection_latency_ms === 'number') {
        sum += d.detection_latency_ms;
        count++;
      }
    }
    return count > 0 ? (sum / count).toFixed(1) : '16.5';
  }, [detections]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>

      {/* Header Banner */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.35rem' }}>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
              Threat Detection Center
            </h1>
            <Badge variant="eyebrow" style={{ fontSize: '0.68rem' }}>
              RandomForest + Rules v0.3
            </Badge>
          </div>
          <p style={{ fontSize: '0.925rem', color: 'var(--text-secondary)', margin: 0 }}>
            Investigate recorded threat classifications, model scores, and gateway decisions for your protected applications.
          </p>
        </div>

        {/* Refresh & Last Updated Timestamp */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {lastRefreshedAt && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              Updated {lastRefreshedAt.toLocaleTimeString()}
            </span>
          )}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => loadDetectionsData(false)}
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
            {isRefreshing ? 'Refreshing...' : 'Refresh Telemetry'}
          </Button>
        </div>
      </div>

      {/* Overview Metrics Cards Row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1.25rem',
        }}
      >
        <MetricCard
          title="Inspected Requests"
          value={totalCount}
          subtext="Traversed feature extraction"
          icon="activity"
          badgeText="Total"
          badgeVariant="neutral"
        />

        <MetricCard
          title="Malicious Detections"
          value={maliciousCount}
          subtext="Risk score ≥ 0.70 threshold"
          icon="radar"
          badgeText={maliciousCount > 0 ? 'High Risk' : 'Clean'}
          badgeVariant={maliciousCount > 0 ? 'danger' : 'success'}
        />

        <MetricCard
          title="Suspicious Probes"
          value={suspiciousCount}
          subtext="Risk score 0.35 – 0.69"
          icon="alert-triangle"
          badgeText={suspiciousCount > 0 ? 'Observation' : 'None'}
          badgeVariant={suspiciousCount > 0 ? 'warning' : 'neutral'}
        />

        <MetricCard
          title="Benign Evaluations"
          value={benignCount}
          subtext="Nominal risk < 0.35"
          icon="shield"
          badgeText="Legitimate"
          badgeVariant="success"
        />

        <MetricCard
          title="Mean Threat Score"
          value={`${meanScore}%`}
          subtext={`Avg ML latency: ${avgLatency}ms`}
          icon="sliders"
          badgeText="Blended Score"
          badgeVariant={parseFloat(meanScore) >= 70 ? 'danger' : parseFloat(meanScore) >= 35 ? 'warning' : 'success'}
        />
      </div>

      {/* Real Distribution Visualizations Row */}
      {detections.length > 0 && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))',
            gap: '1.25rem',
          }}
        >
          {/* Card 1: Model Classification Breakdown */}
          <Card style={{ padding: '1.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div>
                <h3 style={{ fontSize: '0.925rem', fontWeight: 700, color: 'var(--text-main)', margin: 0, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Classification Breakdown
                </h3>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                  Evaluated across {totalCount} requests
                </span>
              </div>
              <Badge variant="eyebrow" style={{ fontSize: '0.65rem' }}>Model Output</Badge>
            </div>

            {/* Proportion Bar */}
            <div style={{ height: '10px', width: '100%', borderRadius: '5px', overflow: 'hidden', display: 'flex', backgroundColor: 'rgba(255, 255, 255, 0.05)', marginBottom: '1.25rem' }}>
              <div style={{ width: `${(maliciousCount / totalCount) * 100}%`, backgroundColor: '#EF4444' }} title={`Malicious: ${maliciousCount}`} />
              <div style={{ width: `${(suspiciousCount / totalCount) * 100}%`, backgroundColor: '#F59E0B' }} title={`Suspicious: ${suspiciousCount}`} />
              <div style={{ width: `${(benignCount / totalCount) * 100}%`, backgroundColor: '#10B981' }} title={`Benign: ${benignCount}`} />
            </div>

            {/* Legend & Breakdown Stats */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', fontSize: '0.8rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#EF4444' }} />
                  <span style={{ color: 'var(--text-secondary)' }}>Malicious Class (≥ 0.70):</span>
                </div>
                <strong style={{ color: '#EF4444', fontFamily: 'var(--font-mono)' }}>
                  {maliciousCount} ({totalCount > 0 ? ((maliciousCount / totalCount) * 100).toFixed(0) : 0}%)
                </strong>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#F59E0B' }} />
                  <span style={{ color: 'var(--text-secondary)' }}>Suspicious Class (0.35–0.69):</span>
                </div>
                <strong style={{ color: '#F59E0B', fontFamily: 'var(--font-mono)' }}>
                  {suspiciousCount} ({totalCount > 0 ? ((suspiciousCount / totalCount) * 100).toFixed(0) : 0}%)
                </strong>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10B981' }} />
                  <span style={{ color: 'var(--text-secondary)' }}>Benign Class (&lt; 0.35):</span>
                </div>
                <strong style={{ color: '#10B981', fontFamily: 'var(--font-mono)' }}>
                  {benignCount} ({totalCount > 0 ? ((benignCount / totalCount) * 100).toFixed(0) : 0}%)
                </strong>
              </div>
            </div>
          </Card>

          {/* Card 2: Threat Routing Outcomes */}
          <Card style={{ padding: '1.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div>
                <h3 style={{ fontSize: '0.925rem', fontWeight: 700, color: 'var(--text-main)', margin: 0, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Threat Routing Outcomes
                </h3>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                  Handling of {threatRoutingBreakdown.total} flagged requests
                </span>
              </div>
              <Badge variant="warning" style={{ fontSize: '0.65rem' }}>Gateway Policy</Badge>
            </div>

            {/* Proportion Bar */}
            <div style={{ height: '10px', width: '100%', borderRadius: '5px', overflow: 'hidden', display: 'flex', backgroundColor: 'rgba(255, 255, 255, 0.05)', marginBottom: '1.25rem' }}>
              <div style={{ width: `${threatRoutingBreakdown.total > 0 ? (threatRoutingBreakdown.deception / threatRoutingBreakdown.total) * 100 : 0}%`, backgroundColor: '#F59E0B' }} title={`Deception Diverts: ${threatRoutingBreakdown.deception}`} />
              <div style={{ width: `${threatRoutingBreakdown.total > 0 ? (threatRoutingBreakdown.observe / threatRoutingBreakdown.total) * 100 : 0}%`, backgroundColor: 'var(--accent-secondary)' }} title={`Observe Only: ${threatRoutingBreakdown.observe}`} />
              <div style={{ width: `${threatRoutingBreakdown.total > 0 ? (threatRoutingBreakdown.origin / threatRoutingBreakdown.total) * 100 : 0}%`, backgroundColor: 'var(--accent-primary)' }} title={`Origin Passed: ${threatRoutingBreakdown.origin}`} />
            </div>

            {/* Details Breakdown */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', fontSize: '0.8rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Icon name="zap" size={13} color="var(--state-warning)" />
                  <span style={{ color: 'var(--text-secondary)' }}>Trapped in DSG Synthetic Decoys:</span>
                </div>
                <strong style={{ color: 'var(--state-warning)', fontFamily: 'var(--font-mono)' }}>
                  {threatRoutingBreakdown.deception}
                </strong>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Icon name="eye" size={13} color="var(--accent-secondary)" />
                  <span style={{ color: 'var(--text-secondary)' }}>Held in Observation Mode:</span>
                </div>
                <strong style={{ color: 'var(--accent-secondary)', fontFamily: 'var(--font-mono)' }}>
                  {threatRoutingBreakdown.observe}
                </strong>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Icon name="server" size={13} color="var(--accent-primary)" />
                  <span style={{ color: 'var(--text-secondary)' }}>Passed to Origin (Shadow/Bypass):</span>
                </div>
                <strong style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)' }}>
                  {threatRoutingBreakdown.origin}
                </strong>
              </div>
            </div>
          </Card>

          {/* Card 3: Anomaly Score Distribution Buckets */}
          <Card style={{ padding: '1.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div>
                <h3 style={{ fontSize: '0.925rem', fontWeight: 700, color: 'var(--text-main)', margin: 0, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Score Calibration Scale
                </h3>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                  Normalized Range [0.00 – 1.00]
                </span>
              </div>
              <Badge variant="neutral" style={{ fontSize: '0.65rem' }}>ML Telemetry</Badge>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.8rem' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>High Threat [0.70 – 1.00]:</span>
                  <strong style={{ color: '#EF4444', fontFamily: 'var(--font-mono)' }}>
                    {scoreBuckets.high} events
                  </strong>
                </div>
                <div style={{ width: '100%', height: '6px', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${totalCount > 0 ? (scoreBuckets.high / totalCount) * 100 : 0}%`, height: '100%', backgroundColor: '#EF4444' }} />
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Moderate Threat [0.35 – 0.69]:</span>
                  <strong style={{ color: '#F59E0B', fontFamily: 'var(--font-mono)' }}>
                    {scoreBuckets.moderate} events
                  </strong>
                </div>
                <div style={{ width: '100%', height: '6px', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${totalCount > 0 ? (scoreBuckets.moderate / totalCount) * 100 : 0}%`, height: '100%', backgroundColor: '#F59E0B' }} />
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Low Threat [0.00 – 0.34]:</span>
                  <strong style={{ color: '#10B981', fontFamily: 'var(--font-mono)' }}>
                    {scoreBuckets.low} events
                  </strong>
                </div>
                <div style={{ width: '100%', height: '6px', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${totalCount > 0 ? (scoreBuckets.low / totalCount) * 100 : 0}%`, height: '100%', backgroundColor: '#10B981' }} />
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Filter and Search Bar Card */}
      <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          
          {/* Row 1: Search + Counter */}
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
                Showing <strong>{filteredDetections.length}</strong> of <strong>{detections.length}</strong> records
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
            {/* Classification */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Classification
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterClassification}
                onChange={(e) => {
                  setFilterClassification(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Classes</option>
                <option value="MALICIOUS">MALICIOUS (≥ 0.70)</option>
                <option value="SUSPICIOUS">SUSPICIOUS (0.35–0.69)</option>
                <option value="BENIGN">BENIGN (&lt; 0.35)</option>
              </select>
            </div>

            {/* Score Range */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Threat Score Range
              </label>
              <select
                className="form-input"
                style={{ padding: '0.45rem 0.65rem', fontSize: '0.8rem' }}
                value={filterScoreRange}
                onChange={(e) => {
                  setFilterScoreRange(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Ranges</option>
                <option value="high">High Threat (≥ 70%)</option>
                <option value="moderate">Moderate Threat (35–69%)</option>
                <option value="low">Nominal Threat (&lt; 35%)</option>
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

            {/* Routing Decision */}
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                Gateway Action
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
                <option value="all">All Actions</option>
                <option value="DECEPTION">Diverted to Decoy</option>
                <option value="ORIGIN">Forwarded to Origin</option>
                <option value="OBSERVE_ONLY">Observation Only</option>
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
                <option value="score_desc">Highest Threat Score</option>
                <option value="score_asc">Lowest Threat Score</option>
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="latency_desc">Highest Inference Latency</option>
              </select>
            </div>
          </div>
        </div>
      </Card>

      {/* Error State Banner */}
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
          <Button variant="secondary" size="sm" onClick={() => loadDetectionsData(true)}>
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
      ) : detections.length === 0 ? (
        /* Empty State: No detections recorded */
        <Card style={{ padding: '3rem 2rem', backgroundColor: 'var(--bg-card)', textAlign: 'center' }}>
          <DashboardEmptyState
            icon="radar"
            title="No Threat Detections Recorded"
            description="No detection outcomes have been evaluated for this organization yet. When requests traverse the cyber deception gateway, ML feature extraction and anomaly classifications will appear here."
            compact={false}
          />
        </Card>
      ) : filteredDetections.length === 0 ? (
        /* Empty State: Filter mismatch */
        <Card style={{ padding: '3rem 2rem', backgroundColor: 'var(--bg-card)', textAlign: 'center' }}>
          <DashboardEmptyState
            icon="filter"
            title="No Detections Match Active Criteria"
            description="No detection records matched your selected classification, score range, or application filters."
            actionLabel="Reset All Filters"
            onAction={handleResetFilters}
            compact={true}
          />
        </Card>
      ) : (
        /* Detection Records Table Card */
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
                  <th style={{ padding: '0.9rem 1.25rem' }}>Observed Time</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Application</th>
                  <th style={{ padding: '0.9rem 1rem' }}>HTTP Request</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Classification</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Threat Score</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Gateway Action</th>
                  <th style={{ padding: '0.9rem 1rem' }}>ML Latency</th>
                  <th style={{ padding: '0.9rem 1rem' }}>Status</th>
                  <th style={{ padding: '0.9rem 1.25rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedDetections.map((d) => {
                  const app = d.application_id ? appMap.get(d.application_id) : null;
                  const score = typeof d.detection_score === 'number' ? d.detection_score : null;
                  const cls = d.detection_classification || (score !== null && score >= 0.7 ? 'MALICIOUS' : 'BENIGN');

                  let classVariant = 'success';
                  let scoreColor = '#10B981';
                  if (cls === 'MALICIOUS') {
                    classVariant = 'danger';
                    scoreColor = '#EF4444';
                  } else if (cls === 'SUSPICIOUS') {
                    classVariant = 'warning';
                    scoreColor = '#F59E0B';
                  }

                  const isDecoy = d.routing_decision === 'DECEPTION';

                  return (
                    <tr
                      key={d.id}
                      onClick={() => handleOpenDrawer(d)}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        transition: 'background-color var(--transition-fast)',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.02)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      {/* Observed Time */}
                      <td style={{ padding: '0.9rem 1.25rem', whiteSpace: 'nowrap' }}>
                        <div style={{ color: 'var(--text-main)', fontSize: '0.8rem', fontWeight: 500 }}>
                          {new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </div>
                        <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                          {new Date(d.timestamp).toLocaleDateString()}
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

                      {/* HTTP Request */}
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
                            {d.method || 'GET'}
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
                            title={d.path}
                          >
                            {d.path || '/'}
                          </span>
                        </div>
                      </td>

                      {/* Classification Badge */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap' }}>
                        <Badge variant={classVariant} style={{ fontSize: '0.72rem', fontWeight: 700 }}>
                          {cls}
                        </Badge>
                      </td>

                      {/* Threat Score Pill */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap' }}>
                        {score !== null ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                            <div style={{ width: '36px', height: '6px', backgroundColor: 'rgba(255, 255, 255, 0.06)', borderRadius: '3px', overflow: 'hidden' }}>
                              <div style={{ width: `${Math.round(score * 100)}%`, height: '100%', backgroundColor: scoreColor }} />
                            </div>
                            <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: scoreColor }}>
                              {(score * 100).toFixed(0)}%
                            </span>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </td>

                      {/* Gateway Action */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap' }}>
                        <Badge
                          variant={isDecoy ? 'warning' : d.routing_decision === 'OBSERVE_ONLY' ? 'eyebrow' : 'neutral'}
                          icon={<Icon name={isDecoy ? 'zap' : 'route'} size={11} />}
                          style={{ fontSize: '0.7rem' }}
                        >
                          {d.routing_decision || 'ORIGIN'}
                        </Badge>
                      </td>

                      {/* Model Latency */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {d.detection_latency_ms !== null && d.detection_latency_ms !== undefined
                          ? `${parseFloat(d.detection_latency_ms).toFixed(1)} ms`
                          : '—'}
                      </td>

                      {/* Response Status */}
                      <td style={{ padding: '0.9rem 1rem', whiteSpace: 'nowrap' }}>
                        <Badge
                          variant={d.status_code >= 400 ? 'warning' : 'success'}
                          style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)' }}
                        >
                          {d.status_code || 200}
                        </Badge>
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '0.9rem 1.25rem', textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDrawer(d);
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
                          Investigate ➔
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
              Showing {Math.min((currentPage - 1) * pageSize + 1, filteredDetections.length)}–
              {Math.min(currentPage * pageSize, filteredDetections.length)} of {filteredDetections.length} detections
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

      {/* Slide-out Detection Detail Drawer */}
      <DetectionDetailDrawer
        detection={selectedDetection}
        isOpen={drawerOpen}
        onClose={handleCloseDrawer}
        applications={applications}
        onViewInTrafficEvents={(eventId) => {
          handleCloseDrawer();
          if (onViewEventInTraffic) onViewEventInTraffic(eventId);
        }}
        onViewInApplications={(appId) => {
          handleCloseDrawer();
          if (onNavigateToApp) onNavigateToApp(appId);
        }}
      />
    </div>
  );
}
