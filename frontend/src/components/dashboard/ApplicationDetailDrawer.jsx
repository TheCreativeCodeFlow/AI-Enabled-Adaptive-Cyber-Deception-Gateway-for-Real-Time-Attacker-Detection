import React, { useState, useEffect } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Application Detail Drawer
 * Provides deep inspection, real-time DNS TXT verification, protection calibration,
 * and lifecycle controls (Activate, Disable, Edit, Delete).
 */
export default function ApplicationDetailDrawer({
  appId,
  orgId,
  isOpen = false,
  onClose,
  onAppUpdated,
  onAppDeleted,
}) {
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'verification' | 'protection'
  const [appDetails, setAppDetails] = useState(null);
  const [verificationChallenge, setVerificationChallenge] = useState(null);
  const [protectionConfig, setProtectionConfig] = useState(null);

  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [copiedField, setCopiedField] = useState('');

  // Mutation states
  const [isVerifying, setIsVerifying] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);
  const [isActivating, setIsActivating] = useState(false);
  const [isDisabling, setIsDisabling] = useState(false);
  const [isSavingProtection, setIsSavingProtection] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  // Edit metadata form states
  const [isEditing, setIsEditing] = useState(false);
  const [editDisplayName, setEditDisplayName] = useState('');
  const [editEnvironment, setEditEnvironment] = useState('production');
  const [editOrigin, setEditOrigin] = useState('');
  const [isSubmittingEdit, setIsSubmittingEdit] = useState(false);

  // Delete confirmation modal state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showDisableConfirm, setShowDisableConfirm] = useState(false);

  // Fetch full application record on open
  useEffect(() => {
    if (!isOpen || !appId || !orgId) return;

    let isMounted = true;
    setIsLoading(true);
    setErrorMsg('');
    setSuccessMsg('');
    setIsEditing(false);
    setShowDeleteConfirm(false);
    setShowDisableConfirm(false);

    api.getApplication(orgId, appId)
      .then((data) => {
        if (!isMounted) return;
        setAppDetails(data.application);
        setVerificationChallenge(data.verificationChallenge || null);
        setProtectionConfig(data.protection || null);

        setEditDisplayName(data.application.display_name || '');
        setEditEnvironment(data.application.environment || 'production');
        setEditOrigin(data.application.configured_origin || '');
      })
      .catch((err) => {
        if (isMounted) {
          setErrorMsg(err.message || 'Failed to load application details.');
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen, appId, orgId]);

  if (!isOpen) return null;

  const handleCopy = (field, text) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(''), 2000);
  };

  const isVerified = appDetails?.verification_status === 'verified';
  const isActive = appDetails?.activation_status === 'active';

  // 1. Live DNS Verification Check
  const handleVerifyDns = async () => {
    setErrorMsg('');
    setSuccessMsg('');
    setIsVerifying(true);

    try {
      const res = await api.verifyDomain(orgId, appId);
      if (res.verified) {
        setAppDetails((prev) => ({ ...prev, verification_status: 'verified' }));
        setSuccessMsg('Domain ownership successfully verified! Gateway activation unlocked.');
        if (onAppUpdated) onAppUpdated({ ...appDetails, verification_status: 'verified' });
      } else {
        setErrorMsg(res.message || 'DNS TXT verification check incomplete. TXT record not detected yet.');
      }
    } catch (err) {
      setErrorMsg(err.message || 'Verification check failed.');
    } finally {
      setIsVerifying(false);
    }
  };

  // 2. Regenerate Verification Challenge Token
  const handleRegenerateChallenge = async () => {
    setErrorMsg('');
    setSuccessMsg('');
    setIsRegenerating(true);

    try {
      const res = await api.generateVerificationChallenge(orgId, appId, true);
      if (res.verificationChallenge) {
        setVerificationChallenge(res.verificationChallenge);
        setSuccessMsg('New DNS TXT challenge token generated.');
      }
    } catch (err) {
      setErrorMsg(err.message || 'Failed to regenerate challenge token.');
    } finally {
      setIsRegenerating(false);
    }
  };

  // 3. Activate Protection
  const handleActivate = async () => {
    setErrorMsg('');
    setSuccessMsg('');
    setIsActivating(true);

    try {
      const res = await api.activateApplication(orgId, appId);
      setAppDetails(res.application);
      setSuccessMsg('Gateway interception activated! Traffic is now monitored and protected.');
      if (onAppUpdated) onAppUpdated(res.application);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to activate application.');
    } finally {
      setIsActivating(false);
    }
  };

  // 4. Disable Protection
  const handleDisable = async () => {
    setErrorMsg('');
    setSuccessMsg('');
    setIsDisabling(true);

    try {
      const res = await api.disableApplication(orgId, appId);
      setAppDetails(res.application);
      setShowDisableConfirm(false);
      setSuccessMsg('Gateway interception disabled. Traffic is no longer inspected.');
      if (onAppUpdated) onAppUpdated(res.application);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to disable application.');
    } finally {
      setIsDisabling(false);
    }
  };

  // 5. Save Protection Configuration
  const handleSaveProtection = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');
    setIsSavingProtection(true);

    try {
      const res = await api.updateProtection(orgId, appId, {
        routingMode: protectionConfig?.routing_mode || 'shadow',
        deceptionThreshold: protectionConfig?.deception_threshold !== undefined ? parseFloat(protectionConfig.deception_threshold) : 0.70,
        quarantineOnFailure: Boolean(protectionConfig?.quarantine_on_failure),
        emergencyDisable: Boolean(protectionConfig?.emergency_disable),
      });

      setProtectionConfig(res.protection);
      setSuccessMsg('Protection configuration successfully updated.');
    } catch (err) {
      setErrorMsg(err.message || 'Failed to update protection configuration.');
    } finally {
      setIsSavingProtection(false);
    }
  };

  // 6. Save Metadata Edits
  const handleSaveEdit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');

    if (!editDisplayName || editDisplayName.trim().length < 2) {
      setErrorMsg('Display name must be at least 2 characters.');
      return;
    }

    setIsSubmittingEdit(true);
    try {
      const res = await api.updateApplication(orgId, appId, {
        displayName: editDisplayName.trim(),
        environment: editEnvironment,
        configuredOrigin: editOrigin.trim(),
      });

      setAppDetails(res.application);
      setIsEditing(false);
      setSuccessMsg('Application details updated successfully.');
      if (onAppUpdated) onAppUpdated(res.application);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to update application.');
    } finally {
      setIsSubmittingEdit(false);
    }
  };

  // 7. Delete Application
  const handleDeleteApp = async () => {
    setErrorMsg('');
    setIsDeleting(true);

    try {
      await api.deleteApplication(orgId, appId);
      if (onAppDeleted) onAppDeleted(appId);
      onClose();
    } catch (err) {
      setErrorMsg(err.message || 'Failed to delete application.');
      setIsDeleting(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        display: 'flex',
        justifyContent: 'flex-end',
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="drawer-title"
    >
      {/* Semi-transparent Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'absolute',
          inset: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          backdropFilter: 'blur(2px)',
          animation: 'fadeIn 0.2s ease',
        }}
      />

      {/* Drawer Container */}
      <div
        style={{
          position: 'relative',
          width: '100%',
          maxWidth: '680px',
          height: '100%',
          backgroundColor: 'var(--bg-secondary)',
          borderLeft: '1px solid var(--border-medium)',
          boxShadow: '-10px 0 35px rgba(0, 0, 0, 0.5)',
          display: 'flex',
          flexDirection: 'column',
          zIndex: 101,
          animation: 'slideInRight 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        <style>{`
          @keyframes slideInRight {
            from { transform: translateX(100%); }
            to { transform: translateX(0); }
          }
          @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
          }
        `}</style>

        {/* Drawer Header */}
        <div
          style={{
            padding: '1.5rem 1.75rem',
            borderBottom: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-main)',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: '1rem',
          }}
        >
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem', flexWrap: 'wrap' }}>
              <h2
                id="drawer-title"
                style={{
                  fontSize: '1.25rem',
                  fontWeight: 700,
                  color: 'var(--text-main)',
                  letterSpacing: '-0.01em',
                  margin: 0,
                }}
              >
                {appDetails?.display_name || 'Application Details'}
              </h2>
              <Badge variant="neutral" style={{ fontSize: '0.68rem', textTransform: 'capitalize' }}>
                {appDetails?.environment || 'production'}
              </Badge>
              <Badge variant={isVerified ? 'success' : 'warning'} style={{ fontSize: '0.68rem' }}>
                {isVerified ? 'Verified' : 'Unverified'}
              </Badge>
              <Badge variant={isActive ? 'eyebrow' : 'neutral'} style={{ fontSize: '0.68rem' }}>
                {isActive ? 'Active Interception' : 'Inactive'}
              </Badge>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {appDetails?.approved_domain || 'Loading domain...'}
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="btn-subtle"
            style={{ padding: '0.4rem', color: 'var(--text-muted)' }}
            title="Close Drawer"
          >
            <Icon name="x" size={20} />
          </button>
        </div>

        {/* Feedback Banners */}
        {successMsg && (
          <div className="alert-box alert-success" style={{ margin: '1rem 1.75rem 0' }}>
            <Icon name="check-circle" size={16} color="#10B981" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>{successMsg}</div>
          </div>
        )}

        {errorMsg && (
          <div className="alert-box alert-error" style={{ margin: '1rem 1.75rem 0' }}>
            <Icon name="alert-triangle" size={16} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>{errorMsg}</div>
          </div>
        )}

        {/* Drawer Tabs Navigation */}
        <div
          style={{
            display: 'flex',
            padding: '0 1.75rem',
            borderBottom: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-main)',
            gap: '1.5rem',
          }}
        >
          {[
            { id: 'overview', label: 'Identity & Endpoint', icon: 'server' },
            { id: 'verification', label: 'Domain DNS TXT', icon: 'shield' },
            { id: 'protection', label: 'Deception Policy', icon: 'sliders' },
          ].map((tab) => {
            const isTabActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: '0.85rem 0.2rem',
                  fontSize: '0.85rem',
                  fontWeight: isTabActive ? 600 : 500,
                  color: isTabActive ? 'var(--accent-primary)' : 'var(--text-secondary)',
                  borderBottom: `2px solid ${isTabActive ? 'var(--accent-primary)' : 'transparent'}`,
                  backgroundColor: 'transparent',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                }}
              >
                <Icon name={tab.icon} size={15} color={isTabActive ? 'var(--accent-primary)' : 'var(--text-muted)'} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Drawer Body */}
        <div style={{ flexGrow: 1, padding: '1.75rem', overflowY: 'auto' }}>
          {isLoading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ height: '36px', backgroundColor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px' }} />
              <div style={{ height: '120px', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: '6px' }} />
              <div style={{ height: '80px', backgroundColor: 'rgba(255, 255, 255, 0.02)', borderRadius: '6px' }} />
            </div>
          ) : (
            <>
              {/* TAB 1: OVERVIEW */}
              {activeTab === 'overview' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  {/* Metadata Edit Form or Display */}
                  {isEditing ? (
                    <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)' }}>
                      <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '1rem' }}>
                        Edit Application Configuration
                      </h4>
                      <form onSubmit={handleSaveEdit}>
                        <div className="form-group">
                          <label className="form-label" htmlFor="editName">Display Name</label>
                          <input
                            id="editName"
                            type="text"
                            className="form-input"
                            value={editDisplayName}
                            onChange={(e) => setEditDisplayName(e.target.value)}
                            disabled={isSubmittingEdit}
                            maxLength={128}
                          />
                        </div>

                        <div className="form-group">
                          <label className="form-label" htmlFor="editEnv">Environment</label>
                          <select
                            id="editEnv"
                            className="form-input"
                            value={editEnvironment}
                            onChange={(e) => setEditEnvironment(e.target.value)}
                            disabled={isSubmittingEdit}
                          >
                            <option value="production">Production</option>
                            <option value="staging">Staging</option>
                            <option value="development">Development</option>
                          </select>
                        </div>

                        <div className="form-group">
                          <label className="form-label" htmlFor="editOrigin">Configured Upstream Origin URL</label>
                          <input
                            id="editOrigin"
                            type="text"
                            className="form-input"
                            value={editOrigin}
                            onChange={(e) => setEditOrigin(e.target.value)}
                            disabled={isSubmittingEdit}
                          />
                          <span className="form-help-text">
                            Validated against SSRF and cloud metadata addresses (169.254.169.254).
                          </span>
                        </div>

                        <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => setIsEditing(false)}
                            disabled={isSubmittingEdit}
                          >
                            Cancel
                          </Button>
                          <Button
                            type="submit"
                            variant="primary"
                            size="sm"
                            disabled={isSubmittingEdit}
                          >
                            {isSubmittingEdit ? 'Saving...' : 'Save Changes'}
                          </Button>
                        </div>
                      </form>
                    </Card>
                  ) : (
                    <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                        <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                          Application Endpoint & Routing
                        </h4>
                        <Button
                          variant="subtle"
                          size="sm"
                          onClick={() => setIsEditing(true)}
                          icon={<Icon name="edit" size={13} />}
                        >
                          Edit
                        </Button>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.825rem' }}>
                        <div>
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Approved Public Domain</span>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.2rem' }}>
                            <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-primary)', fontSize: '0.85rem' }}>
                              {appDetails?.approved_domain}
                            </code>
                            <button
                              type="button"
                              onClick={() => handleCopy('domain', appDetails?.approved_domain)}
                              className="btn-subtle"
                              style={{ fontSize: '0.7rem', padding: '0.1rem 0.4rem' }}
                            >
                              {copiedField === 'domain' ? 'Copied' : 'Copy'}
                            </button>
                          </div>
                        </div>

                        <div>
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Upstream Origin URL</span>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.2rem' }}>
                            <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-main)', fontSize: '0.85rem' }}>
                              {appDetails?.configured_origin}
                            </code>
                            <button
                              type="button"
                              onClick={() => handleCopy('origin', appDetails?.configured_origin)}
                              className="btn-subtle"
                              style={{ fontSize: '0.7rem', padding: '0.1rem 0.4rem' }}
                            >
                              {copiedField === 'origin' ? 'Copied' : 'Copy'}
                            </button>
                          </div>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
                          <div>
                            <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Created At</span>
                            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                              {appDetails?.created_at ? new Date(appDetails.created_at).toLocaleString() : '—'}
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Last Updated</span>
                            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                              {appDetails?.updated_at ? new Date(appDetails.updated_at).toLocaleString() : '—'}
                            </div>
                          </div>
                        </div>

                        <div>
                          <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Application UUID</span>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.2rem' }}>
                            <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                              {appDetails?.id}
                            </code>
                            <button
                              type="button"
                              onClick={() => handleCopy('appId', appDetails?.id)}
                              className="btn-subtle"
                              style={{ fontSize: '0.7rem', padding: '0.1rem 0.4rem' }}
                            >
                              {copiedField === 'appId' ? 'Copied' : 'Copy UUID'}
                            </button>
                          </div>
                        </div>
                      </div>
                    </Card>
                  )}

                  {/* CNAME Routing Instructions */}
                  <div
                    style={{
                      padding: '1.25rem',
                      backgroundColor: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid var(--border-medium)',
                      borderRadius: 'var(--radius-sm)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                      <Icon name="route" size={15} color="var(--accent-secondary)" />
                      <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        Production DNS Cutover
                      </span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                      Point your public CNAME for <code style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>{appDetails?.approved_domain}</code> to <code style={{ color: 'var(--accent-secondary)', fontFamily: 'var(--font-mono)' }}>localhost:8080</code> (or your gateway ingress host) to enable live inspection.
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: DOMAIN VERIFICATION */}
              {activeTab === 'verification' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  {/* Status Card */}
                  <div
                    style={{
                      padding: '1.25rem',
                      backgroundColor: isVerified ? 'rgba(16, 185, 129, 0.08)' : 'rgba(245, 158, 11, 0.08)',
                      border: `1px solid ${isVerified ? 'rgba(16, 185, 129, 0.35)' : 'rgba(245, 158, 11, 0.35)'}`,
                      borderRadius: 'var(--radius-sm)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                      <Icon
                        name={isVerified ? 'check-circle' : 'alert-triangle'}
                        size={18}
                        color={isVerified ? '#10B981' : 'var(--state-warning)'}
                      />
                      <strong style={{ fontSize: '0.9rem', color: isVerified ? '#10B981' : 'var(--state-warning)' }}>
                        {isVerified ? 'Domain Ownership Cryptographically Verified' : 'Domain Verification Pending'}
                      </strong>
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.45 }}>
                      {isVerified
                        ? `DNS TXT record ownership for ${appDetails?.approved_domain} was confirmed. Traffic interception can be activated safely.`
                        : `To prevent unauthorized traffic interception, publish the DNS TXT record below before activating gateway routing.`}
                    </p>
                  </div>

                  {/* DNS TXT Record Details */}
                  {verificationChallenge ? (
                    <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                        <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                          Required DNS TXT Record
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                          TTL: 300s (5 min)
                        </span>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                        {/* Host / Name */}
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>RECORD HOST / NAME</span>
                            <button
                              type="button"
                              onClick={() => handleCopy('txtHost', verificationChallenge.record_name)}
                              className="btn-subtle"
                              style={{ fontSize: '0.68rem', padding: '0 0.35rem' }}
                            >
                              {copiedField === 'txtHost' ? 'Copied' : 'Copy Host'}
                            </button>
                          </div>
                          <div style={{ padding: '0.5rem 0.75rem', backgroundColor: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-main)' }}>
                            {verificationChallenge.record_name}
                          </div>
                        </div>

                        {/* Token / Value */}
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>RECORD VALUE / TOKEN</span>
                            <button
                              type="button"
                              onClick={() => handleCopy('txtValue', verificationChallenge.token)}
                              className="btn-subtle"
                              style={{ fontSize: '0.68rem', padding: '0 0.35rem' }}
                            >
                              {copiedField === 'txtValue' ? 'Copied' : 'Copy Value'}
                            </button>
                          </div>
                          <div style={{ padding: '0.5rem 0.75rem', backgroundColor: 'rgba(0, 0, 0, 0.3)', border: '1px solid var(--border-medium)', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--accent-secondary)', wordBreak: 'break-all' }}>
                            {verificationChallenge.token}
                          </div>
                        </div>

                        {/* Challenge Meta */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-dim)', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
                          <span>Attempts: {verificationChallenge.attempts_count || 0} / 5</span>
                          <span>Expires: {verificationChallenge.expires_at ? new Date(verificationChallenge.expires_at).toLocaleTimeString() : '24h'}</span>
                        </div>
                      </div>
                    </Card>
                  ) : (
                    <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.825rem' }}>
                      No active verification challenge found.
                    </div>
                  )}

                  {/* Verification Actions */}
                  <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={handleVerifyDns}
                      disabled={isVerifying || isRegenerating}
                      icon={isVerifying ? <Icon name="refresh-cw" size={13} className="spin-animation" /> : <Icon name="check-circle" size={13} />}
                    >
                      {isVerifying ? 'Checking DNS...' : isVerified ? 'Re-verify DNS Record' : 'Verify DNS Record'}
                    </Button>

                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={handleRegenerateChallenge}
                      disabled={isVerifying || isRegenerating}
                      icon={isRegenerating ? <Icon name="refresh-cw" size={13} className="spin-animation" /> : <Icon name="refresh-cw" size={13} />}
                    >
                      {isRegenerating ? 'Generating...' : 'Regenerate Challenge'}
                    </Button>
                  </div>
                </div>
              )}

              {/* TAB 3: PROTECTION & DECEPTION CONFIGURATION */}
              {activeTab === 'protection' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  <form onSubmit={handleSaveProtection}>
                    <Card style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', marginBottom: '1.5rem' }}>
                      <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '1rem' }}>
                        Deception Routing Parameters
                      </h4>

                      {/* Routing Mode */}
                      <div className="form-group">
                        <label className="form-label">Routing Mode</label>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
                          <button
                            type="button"
                            onClick={() => setProtectionConfig((prev) => ({ ...prev, routing_mode: 'active' }))}
                            style={{
                              padding: '0.75rem',
                              borderRadius: 'var(--radius-sm)',
                              backgroundColor: protectionConfig?.routing_mode === 'active' ? 'rgba(91, 156, 255, 0.1)' : 'var(--bg-main)',
                              border: `1px solid ${protectionConfig?.routing_mode === 'active' ? 'var(--accent-primary)' : 'var(--border-medium)'}`,
                              textAlign: 'left',
                              cursor: 'pointer',
                            }}
                          >
                            <div style={{ fontWeight: 600, fontSize: '0.825rem', color: protectionConfig?.routing_mode === 'active' ? 'var(--accent-primary)' : 'var(--text-main)' }}>
                              Active Deception
                            </div>
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>
                              Diverts attacks to synthetic decoys
                            </div>
                          </button>

                          <button
                            type="button"
                            onClick={() => setProtectionConfig((prev) => ({ ...prev, routing_mode: 'shadow' }))}
                            style={{
                              padding: '0.75rem',
                              borderRadius: 'var(--radius-sm)',
                              backgroundColor: protectionConfig?.routing_mode === 'shadow' ? 'rgba(255, 255, 255, 0.05)' : 'var(--bg-main)',
                              border: `1px solid ${protectionConfig?.routing_mode === 'shadow' ? 'var(--text-main)' : 'var(--border-medium)'}`,
                              textAlign: 'left',
                              cursor: 'pointer',
                            }}
                          >
                            <div style={{ fontWeight: 600, fontSize: '0.825rem', color: protectionConfig?.routing_mode === 'shadow' ? 'var(--text-main)' : 'var(--text-secondary)' }}>
                              Shadow Telemetry
                            </div>
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>
                              Observe and score without diversion
                            </div>
                          </button>
                        </div>
                      </div>

                      {/* Threshold Slider */}
                      <div className="form-group">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                          <label className="form-label" style={{ margin: 0 }}>Deception Sensitivity Threshold</label>
                          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-secondary)', fontSize: '0.9rem' }}>
                            {protectionConfig?.deception_threshold ? `${Math.round(parseFloat(protectionConfig.deception_threshold) * 100)}%` : '70%'}
                          </span>
                        </div>
                        <input
                          type="range"
                          min="0.10"
                          max="0.99"
                          step="0.01"
                          value={protectionConfig?.deception_threshold || 0.70}
                          onChange={(e) => setProtectionConfig((prev) => ({ ...prev, deception_threshold: parseFloat(e.target.value) }))}
                          style={{ width: '100%', accentColor: 'var(--accent-primary)', cursor: 'pointer' }}
                        />
                        <span className="form-help-text">
                          Requests with anomaly confidence exceeding this threshold are diverted to the Deception State Graph.
                        </span>
                      </div>

                      {/* Quarantine on Failure */}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)' }}>
                        <label className="form-checkbox-row" style={{ alignItems: 'flex-start' }}>
                          <input
                            type="checkbox"
                            className="form-checkbox-input"
                            checked={protectionConfig?.quarantine_on_failure !== false}
                            onChange={(e) => setProtectionConfig((prev) => ({ ...prev, quarantine_on_failure: e.target.checked }))}
                            style={{ marginTop: '2px' }}
                          />
                          <div>
                            <span style={{ fontSize: '0.825rem', fontWeight: 600, color: 'var(--text-main)' }}>Fail-Safe Quarantine</span>
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', lineHeight: 1.4 }}>
                              Drop suspicious requests if deception nodes are unreachable rather than leaking real origin.
                            </span>
                          </div>
                        </label>

                        <label className="form-checkbox-row" style={{ alignItems: 'flex-start' }}>
                          <input
                            type="checkbox"
                            className="form-checkbox-input"
                            checked={Boolean(protectionConfig?.emergency_disable)}
                            onChange={(e) => setProtectionConfig((prev) => ({ ...prev, emergency_disable: e.target.checked }))}
                            style={{ marginTop: '2px' }}
                          />
                          <div>
                            <span style={{ fontSize: '0.825rem', fontWeight: 600, color: protectionConfig?.emergency_disable ? 'var(--state-danger)' : 'var(--text-main)' }}>
                              Emergency Bypass
                            </span>
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', lineHeight: 1.4 }}>
                              Pass all traffic directly to origin without anomaly inspection.
                            </span>
                          </div>
                        </label>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.25rem' }}>
                        <Button
                          type="submit"
                          variant="primary"
                          size="sm"
                          disabled={isSavingProtection}
                        >
                          {isSavingProtection ? 'Saving...' : 'Save Protection Settings'}
                        </Button>
                      </div>
                    </Card>
                  </form>
                </div>
              )}
            </>
          )}
        </div>

        {/* Drawer Footer: Lifecycle Action Bar */}
        <div
          style={{
            padding: '1.25rem 1.75rem',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-main)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
          }}
        >
          {/* Left: Interception Toggle */}
          <div>
            {isActive ? (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setShowDisableConfirm(true)}
                disabled={isDisabling}
                style={{ color: 'var(--state-danger)' }}
              >
                Disable Interception
              </Button>
            ) : (
              <Button
                variant="primary"
                size="sm"
                onClick={handleActivate}
                disabled={!isVerified || isActivating}
                icon={isActivating ? <Icon name="refresh-cw" size={13} className="spin-animation" /> : <Icon name="zap" size={13} />}
                title={!isVerified ? 'Domain verification required before activation' : 'Activate gateway reverse proxy'}
              >
                {isActivating ? 'Activating...' : 'Activate Protection'}
              </Button>
            )}
          </div>

          {/* Right: Delete Dangerous Action */}
          <button
            type="button"
            onClick={() => setShowDeleteConfirm(true)}
            className="btn-subtle"
            style={{ color: '#EF4444', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <Icon name="trash" size={14} color="#EF4444" />
            <span>Delete App</span>
          </button>
        </div>

        {/* Confirmation Modal: Disable Interception */}
        {showDisableConfirm && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.8)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '1.5rem',
              zIndex: 110,
            }}
          >
            <Card style={{ maxWidth: '420px', width: '100%', padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--state-warning)' }}>
                <Icon name="alert-triangle" size={18} color="var(--state-warning)" />
                <h4 style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
                  Disable Gateway Interception?
                </h4>
              </div>
              <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '1.5rem' }}>
                Disabling interception stops active AI anomaly detection and deception diversion for <strong>{appDetails?.approved_domain}</strong>. Requests will bypass the deception subsystem.
              </p>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <Button variant="secondary" size="sm" onClick={() => setShowDisableConfirm(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleDisable}
                  disabled={isDisabling}
                  style={{ backgroundColor: '#EF4444', borderColor: '#EF4444' }}
                >
                  {isDisabling ? 'Disabling...' : 'Confirm Disable'}
                </Button>
              </div>
            </Card>
          </div>
        )}

        {/* Confirmation Modal: Delete Application */}
        {showDeleteConfirm && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.85)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '1.5rem',
              zIndex: 120,
            }}
          >
            <Card style={{ maxWidth: '420px', width: '100%', padding: '1.75rem', backgroundColor: 'var(--bg-card)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: '#EF4444' }}>
                <Icon name="trash" size={18} color="#EF4444" />
                <h4 style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
                  Permanently Delete Application?
                </h4>
              </div>
              <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '1.5rem' }}>
                Are you sure you want to delete <strong>{appDetails?.display_name}</strong> ({appDetails?.approved_domain})? This will permanently remove the application registration, DNS challenge records, and protection policies. This action cannot be undone.
              </p>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <Button variant="secondary" size="sm" onClick={() => setShowDeleteConfirm(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleDeleteApp}
                  disabled={isDeleting}
                  style={{ backgroundColor: '#EF4444', borderColor: '#EF4444' }}
                >
                  {isDeleting ? 'Deleting...' : 'Delete Permanently'}
                </Button>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
