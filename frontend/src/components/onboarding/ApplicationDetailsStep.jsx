import React, { useState } from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import Badge from '../ui/Badge';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Step 1: Application Details
 * Collects application identity, target environment, approved domain, and upstream origin.
 */
export default function ApplicationDetailsStep({
  organisations,
  selectedOrgId,
  onSelectOrgId,
  appData,
  onAppRegistered,
  onNext,
}) {
  const [displayName, setDisplayName] = useState(appData?.displayName || appData?.display_name || '');
  const [environment, setEnvironment] = useState(appData?.environment || 'production');
  const [approvedDomain, setApprovedDomain] = useState(appData?.approvedDomain || appData?.approved_domain || '');
  const [configuredOrigin, setConfiguredOrigin] = useState(appData?.configuredOrigin || appData?.configured_origin || '');

  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [apiError, setApiError] = useState('');

  const isExistingApp = Boolean(appData?.id);

  const validate = () => {
    const errs = {};
    if (!displayName || displayName.trim().length < 2 || displayName.trim().length > 128) {
      errs.displayName = 'Display name must be between 2 and 128 characters.';
    }

    if (!approvedDomain || approvedDomain.trim().length < 3) {
      errs.approvedDomain = 'Approved domain is required.';
    } else {
      const clean = approvedDomain.trim().toLowerCase();
      if (clean.includes('://') || clean.includes('/') || clean.includes(':')) {
        errs.approvedDomain = 'Domain name must not include protocol (http://), port, or path.';
      }
    }

    if (!configuredOrigin || configuredOrigin.trim().length === 0) {
      errs.configuredOrigin = 'Upstream origin URL is required.';
    } else {
      try {
        const url = new URL(configuredOrigin.trim());
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
          errs.configuredOrigin = 'Origin must start with http:// or https://.';
        }
      } catch {
        errs.configuredOrigin = 'Origin must be a valid absolute URL (e.g., https://api.internal.corp).';
      }
    }

    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setApiError('');

    if (!validate()) return;
    if (!selectedOrgId) {
      setApiError('Please select or create an organisation first.');
      return;
    }

    setIsSubmitting(true);
    try {
      if (isExistingApp) {
        // Update existing application
        const res = await api.updateApplication(selectedOrgId, appData.id, {
          displayName: displayName.trim(),
          environment,
          configuredOrigin: configuredOrigin.trim(),
        });
        onAppRegistered(res.application, null);
        onNext();
      } else {
        // Register brand new application
        const res = await api.registerApplication(selectedOrgId, {
          displayName: displayName.trim(),
          environment,
          approvedDomain: approvedDomain.trim().toLowerCase(),
          configuredOrigin: configuredOrigin.trim(),
        });
        onAppRegistered(res.application, res.verificationChallenge);
        onNext();
      }
    } catch (err) {
      setApiError(err.message || 'Failed to save application details.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDemoFill = () => {
    const rand = Math.floor(1000 + Math.random() * 9000);
    setDisplayName('Customer Portal API');
    setEnvironment('production');
    setApprovedDomain(`portal-${rand}.acme-corp.com`);
    setConfiguredOrigin(`https://api-internal-${rand}.acme-corp.internal`);
    setErrors({});
    setApiError('');
  };

  return (
    <Card
      style={{
        padding: '2.5rem',
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-medium)',
      }}
    >
      {/* Step Header */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
          <Badge variant="eyebrow" icon={<Icon name="shield" size={12} color="var(--accent-primary)" />}>
            Step 1 of 6: Application Registration
          </Badge>
          <button
            type="button"
            onClick={handleDemoFill}
            className="demo-creds-btn"
            title="Auto-fill with sample test data"
          >
            Fill Demo Defaults
          </button>
        </div>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', marginBottom: '0.4rem' }}>
          Register Web Application
        </h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          Define the protected service identity, deployment environment, and approved public domain name.
        </p>
      </div>

      {apiError && (
        <div className="alert-box alert-error" role="alert">
          <Icon name="alert-triangle" size={18} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>Registration Error: </strong>
            {apiError}
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate>
        {/* Organisation Selector */}
        {organisations && organisations.length > 1 && (
          <div className="form-group">
            <label className="form-label">
              <span>Target Organisation</span>
            </label>
            <select
              className="form-input"
              value={selectedOrgId}
              onChange={(e) => onSelectOrgId(e.target.value)}
              disabled={isExistingApp}
            >
              {organisations.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.name} ({org.slug})
                </option>
              ))}
            </select>
            <span className="form-help-text">
              The application and deception metrics will be scoped to this tenant workspace.
            </span>
          </div>
        )}

        {/* Display Name */}
        <div className="form-group">
          <label className="form-label" htmlFor="displayName">
            <span>Application Display Name</span>
          </label>
          <input
            id="displayName"
            type="text"
            className={`form-input ${errors.displayName ? 'form-input-error' : ''}`}
            placeholder="e.g. Customer Portal API"
            value={displayName}
            onChange={(e) => {
              setDisplayName(e.target.value);
              if (errors.displayName) setErrors((prev) => ({ ...prev, displayName: null }));
            }}
            disabled={isSubmitting}
            maxLength={128}
          />
          {errors.displayName ? (
            <span className="form-error-text">
              <Icon name="alert-triangle" size={14} color="var(--state-danger)" />
              {errors.displayName}
            </span>
          ) : (
            <span className="form-help-text">A descriptive label visible in your operations dashboard and alerts.</span>
          )}
        </div>

        {/* Environment Selection */}
        <div className="form-group">
          <label className="form-label">
            <span>Deployment Environment</span>
          </label>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '0.75rem',
            }}
          >
            {[
              { id: 'production', label: 'Production', desc: 'Live customer-facing workloads' },
              { id: 'staging', label: 'Staging', desc: 'Pre-production validation & QA' },
              { id: 'development', label: 'Development', desc: 'Local testing & integration builds' },
            ].map((env) => {
              const isSelected = environment === env.id;
              return (
                <button
                  key={env.id}
                  type="button"
                  onClick={() => setEnvironment(env.id)}
                  style={{
                    padding: '0.85rem 1rem',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: isSelected ? 'rgba(91, 156, 255, 0.08)' : 'var(--bg-main)',
                    border: `1px solid ${isSelected ? 'var(--accent-primary)' : 'var(--border-medium)'}`,
                    textAlign: 'left',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: isSelected ? 'var(--accent-primary)' : 'var(--text-main)' }}>
                      {env.label}
                    </span>
                    {isSelected && (
                      <span style={{ width: '8px', height: '8px', borderRadius: 'var(--radius-full)', backgroundColor: 'var(--accent-primary)' }} />
                    )}
                  </div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', lineHeight: 1.3, display: 'block' }}>
                    {env.desc}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Approved Domain */}
        <div className="form-group">
          <label className="form-label" htmlFor="approvedDomain">
            <span>Approved Public Domain (FQDN)</span>
            {isExistingApp && <span className="form-label-optional">(Immutable after registration)</span>}
          </label>
          <input
            id="approvedDomain"
            type="text"
            className={`form-input ${errors.approvedDomain ? 'form-input-error' : ''}`}
            placeholder="e.g. portal.acme-corp.com"
            value={approvedDomain}
            onChange={(e) => {
              setApprovedDomain(e.target.value);
              if (errors.approvedDomain) setErrors((prev) => ({ ...prev, approvedDomain: null }));
            }}
            disabled={isExistingApp || isSubmitting}
          />
          {errors.approvedDomain ? (
            <span className="form-error-text">
              <Icon name="alert-triangle" size={14} color="var(--state-danger)" />
              {errors.approvedDomain}
            </span>
          ) : (
            <span className="form-help-text">
              The exact Fully Qualified Domain Name (FQDN) that clients will access. Domain ownership must be proven via DNS TXT in Step 2.
            </span>
          )}
        </div>

        {/* Configured Origin */}
        <div className="form-group">
          <label className="form-label" htmlFor="configuredOrigin">
            <span>Configured Upstream Origin URL</span>
          </label>
          <input
            id="configuredOrigin"
            type="text"
            className={`form-input ${errors.configuredOrigin ? 'form-input-error' : ''}`}
            placeholder="e.g. https://api-internal.acme-corp.internal:443"
            value={configuredOrigin}
            onChange={(e) => {
              setConfiguredOrigin(e.target.value);
              if (errors.configuredOrigin) setErrors((prev) => ({ ...prev, configuredOrigin: null }));
            }}
            disabled={isSubmitting}
          />
          {errors.configuredOrigin ? (
            <span className="form-error-text">
              <Icon name="alert-triangle" size={14} color="var(--state-danger)" />
              {errors.configuredOrigin}
            </span>
          ) : (
            <span className="form-help-text">
              The internal address of your protected application. Clean requests will be proxied here. Validated against SSRF and cloud metadata addresses.
            </span>
          )}
        </div>

        {/* Action Button */}
        <div style={{ marginTop: '2.5rem', display: 'flex', justifyContent: 'flex-end' }}>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            disabled={isSubmitting}
            icon={isSubmitting ? <Icon name="refresh-cw" size={16} className="spin-animation" /> : <Icon name="arrow-right" size={16} />}
            iconPosition="right"
          >
            {isSubmitting ? 'Registering Application...' : isExistingApp ? 'Save & Continue to Verification' : 'Register & Generate DNS Challenge'}
          </Button>
        </div>
      </form>
    </Card>
  );
}
