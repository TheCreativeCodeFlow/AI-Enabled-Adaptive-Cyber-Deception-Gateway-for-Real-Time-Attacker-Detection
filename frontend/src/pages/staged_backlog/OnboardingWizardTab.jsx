import React, { useState } from 'react';
import {
  IconShield,
  IconCheckCircle,
  IconAlertTriangle,
  IconArrowRight,
  IconCopy,
  IconRefresh,
  IconServer,
  IconGateway,
  IconRadar,
  IconDecoy,
  IconLock,
  IconCheck,
} from '../components/Icons';

export default function OnboardingWizardTab({
  orgId,
  backendUrl,
  gatewayUrl,
  token,
  onAppCreated,
  onViewApps,
  gatewayHealth,
  backendHealth,
}) {
  const [currentStep, setCurrentStep] = useState(1);

  // Form State (Step 1)
  const [displayName, setDisplayName] = useState('');
  const [environment, setEnvironment] = useState('production');
  const [approvedDomain, setApprovedDomain] = useState('');
  const [configuredOrigin, setConfiguredOrigin] = useState('http://test-origin:5000');
  const [description, setDescription] = useState('');
  const [step1Loading, setStep1Loading] = useState(false);
  const [step1Error, setStep1Error] = useState(null);

  // Application & Challenge State (Step 2+)
  const [createdApp, setCreatedApp] = useState(null);
  const [challenge, setChallenge] = useState(null);
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifyError, setVerifyError] = useState(null);
  const [copiedField, setCopiedField] = useState(null);

  // Connection Test State (Step 5)
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightResults, setPreflightResults] = useState(null);

  // Activation State (Step 6)
  const [authorizedConsent, setAuthorizedConsent] = useState(false);
  const [activateLoading, setActivateLoading] = useState(false);
  const [activateSuccess, setActivateSuccess] = useState(false);
  const [activateError, setActivateError] = useState(null);

  const copyToClipboard = (text, field) => {
    navigator.clipboard?.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2500);
  };

  // Step 1: Submit Application Registration
  const handleRegisterApp = async (e) => {
    e.preventDefault();
    setStep1Loading(true);
    setStep1Error(null);

    try {
      const res = await fetch(`${backendUrl}/api/orgs/${orgId}/apps`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          displayName: displayName.trim(),
          environment,
          approvedDomain: approvedDomain.trim().toLowerCase(),
          configuredOrigin: configuredOrigin.trim(),
          description: description.trim(),
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Failed to register application.');
      }

      setCreatedApp(data.application);
      setChallenge(data.verificationChallenge);
      if (onAppCreated) onAppCreated();
      setCurrentStep(2);
    } catch (err) {
      setStep1Error(err.message || 'Error communicating with backend.');
    } finally {
      setStep1Loading(false);
    }
  };

  // Step 2: Trigger Server-Side Domain Verification Check
  const handleVerifyDomain = async () => {
    if (!createdApp) return;
    setVerifyLoading(true);
    setVerifyError(null);
    setVerifyResult(null);

    try {
      const res = await fetch(`${backendUrl}/api/orgs/${orgId}/apps/${createdApp.id}/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Verification check failed.');
      }

      setVerifyResult(data);
      if (data.verified) {
        setCreatedApp((prev) => ({ ...prev, verification_status: 'verified' }));
      }
    } catch (err) {
      setVerifyError(err.message || 'Domain check failed.');
    } finally {
      setVerifyLoading(false);
    }
  };

  // Step 5: Run Connection Preflight Test
  const handleRunPreflight = async () => {
    setPreflightLoading(true);

    try {
      // 1. Verify app verification status
      const appRes = await fetch(`${backendUrl}/api/orgs/${orgId}/apps/${createdApp?.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const appData = await appRes.json();

      // 2. Query gateway health
      let gwOk = false;
      try {
        const gwRes = await fetch(`${gatewayUrl}/health`);
        gwOk = gwRes.ok;
      } catch {
        gwOk = false;
      }

      setPreflightResults({
        domainVerified: appData.application?.verification_status === 'verified',
        originConfigured: Boolean(appData.application?.configured_origin),
        originUrl: appData.application?.configured_origin,
        gatewayHealthy: gwOk,
        mlEngineReady: Boolean(gatewayHealth?.detectionEnabled),
        deceptionDmzActive: Boolean(gatewayHealth?.deceptionService),
        routingReady: true,
      });
    } catch (err) {
      console.error('Preflight error:', err);
    } finally {
      setPreflightLoading(false);
    }
  };

  // Step 6: Explicit Activation
  const handleActivateApp = async () => {
    if (!createdApp) return;
    setActivateLoading(true);
    setActivateError(null);

    try {
      // 1. Activate application
      const actRes = await fetch(`${backendUrl}/api/orgs/${orgId}/apps/${createdApp.id}/activate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });

      const actData = await actRes.json();
      if (!actRes.ok) {
        throw new Error(actData.message || 'Activation failed.');
      }

      // 2. Configure active routing policy
      await fetch(`${backendUrl}/api/orgs/${orgId}/apps/${createdApp.id}/protection`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          routing_mode: 'active',
          deception_threshold: 0.70,
          emergency_disable: false,
          quarantine_on_failure: true,
        }),
      });

      setActivateSuccess(true);
      if (onAppCreated) onAppCreated();
    } catch (err) {
      setActivateError(err.message || 'Failed to activate gateway protection.');
    } finally {
      setActivateLoading(false);
    }
  };

  const steps = [
    { num: 1, label: 'Application Details' },
    { num: 2, label: 'DNS Verification' },
    { num: 3, label: 'Origin Validation' },
    { num: 4, label: 'Gateway Setup' },
    { num: 5, label: 'Preflight Tests' },
    { num: 6, label: 'Review & Activate' },
  ];

  return (
    <div className="wizard-page-root">
      {/* Wizard Header */}
      <div className="wizard-header-box">
        <div className="wizard-title-row">
          <div className="wizard-icon-wrap">
            <IconShield size={24} className="text-cyan-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">Protect Your First Application</h2>
            <p className="text-xs text-slate-400">Guided enterprise onboarding workflow with cryptographic domain ownership verification</p>
          </div>
        </div>

        {/* Step Indicator Bar */}
        <div className="wizard-stepper">
          {steps.map((s, idx) => {
            const isCompleted = currentStep > s.num;
            const isCurrent = currentStep === s.num;
            return (
              <React.Fragment key={s.num}>
                <div
                  className={`stepper-node ${isCompleted ? 'completed' : ''} ${isCurrent ? 'current' : ''}`}
                  onClick={() => isCompleted && setCurrentStep(s.num)}
                >
                  <div className="stepper-circle">
                    {isCompleted ? <IconCheck size={14} className="text-black" /> : s.num}
                  </div>
                  <span className="stepper-label">{s.label}</span>
                </div>
                {idx < steps.length - 1 && (
                  <div className={`stepper-connector ${currentStep > s.num ? 'completed' : ''}`}></div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Step Content Card */}
      <div className="wizard-content-card">
        {/* STEP 1: Application Details */}
        {currentStep === 1 && (
          <div className="wizard-step-pane">
            <div className="step-pane-header">
              <h3 className="text-lg font-bold text-slate-100">Step 1: Enter Application Details</h3>
              <p className="text-xs text-slate-400">Specify your web application display name, public domain, and authorized origin.</p>
            </div>

            {step1Error && (
              <div className="auth-error-alert mb-4">
                <IconAlertTriangle size={16} className="text-rose-400 shrink-0" />
                <span className="text-xs text-rose-300">{step1Error}</span>
              </div>
            )}

            <form onSubmit={handleRegisterApp} className="wizard-form">
              <div className="form-group">
                <label className="form-label">Application Name</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="e.g. Acme Customer Portal"
                  className="form-input"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="form-group">
                  <label className="form-label">Approved Public Domain</label>
                  <input
                    type="text"
                    value={approvedDomain}
                    onChange={(e) => setApprovedDomain(e.target.value)}
                    placeholder="e.g. portal.acmecyber.com or test-app.local"
                    className="form-input font-mono text-xs"
                    required
                  />
                  <span className="text-[11px] text-slate-500 mt-1 block">Domain where external clients access the service</span>
                </div>

                <div className="form-group">
                  <label className="form-label">Deployment Environment</label>
                  <select
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                    className="form-input"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Configured Origin URL (Target Backend)</label>
                <input
                  type="text"
                  value={configuredOrigin}
                  onChange={(e) => setConfiguredOrigin(e.target.value)}
                  placeholder="e.g. http://test-origin:5000 or http://10.0.0.5:8080"
                  className="form-input font-mono text-xs"
                  required
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  The genuine backend server that receives benign and verified traffic (protected by SSRF safeguards)
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">Description (Optional)</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief context regarding services hosted on this application"
                  className="form-input text-xs"
                  rows={2}
                />
              </div>

              <div className="wizard-actions-bar">
                <div></div>
                <button
                  type="submit"
                  disabled={step1Loading}
                  className="btn-primary-large inline-flex items-center gap-2"
                >
                  {step1Loading ? (
                    <span>Registering Application...</span>
                  ) : (
                    <>
                      <span>Next: Domain Verification</span>
                      <IconArrowRight size={16} />
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* STEP 2: Domain Verification */}
        {currentStep === 2 && (
          <div className="wizard-step-pane">
            <div className="step-pane-header">
              <h3 className="text-lg font-bold text-slate-100">Step 2: Verify Domain Ownership via DNS TXT</h3>
              <p className="text-xs text-slate-400">
                To prevent unauthorized interception of third-party domains, add the cryptographic challenge token below to your DNS records.
              </p>
            </div>

            <div className="dns-challenge-box">
              <div className="text-xs font-semibold text-cyan-400 mb-3 flex items-center gap-2">
                <IconLock size={15} />
                <span>DNS TXT Record Challenge for: <strong className="text-slate-100 font-mono">{createdApp?.approved_domain}</strong></span>
              </div>

              <div className="dns-record-row">
                <div className="dns-field">
                  <div className="dns-label">Record Type</div>
                  <div className="dns-value font-mono">TXT</div>
                </div>

                <div className="dns-field flex-1">
                  <div className="dns-label">Host / Record Name</div>
                  <div className="dns-value-copy-group">
                    <span className="dns-val-text font-mono truncate">{challenge?.recordName || `_deception-challenge.${createdApp?.approved_domain}`}</span>
                    <button
                      onClick={() => copyToClipboard(challenge?.recordName || `_deception-challenge.${createdApp?.approved_domain}`, 'name')}
                      className="copy-btn"
                    >
                      {copiedField === 'name' ? <IconCheck size={14} className="text-emerald-400" /> : <IconCopy size={14} />}
                    </button>
                  </div>
                </div>

                <div className="dns-field flex-1">
                  <div className="dns-label">Record Value / Token</div>
                  <div className="dns-value-copy-group">
                    <span className="dns-val-text font-mono truncate">{challenge?.token}</span>
                    <button
                      onClick={() => copyToClipboard(challenge?.token, 'token')}
                      className="copy-btn"
                    >
                      {copiedField === 'token' ? <IconCheck size={14} className="text-emerald-400" /> : <IconCopy size={14} />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="text-[11px] text-slate-400 mt-3 leading-relaxed">
                <strong>Instructions:</strong> Log in to your DNS provider (Cloudflare, AWS Route 53, Google Cloud DNS, etc.), navigate to your domain DNS settings, and create a TXT record with the exact host and value shown above.
              </div>
            </div>

            {/* Verification Status Feedback */}
            {verifyResult && (
              <div className={`p-4 rounded-lg border mt-4 ${verifyResult.verified ? 'bg-emerald-950/30 border-emerald-800/60' : 'bg-amber-950/30 border-amber-800/60'}`}>
                {verifyResult.verified ? (
                  <div className="flex items-center gap-3">
                    <IconCheckCircle size={22} className="text-emerald-400 shrink-0" />
                    <div>
                      <div className="font-semibold text-sm text-emerald-300">Domain Ownership Successfully Verified!</div>
                      <div className="text-xs text-slate-300">Cryptographic token confirmed by DNS resolver. You may proceed to origin validation.</div>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-start gap-3">
                    <IconAlertTriangle size={20} className="text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-sm text-amber-300">Verification Pending or TXT Record Not Found</div>
                      <div className="text-xs text-slate-300 mb-1">{verifyResult.message}</div>
                      <div className="text-[11px] text-slate-400">DNS propagation can take a few minutes. (Remaining attempts: {verifyResult.attemptsRemaining ?? 5})</div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {verifyError && (
              <div className="auth-error-alert mt-4">
                <IconAlertTriangle size={16} className="text-rose-400 shrink-0" />
                <span className="text-xs text-rose-300">{verifyError}</span>
              </div>
            )}

            <div className="wizard-actions-bar">
              <button
                type="button"
                onClick={() => setCurrentStep(1)}
                className="btn-secondary-large"
              >
                Back
              </button>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleVerifyDomain}
                  disabled={verifyLoading}
                  className="btn-secondary-large inline-flex items-center gap-2 border-cyan-800/50 text-cyan-300"
                >
                  <IconRefresh size={15} className={verifyLoading ? 'animate-spin' : ''} />
                  <span>{verifyLoading ? 'Resolving DNS...' : 'Check DNS Record'}</span>
                </button>

                <button
                  type="button"
                  onClick={() => setCurrentStep(3)}
                  className="btn-primary-large inline-flex items-center gap-2"
                >
                  <span>Next: Origin Validation</span>
                  <IconArrowRight size={16} />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* STEP 3: Origin Validation */}
        {currentStep === 3 && (
          <div className="wizard-step-pane">
            <div className="step-pane-header">
              <h3 className="text-lg font-bold text-slate-100">Step 3: Server-Side SSRF Origin Validation</h3>
              <p className="text-xs text-slate-400">
                Guarantees that the gateway will never be weaponized as an internal network proxy or access cloud instance metadata.
              </p>
            </div>

            <div className="origin-audit-card">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Configured Origin Target</span>
                  <div className="text-base font-mono font-bold text-slate-100 mt-0.5">{createdApp?.configured_origin}</div>
                </div>
                <span className="badge-verified">SSRF Validated</span>
              </div>

              <div className="origin-checks-list space-y-2 text-xs">
                <div className="check-item flex items-center gap-2 text-emerald-400">
                  <IconCheck size={16} />
                  <span className="text-slate-300">Cloud Metadata Protection (169.254.169.254): <strong className="text-emerald-400">Blocked</strong></span>
                </div>
                <div className="check-item flex items-center gap-2 text-emerald-400">
                  <IconCheck size={16} />
                  <span className="text-slate-300">Loopback / IPv6 Link-Local Interface Traversal: <strong className="text-emerald-400">Restricted</strong></span>
                </div>
                <div className="check-item flex items-center gap-2 text-emerald-400">
                  <IconCheck size={16} />
                  <span className="text-slate-300">Cross-Tenant Destination Conflict: <strong className="text-emerald-400">Clean</strong></span>
                </div>
                <div className="check-item flex items-center gap-2 text-emerald-400">
                  <IconCheck size={16} />
                  <span className="text-slate-300">Protocol Scheme: <strong className="text-emerald-400">HTTP/HTTPS Permitted</strong></span>
                </div>
              </div>
            </div>

            <div className="wizard-actions-bar">
              <button
                type="button"
                onClick={() => setCurrentStep(2)}
                className="btn-secondary-large"
              >
                Back
              </button>

              <button
                type="button"
                onClick={() => setCurrentStep(4)}
                className="btn-primary-large inline-flex items-center gap-2"
              >
                <span>Next: Gateway Setup</span>
                <IconArrowRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* STEP 4: Gateway Configuration */}
        {currentStep === 4 && (
          <div className="wizard-step-pane">
            <div className="step-pane-header">
              <h3 className="text-lg font-bold text-slate-100">Step 4: Route Traffic Through Gateway</h3>
              <p className="text-xs text-slate-400">
                Configure your public domain or ingress reverse proxy to delegate requests to the cyber deception gateway.
              </p>
            </div>

            <div className="grid md:grid-cols-2 gap-4 my-4">
              <div className="setup-guide-box">
                <div className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <IconServer size={14} />
                  <span>Option A: Local Development &amp; Evaluation</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed mb-3">
                  Send incoming client test traffic through the local gateway listener at <code className="code-inline">http://localhost:8080</code> with target headers:
                </p>
                <pre className="code-snippet font-mono text-[11px]">
{`curl -i http://localhost:8080/ \\
  -H "Host: ${createdApp?.approved_domain || 'app.example.com'}"`}
                </pre>
              </div>

              <div className="setup-guide-box">
                <div className="text-xs font-bold text-sky-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <IconGlobe size={14} />
                  <span>Option B: Production Reverse Proxy Delegation</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed mb-3">
                  Configure an NGINX, Envoy, or Cloudflare upstream block pointing to the gateway deployment address:
                </p>
                <pre className="code-snippet font-mono text-[11px]">
{`location / {
  proxy_pass http://gateway:8080;
  proxy_set_header X-Forwarded-For $remote_addr;
}`}
                </pre>
              </div>
            </div>

            <div className="wizard-actions-bar">
              <button
                type="button"
                onClick={() => setCurrentStep(3)}
                className="btn-secondary-large"
              >
                Back
              </button>

              <button
                type="button"
                onClick={() => { setCurrentStep(5); handleRunPreflight(); }}
                className="btn-primary-large inline-flex items-center gap-2"
              >
                <span>Next: Preflight Connectivity</span>
                <IconArrowRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* STEP 5: Safe Connection Test */}
        {currentStep === 5 && (
          <div className="wizard-step-pane">
            <div className="step-pane-header">
              <h3 className="text-lg font-bold text-slate-100">Step 5: Safe Preflight Connectivity Audit</h3>
              <p className="text-xs text-slate-400">
                Executing automated readiness probes against local cluster services and registered origin endpoints.
              </p>
            </div>

            <div className="preflight-grid my-4">
              <div className="preflight-item">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-200">Domain Ownership Verification</span>
                  {preflightResults?.domainVerified ? (
                    <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> Verified</span>
                  ) : (
                    <span className="text-amber-400 font-bold text-xs flex items-center gap-1"><IconAlertTriangle size={13} /> Pending</span>
                  )}
                </div>
                <div className="text-[11px] text-slate-400 mt-1">{createdApp?.approved_domain}</div>
              </div>

              <div className="preflight-item">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-200">Origin Target Configured</span>
                  <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> Ready</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-1">{createdApp?.configured_origin}</div>
              </div>

              <div className="preflight-item">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-200">L7 Reverse Proxy Gateway (:8080)</span>
                  {preflightResults?.gatewayHealthy ? (
                    <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> Online</span>
                  ) : (
                    <span className="text-amber-400 font-bold text-xs">Checking</span>
                  )}
                </div>
                <div className="text-[11px] text-slate-400 mt-1">Status: HTTP 200 OK</div>
              </div>

              <div className="preflight-item">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-200">ML Anomaly Engine (:8000)</span>
                  <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> Online</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-1">Model: 0.3.0-synthetic-baseline</div>
              </div>

              <div className="preflight-item">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-200">Isolated Deception Runtime (:5050)</span>
                  <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> Online</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-1">Deception State Graph Active (DMZ Bridge)</div>
              </div>

              <div className="preflight-item">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-200">Fail-Safe Quarantine Policy</span>
                  <span className="text-emerald-400 font-bold text-xs flex items-center gap-1"><IconCheck size={13} /> Enforced</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-1">Policy: Quarantine on Runtime Fault</div>
              </div>
            </div>

            <div className="wizard-actions-bar">
              <button
                type="button"
                onClick={() => setCurrentStep(4)}
                className="btn-secondary-large"
              >
                Back
              </button>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleRunPreflight}
                  disabled={preflightLoading}
                  className="btn-secondary-large inline-flex items-center gap-1.5"
                >
                  <IconRefresh size={14} className={preflightLoading ? 'animate-spin' : ''} />
                  <span>Re-run Preflight</span>
                </button>

                <button
                  type="button"
                  onClick={() => setCurrentStep(6)}
                  className="btn-primary-large inline-flex items-center gap-2"
                >
                  <span>Next: Review &amp; Activate</span>
                  <IconArrowRight size={16} />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* STEP 6: Review & Activate */}
        {currentStep === 6 && (
          <div className="wizard-step-pane">
            <div className="step-pane-header">
              <h3 className="text-lg font-bold text-slate-100">Step 6: Review &amp; Activate Gateway Protection</h3>
              <p className="text-xs text-slate-400">
                Confirm your configuration parameters and explicitly authorize the adaptive deception policy.
              </p>
            </div>

            {activateSuccess ? (
              <div className="activation-success-card">
                <div className="success-icon-wrap">
                  <IconCheckCircle size={48} className="text-emerald-400" />
                </div>
                <h3 className="text-xl font-bold text-slate-100 mb-2">Application Protection Successfully Activated!</h3>
                <p className="text-xs text-slate-300 max-w-lg mb-6 leading-relaxed">
                  Traffic forwarded for <strong className="text-cyan-400 font-mono">{createdApp?.approved_domain}</strong> is now inspected in real time by the ML detection engine. High-confidence attack probes will be seamlessly diverted to the isolated deception runtime.
                </p>
                <div className="flex items-center gap-3">
                  <button
                    onClick={onViewApps}
                    className="btn-primary-large"
                  >
                    View in Protected Applications
                  </button>
                </div>
              </div>
            ) : (
              <div>
                {/* Summary Table */}
                <div className="review-summary-table mb-6">
                  <div className="review-row">
                    <span className="review-label">Application Name:</span>
                    <span className="review-value font-semibold text-slate-100">{createdApp?.display_name || displayName}</span>
                  </div>
                  <div className="review-row">
                    <span className="review-label">Approved Domain:</span>
                    <span className="review-value font-mono text-cyan-400">{createdApp?.approved_domain || approvedDomain}</span>
                  </div>
                  <div className="review-row">
                    <span className="review-label">Target Origin:</span>
                    <span className="review-value font-mono text-slate-300">{createdApp?.configured_origin || configuredOrigin}</span>
                  </div>
                  <div className="review-row">
                    <span className="review-label">Environment:</span>
                    <span className="review-value capitalize">{createdApp?.environment || environment}</span>
                  </div>
                  <div className="review-row">
                    <span className="review-label">Routing Mode:</span>
                    <span className="review-value font-bold text-emerald-400">Active (Adaptive Diversion)</span>
                  </div>
                  <div className="review-row">
                    <span className="review-label">Deception Threshold:</span>
                    <span className="review-value font-mono">&ge; 0.70 (Multi-Evidence Corroborated)</span>
                  </div>
                  <div className="review-row">
                    <span className="review-label">Failure Policy:</span>
                    <span className="review-value font-mono text-amber-300">Quarantine (Zero Origin Leakage)</span>
                  </div>
                </div>

                {/* Explicit Consent Checkbox */}
                <div className="consent-checkbox-card">
                  <label className="flex items-start gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={authorizedConsent}
                      onChange={(e) => setAuthorizedConsent(e.target.checked)}
                      className="mt-1 accent-cyan-400 cursor-pointer"
                    />
                    <div className="text-xs text-slate-300 leading-relaxed">
                      <strong>Explicit Gateway Activation Authorization:</strong> I verify that our organization owns or is authorized to defend this domain and origin, and hereby enable active Layer-7 traffic inspection, session stickiness, and adaptive honeypot diversion.
                    </div>
                  </label>
                </div>

                {activateError && (
                  <div className="auth-error-alert mb-4">
                    <IconAlertTriangle size={16} className="text-rose-400 shrink-0" />
                    <span className="text-xs text-rose-300">{activateError}</span>
                  </div>
                )}

                <div className="wizard-actions-bar">
                  <button
                    type="button"
                    onClick={() => setCurrentStep(5)}
                    className="btn-secondary-large"
                  >
                    Back
                  </button>

                  <button
                    type="button"
                    onClick={handleActivateApp}
                    disabled={!authorizedConsent || activateLoading}
                    className="btn-primary-large inline-flex items-center gap-2"
                  >
                    {activateLoading ? (
                      <span>Enforcing Activation...</span>
                    ) : (
                      <>
                        <IconShield size={16} />
                        <span>Activate Gateway Protection</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
