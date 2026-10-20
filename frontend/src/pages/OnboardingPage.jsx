import React, { useState, useEffect } from 'react';
import OnboardingStepper from '../components/onboarding/OnboardingStepper';
import OnboardingSummary from '../components/onboarding/OnboardingSummary';
import ApplicationDetailsStep from '../components/onboarding/ApplicationDetailsStep';
import DomainVerificationStep from '../components/onboarding/DomainVerificationStep';
import OriginConfigurationStep from '../components/onboarding/OriginConfigurationStep';
import DetectionConfigurationStep from '../components/onboarding/DetectionConfigurationStep';
import PreflightChecksStep from '../components/onboarding/PreflightChecksStep';
import ReviewActivationStep from '../components/onboarding/ReviewActivationStep';
import Button from '../components/ui/Button';
import Icon from '../components/ui/Icon';
import Badge from '../components/ui/Badge';
import { api } from '../services/api';

/**
 * Cyber Deception Gateway — Application Onboarding Wizard Page (/app/onboard)
 * Orchestrates the 6-step application onboarding workflow, manages draft state, and integrates with backend APIs.
 */
export default function OnboardingPage({ operator, onNavigate, onLogout }) {
  const [currentStep, setCurrentStep] = useState(1);
  const [maxCompletedStep, setMaxCompletedStep] = useState(0);

  const [organisations, setOrganisations] = useState([]);
  const [selectedOrgId, setSelectedOrgId] = useState('');
  const [loadingOrg, setLoadingOrg] = useState(true);

  const [appData, setAppData] = useState(null);
  const [verificationChallenge, setVerificationChallenge] = useState(null);
  const [protectionData, setProtectionData] = useState({
    routingMode: 'shadow',
    deceptionThreshold: 0.70,
    emergencyDisable: false,
    quarantineOnFailure: true,
  });

  // Restore draft state from sessionStorage if available
  useEffect(() => {
    try {
      const saved = sessionStorage.getItem('cdg_onboarding_draft');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.appData) setAppData(parsed.appData);
        if (parsed.verificationChallenge) setVerificationChallenge(parsed.verificationChallenge);
        if (parsed.protectionData) setProtectionData(parsed.protectionData);
        if (parsed.currentStep) setCurrentStep(parsed.currentStep);
        if (parsed.maxCompletedStep) setMaxCompletedStep(parsed.maxCompletedStep);
      }
    } catch {
      // Ignore sessionStorage parsing errors
    }
  }, []);

  // Save draft state to sessionStorage
  useEffect(() => {
    try {
      sessionStorage.setItem(
        'cdg_onboarding_draft',
        JSON.stringify({
          appData,
          verificationChallenge,
          protectionData,
          currentStep,
          maxCompletedStep,
        })
      );
    } catch {
      // Ignore sessionStorage quota errors
    }
  }, [appData, verificationChallenge, protectionData, currentStep, maxCompletedStep]);

  // Load operator's organizations on mount
  useEffect(() => {
    let isMounted = true;
    api.getOrganisations()
      .then(async (res) => {
        if (!isMounted) return;
        const orgs = res.organisations || [];
        if (orgs.length > 0) {
          setOrganisations(orgs);
          setSelectedOrgId(orgs[0].id);
        } else {
          // If operator has no org yet, automatically bootstrap a primary workspace
          try {
            const newOrg = await api.createOrganisation('Primary Workspace', 'primary-workspace');
            if (isMounted && newOrg.organisation) {
              setOrganisations([newOrg.organisation]);
              setSelectedOrgId(newOrg.organisation.id);
            }
          } catch (createErr) {
            console.error('Failed to bootstrap organization:', createErr);
          }
        }
      })
      .catch((err) => {
        console.error('Failed to load organizations:', err);
      })
      .finally(() => {
        if (isMounted) setLoadingOrg(false);
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const selectedOrg = organisations.find((o) => o.id === selectedOrgId) || organisations[0];

  const handleStepClick = (stepNumber) => {
    setCurrentStep(stepNumber);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleNextStep = () => {
    setMaxCompletedStep((prev) => Math.max(prev, currentStep));
    setCurrentStep((prev) => Math.min(6, prev + 1));
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleBackStep = () => {
    setCurrentStep((prev) => Math.max(1, prev - 1));
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleAppRegistered = (newApp, challenge) => {
    setAppData(newApp);
    if (challenge) {
      setVerificationChallenge(challenge);
    }
    setMaxCompletedStep((prev) => Math.max(prev, 1));
  };

  const handleResetDraft = () => {
    sessionStorage.removeItem('cdg_onboarding_draft');
    setAppData(null);
    setVerificationChallenge(null);
    setProtectionData({
      routingMode: 'shadow',
      deceptionThreshold: 0.70,
      emergencyDisable: false,
      quarantineOnFailure: true,
    });
    setCurrentStep(1);
    setMaxCompletedStep(0);
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        backgroundColor: 'var(--bg-main)',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Top Application Header */}
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
          zIndex: 40,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <button
            type="button"
            onClick={() => onNavigate('/app')}
            className="btn-subtle"
            style={{
              padding: '0.4rem 0.65rem',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              fontSize: '0.8rem',
            }}
            title="Return to Workspace"
          >
            <Icon name="arrow-left" size={14} />
            <span>Workspace</span>
          </button>

          <span style={{ color: 'var(--border-medium)' }}>/</span>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div
              style={{
                width: '30px',
                height: '30px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--accent-primary-subtle)',
                border: '1px solid var(--accent-primary-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-primary)',
              }}
            >
              <Icon name="shield" size={16} color="var(--accent-primary)" />
            </div>
            <span style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-main)' }}>
              Application Onboarding Wizard
            </span>
          </div>
        </div>

        {/* Right Header Utilities */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          {appData && (
            <button
              type="button"
              onClick={handleResetDraft}
              className="btn-subtle"
              style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}
              title="Clear draft and start onboarding over"
            >
              Reset Draft
            </button>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <span style={{ fontSize: '0.825rem', fontWeight: 600, color: 'var(--text-main)' }}>
              {operator?.username}
            </span>
            <Badge variant="eyebrow" style={{ fontSize: '0.68rem', padding: '0.15rem 0.45rem' }}>
              {operator?.role || 'analyst'}
            </Badge>
          </div>

          <Button
            variant="subtle"
            size="sm"
            onClick={onLogout}
            style={{ color: '#F87171' }}
          >
            Sign Out
          </Button>
        </div>
      </header>

      {/* Main Content Layout */}
      <main style={{ flexGrow: 1, padding: '2.5rem 1.5rem 4rem' }}>
        <div style={{ maxWidth: '1240px', margin: '0 auto', width: '100%' }}>
          {/* Stepper Navigation */}
          <OnboardingStepper
            currentStep={currentStep}
            maxCompletedStep={maxCompletedStep}
            onStepClick={handleStepClick}
          />

          {/* Two-Column Responsive Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'minmax(0, 1fr) 340px',
              gap: '2rem',
              alignItems: 'start',
            }}
          >
            {/* Left Column: Active Step Screen */}
            <section style={{ minWidth: 0 }}>
              {currentStep === 1 && (
                <ApplicationDetailsStep
                  organisations={organisations}
                  selectedOrgId={selectedOrgId}
                  onSelectOrgId={setSelectedOrgId}
                  appData={appData}
                  onAppRegistered={handleAppRegistered}
                  onNext={handleNextStep}
                />
              )}

              {currentStep === 2 && (
                <DomainVerificationStep
                  orgId={selectedOrgId}
                  appData={appData}
                  verificationChallenge={verificationChallenge}
                  onChallengeUpdated={setVerificationChallenge}
                  onAppUpdated={setAppData}
                  onBack={handleBackStep}
                  onNext={handleNextStep}
                />
              )}

              {currentStep === 3 && (
                <OriginConfigurationStep
                  orgId={selectedOrgId}
                  appData={appData}
                  onAppUpdated={setAppData}
                  onBack={handleBackStep}
                  onNext={handleNextStep}
                />
              )}

              {currentStep === 4 && (
                <DetectionConfigurationStep
                  orgId={selectedOrgId}
                  appData={appData}
                  protectionData={protectionData}
                  onProtectionUpdated={setProtectionData}
                  onBack={handleBackStep}
                  onNext={handleNextStep}
                />
              )}

              {currentStep === 5 && (
                <PreflightChecksStep
                  appData={appData}
                  onBack={handleBackStep}
                  onNext={handleNextStep}
                />
              )}

              {currentStep === 6 && (
                <ReviewActivationStep
                  orgId={selectedOrgId}
                  appData={appData}
                  protectionData={protectionData}
                  onAppUpdated={setAppData}
                  onBack={handleBackStep}
                  onGoToStep={handleStepClick}
                  onFinish={() => onNavigate('/app')}
                />
              )}
            </section>

            {/* Right Column: Live Sticky Summary Panel */}
            <OnboardingSummary
              currentStep={currentStep}
              selectedOrg={selectedOrg}
              appData={appData}
              verificationChallenge={verificationChallenge}
              protectionData={protectionData}
            />
          </div>
        </div>
      </main>
    </div>
  );
}
