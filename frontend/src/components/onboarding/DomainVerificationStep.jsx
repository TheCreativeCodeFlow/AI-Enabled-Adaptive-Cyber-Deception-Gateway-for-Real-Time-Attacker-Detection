import React, { useState } from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import Badge from '../ui/Badge';
import { api } from '../../services/api';

/**
 * Cyber Deception Gateway — Step 2: Domain Ownership Verification
 * Displays DNS TXT record challenge, performs real-time verification checks, and manages challenge regeneration.
 */
export default function DomainVerificationStep({
  orgId,
  appData,
  verificationChallenge,
  onChallengeUpdated,
  onAppUpdated,
  onBack,
  onNext,
}) {
  const [isVerifying, setIsVerifying] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);
  const [copiedField, setCopiedField] = useState('');
  const [verificationResult, setVerificationResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  const isVerified = appData?.verification_status === 'verified';
  const domain = appData?.approvedDomain || appData?.approved_domain || 'example.com';
  const recordName = verificationChallenge?.recordName || verificationChallenge?.record_name || `_deception-challenge.${domain}`;
  const token = verificationChallenge?.token || 'deception-verify-pending...';
  const attemptsRemaining = verificationResult?.attemptsRemaining !== undefined ? verificationResult.attemptsRemaining : 5;

  const handleCopy = (field, text) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(''), 2000);
  };

  const handleVerify = async () => {
    setErrorMsg('');
    setIsVerifying(true);
    setVerificationResult(null);

    try {
      const res = await api.verifyDomain(orgId, appData.id);
      setVerificationResult(res);

      if (res.verified) {
        onAppUpdated({ ...appData, verification_status: 'verified' });
      } else {
        onAppUpdated({ ...appData, verification_status: 'unverified' });
      }
    } catch (err) {
      setErrorMsg(err.message || 'Error occurred while contacting verification service.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleRegenerate = async () => {
    setErrorMsg('');
    setIsRegenerating(true);
    setVerificationResult(null);

    try {
      const res = await api.generateVerificationChallenge(orgId, appData.id, true);
      if (res.verificationChallenge) {
        onChallengeUpdated(res.verificationChallenge);
      }
    } catch (err) {
      setErrorMsg(err.message || 'Failed to regenerate verification token.');
    } finally {
      setIsRegenerating(false);
    }
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
          <Badge
            variant={isVerified ? 'success' : 'eyebrow'}
            icon={<Icon name={isVerified ? 'check-circle' : 'shield'} size={12} color={isVerified ? '#10B981' : 'var(--accent-primary)'} />}
          >
            {isVerified ? 'Domain Ownership Verified' : 'Step 2 of 6: Domain Verification'}
          </Badge>
          <span
            style={{
              fontSize: '0.75rem',
              fontFamily: 'var(--font-mono)',
              color: isVerified ? '#10B981' : 'var(--state-warning)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: 'var(--radius-full)',
                backgroundColor: isVerified ? '#10B981' : 'var(--state-warning)',
              }}
            />
            {isVerified ? 'Verified' : 'Verification Pending'}
          </span>
        </div>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em', marginBottom: '0.4rem' }}>
          Verify Domain Ownership
        </h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          Publish the following cryptographic DNS TXT challenge to confirm your authority over <code style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>{domain}</code>.
        </p>
      </div>

      {/* Verification Success Alert */}
      {isVerified && (
        <div className="alert-box alert-success" style={{ marginBottom: '1.75rem' }}>
          <Icon name="check-circle" size={20} color="#10B981" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong style={{ display: 'block', fontSize: '0.925rem', marginBottom: '0.15rem' }}>
              Domain Ownership Successfully Verified!
            </strong>
            The cryptographic signature for <code style={{ fontFamily: 'var(--font-mono)' }}>{domain}</code> has been confirmed. Gateway routing activation is unlocked.
          </div>
        </div>
      )}

      {/* Verification Failure / Pending Alert */}
      {verificationResult && !verificationResult.verified && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.75rem' }}>
          <Icon name="alert-triangle" size={20} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong style={{ display: 'block', fontSize: '0.925rem', marginBottom: '0.15rem' }}>
              Verification Check Incomplete
            </strong>
            {verificationResult.message || 'TXT record not detected yet.'}
            <div style={{ marginTop: '0.4rem', fontSize: '0.8rem', opacity: 0.85 }}>
              DNS propagation can take several minutes depending on your DNS provider's TTL. ({attemptsRemaining} check attempts remaining before token expiration).
            </div>
          </div>
        </div>
      )}

      {errorMsg && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.75rem' }}>
          <Icon name="alert-triangle" size={18} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>{errorMsg}</div>
        </div>
      )}

      {/* DNS TXT Challenge Configuration Box */}
      <div
        style={{
          backgroundColor: 'var(--bg-main)',
          border: '1px solid var(--border-medium)',
          borderRadius: 'var(--radius-sm)',
          padding: '1.5rem',
          marginBottom: '2rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Icon name="terminal" size={16} color="var(--accent-secondary)" />
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              DNS TXT Record Instructions
            </span>
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            TTL: 300 seconds (5 min)
          </span>
        </div>

        {/* Record Type & Host */}
        <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '1rem', marginBottom: '1rem' }}>
          <div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.3rem', fontWeight: 600 }}>
              RECORD TYPE
            </span>
            <div
              style={{
                padding: '0.65rem 0.85rem',
                backgroundColor: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                fontWeight: 700,
                color: 'var(--accent-primary)',
              }}
            >
              TXT
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>
                RECORD NAME / HOST
              </span>
              <button
                type="button"
                onClick={() => handleCopy('host', recordName)}
                className="btn-subtle"
                style={{ fontSize: '0.72rem', padding: '0.1rem 0.4rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
              >
                <Icon name={copiedField === 'host' ? 'check' : 'copy'} size={12} color={copiedField === 'host' ? '#10B981' : 'var(--text-secondary)'} />
                {copiedField === 'host' ? 'Copied' : 'Copy Host'}
              </button>
            </div>
            <div
              style={{
                padding: '0.65rem 0.85rem',
                backgroundColor: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                color: 'var(--text-main)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={recordName}
            >
              {recordName}
            </div>
          </div>
        </div>

        {/* Record Value / Token */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>
              RECORD VALUE / TOKEN (160-BIT CHALLENGE)
            </span>
            <button
              type="button"
              onClick={() => handleCopy('token', token)}
              className="btn-subtle"
              style={{ fontSize: '0.72rem', padding: '0.1rem 0.4rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
            >
              <Icon name={copiedField === 'token' ? 'check' : 'copy'} size={12} color={copiedField === 'token' ? '#10B981' : 'var(--text-secondary)'} />
              {copiedField === 'token' ? 'Copied' : 'Copy Value'}
            </button>
          </div>
          <div
            style={{
              padding: '0.75rem 0.85rem',
              backgroundColor: 'rgba(0, 0, 0, 0.35)',
              border: '1px solid var(--border-medium)',
              borderRadius: 'var(--radius-sm)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.825rem',
              color: 'var(--accent-secondary)',
              wordBreak: 'break-all',
              userSelect: 'all',
            }}
          >
            {token}
          </div>
        </div>
      </div>

      {/* Action Trigger Buttons */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          paddingBottom: '2rem',
          borderBottom: '1px solid var(--border-subtle)',
          marginBottom: '2rem',
        }}
      >
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button
            variant="primary"
            onClick={handleVerify}
            disabled={isVerifying || isRegenerating}
            icon={isVerifying ? <Icon name="refresh-cw" size={16} className="spin-animation" /> : <Icon name="check-circle" size={16} />}
          >
            {isVerifying ? 'Checking DNS TXT Record...' : isVerified ? 'Re-verify DNS Record' : 'Verify DNS Record'}
          </Button>

          <Button
            variant="secondary"
            onClick={handleRegenerate}
            disabled={isVerifying || isRegenerating}
            icon={isRegenerating ? <Icon name="refresh-cw" size={14} className="spin-animation" /> : <Icon name="refresh-cw" size={14} />}
          >
            {isRegenerating ? 'Regenerating...' : 'Regenerate Challenge'}
          </Button>
        </div>

        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Expires in 24 hours · Max 5 resolution checks per challenge
        </span>
      </div>

      {/* Mandatory Security Rationale */}
      <div
        style={{
          padding: '1.25rem',
          backgroundColor: 'rgba(255, 255, 255, 0.02)',
          borderRadius: 'var(--radius-sm)',
          border: '1px dashed var(--border-subtle)',
          marginBottom: '2.5rem',
          fontSize: '0.825rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.55,
        }}
      >
        <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '0.25rem' }}>
          Security Guarantee:
        </strong>
        Domain verification is an cryptographic anti-spoofing control. It ensures that an operator cannot register domains belonging to third parties or other tenants on the Gateway.
      </div>

      {/* Navigation Buttons */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button
          variant="secondary"
          onClick={onBack}
          icon={<Icon name="arrow-left" size={16} />}
        >
          Back to Details
        </Button>

        <Button
          variant="primary"
          onClick={onNext}
          icon={<Icon name="arrow-right" size={16} />}
          iconPosition="right"
        >
          Continue to Upstream Origin
        </Button>
      </div>
    </Card>
  );
}
