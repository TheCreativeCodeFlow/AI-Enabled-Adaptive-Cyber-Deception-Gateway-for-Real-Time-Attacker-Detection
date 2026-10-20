import React from 'react';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Onboarding Stepper
 * Displays the 6 onboarding phases with interactive navigation for visited steps.
 */
export default function OnboardingStepper({ currentStep, maxCompletedStep, onStepClick }) {
  const steps = [
    { number: 1, title: 'App Details', desc: 'Identity & Environment' },
    { number: 2, title: 'Domain Verification', desc: 'DNS TXT Ownership' },
    { number: 3, title: 'Upstream Origin', desc: 'SSRF & Gateway Routing' },
    { number: 4, title: 'Deception Policy', desc: 'Mode & Sensitivity' },
    { number: 5, title: 'Preflight Checks', desc: 'System Readiness' },
    { number: 6, title: 'Review & Activate', desc: 'Cutover & Activation' },
  ];

  return (
    <nav aria-label="Onboarding Progress" style={{ marginBottom: '2.5rem' }}>
      <ol
        style={{
          listStyle: 'none',
          padding: 0,
          margin: 0,
          display: 'grid',
          gridTemplateColumns: 'repeat(6, 1fr)',
          gap: '0.75rem',
        }}
      >
        {steps.map((step) => {
          const isCompleted = step.number < currentStep || (maxCompletedStep >= step.number && currentStep !== step.number);
          const isActive = step.number === currentStep;
          const isClickable = step.number <= maxCompletedStep + 1;

          let borderColor = 'var(--border-subtle)';
          let bgColor = 'rgba(255, 255, 255, 0.02)';
          let textColor = 'var(--text-muted)';
          let badgeBg = 'rgba(255, 255, 255, 0.05)';
          let badgeColor = 'var(--text-muted)';

          if (isActive) {
            borderColor = 'var(--accent-primary)';
            bgColor = 'rgba(91, 156, 255, 0.08)';
            textColor = 'var(--text-main)';
            badgeBg = 'var(--accent-primary)';
            badgeColor = '#050A14';
          } else if (isCompleted) {
            borderColor = 'rgba(16, 185, 129, 0.4)';
            bgColor = 'rgba(16, 185, 129, 0.04)';
            textColor = 'var(--text-main)';
            badgeBg = 'rgba(16, 185, 129, 0.2)';
            badgeColor = '#10B981';
          }

          return (
            <li key={step.number} style={{ minWidth: 0 }}>
              <button
                type="button"
                onClick={() => isClickable && onStepClick(step.number)}
                disabled={!isClickable}
                style={{
                  width: '100%',
                  padding: '0.85rem 0.75rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: bgColor,
                  border: `1px solid ${borderColor}`,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.35rem',
                  textAlign: 'left',
                  cursor: isClickable ? 'pointer' : 'not-allowed',
                  opacity: !isClickable ? 0.5 : 1,
                  transition: 'all var(--transition-fast)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                  <span
                    style={{
                      width: '22px',
                      height: '22px',
                      borderRadius: 'var(--radius-full)',
                      backgroundColor: badgeBg,
                      color: badgeColor,
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    {isCompleted ? <Icon name="check" size={12} color={badgeColor} /> : step.number}
                  </span>
                  {isActive && (
                    <span
                      style={{
                        width: '6px',
                        height: '6px',
                        borderRadius: 'var(--radius-full)',
                        backgroundColor: 'var(--accent-primary)',
                        boxShadow: '0 0 8px var(--accent-primary)',
                      }}
                    />
                  )}
                </div>

                <div style={{ marginTop: '0.15rem' }}>
                  <div
                    style={{
                      fontSize: '0.82rem',
                      fontWeight: 600,
                      color: textColor,
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {step.title}
                  </div>
                  <div
                    style={{
                      fontSize: '0.68rem',
                      color: 'var(--text-dim)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {step.desc}
                  </div>
                </div>
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
