import React from 'react';
import Card from '../ui/Card';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Core Capabilities Section
 * Five structured capability cards with factual descriptions and restrained styling.
 */
export default function CoreCapabilities() {
  const capabilities = [
    {
      id: 'detection',
      title: 'AI-Powered Threat Detection',
      description: 'Analyze application requests in real-time and identify suspicious or potentially malicious patterns using calibrated machine learning models.',
      icon: 'radar',
      tag: 'Real-Time Inference',
    },
    {
      id: 'routing',
      title: 'Policy-Controlled Routing',
      description: 'Apply configured routing decisions to incoming requests based on detection results, confidence thresholds, and system protection policies.',
      icon: 'route',
      tag: 'Dynamic Dispatch',
    },
    {
      id: 'deception',
      title: 'Adaptive Cyber Deception',
      description: 'Use the isolated deception environment to support controlled investigation of suspicious activity without exposing upstream resources.',
      icon: 'layers',
      tag: 'Synthetic DSG',
    },
    {
      id: 'analysis',
      title: 'Attacker Behavior Analysis',
      description: 'Observe suspicious sessions and record multi-request interaction timelines to support security investigation and threat evaluation.',
      icon: 'activity',
      tag: 'Session Tracking',
    },
    {
      id: 'protection',
      title: 'Application Protection',
      description: 'Bring application traffic through a reverse-proxy gateway architecture with verified domain ownership and configurable origin settings.',
      icon: 'server',
      tag: 'Origin Shielding',
    },
  ];

  return (
    <section id="capabilities" className="section section-alt">
      <div className="container">
        <div className="section-header">
          <span className="section-eyebrow">Defensive Capabilities</span>
          <h2 className="section-title">Built for Controlled Application Defense</h2>
          <p className="section-description">
            A coordinated set of defensive capabilities designed to evaluate incoming HTTP traffic, isolate suspicious actors, and preserve upstream service integrity.
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: '1.75rem',
          }}
        >
          {capabilities.map((cap) => (
            <Card
              key={cap.id}
              style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '1.25rem',
                  }}
                >
                  <div
                    style={{
                      width: '44px',
                      height: '44px',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'var(--accent-primary-subtle)',
                      border: '1px solid var(--accent-primary-border)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: 'var(--accent-primary)',
                    }}
                  >
                    <Icon name={cap.icon} size={22} color="var(--accent-primary)" />
                  </div>
                  <span
                    style={{
                      fontSize: '0.72rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-muted)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                      backgroundColor: 'rgba(255, 255, 255, 0.03)',
                      padding: '0.2rem 0.5rem',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    {cap.tag}
                  </span>
                </div>

                <h3
                  style={{
                    fontSize: '1.2rem',
                    fontWeight: 700,
                    color: 'var(--text-main)',
                    marginBottom: '0.75rem',
                    letterSpacing: '-0.01em',
                  }}
                >
                  {cap.title}
                </h3>

                <p
                  style={{
                    fontSize: '0.925rem',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.6,
                    marginBottom: '1.5rem',
                  }}
                >
                  {cap.description}
                </p>
              </div>

              <div
                style={{
                  paddingTop: '1rem',
                  borderTop: '1px solid rgba(28, 40, 63, 0.6)',
                  fontSize: '0.8rem',
                  color: 'var(--accent-secondary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  fontWeight: 600,
                }}
              >
                <span>Core Architectural Component</span>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
