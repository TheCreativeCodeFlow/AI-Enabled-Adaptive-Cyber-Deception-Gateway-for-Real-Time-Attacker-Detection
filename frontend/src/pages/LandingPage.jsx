import React from 'react';
import Navbar from '../components/layout/Navbar';
import Footer from '../components/layout/Footer';
import Hero from '../components/landing/Hero';
import CoreCapabilities from '../components/landing/CoreCapabilities';
import HowItWorks from '../components/landing/HowItWorks';
import ArchitectureSection from '../components/landing/ArchitectureSection';
import SecurityPrinciples from '../components/landing/SecurityPrinciples';
import FinalCta from '../components/landing/FinalCta';

/**
 * Cyber Deception Gateway — Public Landing Page (Stage 1)
 *
 * Implements the full premium landing page design:
 * - Section 1: Navigation
 * - Section 2: Hero & Interactive Gateway Diagram
 * - Section 3: Core Capabilities
 * - Section 4: How It Works
 * - Section 5: Architecture Overview
 * - Section 6: Security-Focused Design Principles
 * - Section 7: Final Call to Action
 * - Section 8: Footer
 */
export default function LandingPage({ onNavigate }) {
  return (
    <div className="landing-page-root" style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Section 1: Navigation */}
      <Navbar onNavigate={onNavigate} />

      <main style={{ flexGrow: 1 }}>
        {/* Section 2: Hero */}
        <Hero onNavigate={onNavigate} />

        {/* Section 3: Core Capabilities */}
        <CoreCapabilities />

        {/* Section 4: How It Works */}
        <HowItWorks />

        {/* Section 5: Architecture Overview */}
        <ArchitectureSection />

        {/* Section 6: Security-Focused Design Principles */}
        <SecurityPrinciples />

        {/* Section 7: Final Call to Action */}
        <FinalCta onNavigate={onNavigate} />
      </main>

      {/* Section 8: Footer */}
      <Footer onNavigate={onNavigate} />
    </div>
  );
}
