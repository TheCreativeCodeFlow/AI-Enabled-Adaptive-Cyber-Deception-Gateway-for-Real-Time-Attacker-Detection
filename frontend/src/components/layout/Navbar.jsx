import React, { useState, useEffect } from 'react';
import Icon from '../ui/Icon';
import Button from '../ui/Button';

/**
 * Cyber Deception Gateway — Top Navigation Bar
 * Responsive, accessible navigation with section scrolling and mobile drawer.
 */
export default function Navbar({ onNavigate }) {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleNavClick = (e, sectionId) => {
    e.preventDefault();
    setMobileMenuOpen(false);

    if (window.location.pathname !== '/') {
      onNavigate('/');
      setTimeout(() => {
        const el = document.getElementById(sectionId);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 100);
      return;
    }

    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleActionClick = (path) => {
    setMobileMenuOpen(false);
    onNavigate(path);
  };

  return (
    <header
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        backgroundColor: isScrolled ? 'rgba(8, 13, 24, 0.92)' : 'rgba(8, 13, 24, 0.75)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        borderBottom: `1px solid ${isScrolled ? 'var(--border-subtle)' : 'transparent'}`,
        transition: 'all var(--transition-normal)',
      }}
    >
      <div className="container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: 'var(--nav-height)' }}>
        {/* Brand Identity */}
        <a
          href="/"
          onClick={(e) => {
            e.preventDefault();
            onNavigate('/');
            window.scrollTo({ top: 0, behavior: 'smooth' });
          }}
          style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontWeight: 700, fontSize: '1.05rem', color: 'var(--text-main)' }}
          aria-label="Cyber Deception Gateway Home"
        >
          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-primary-subtle)',
              border: '1px solid var(--accent-primary-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-primary)',
            }}
          >
            <Icon name="shield" size={20} color="var(--accent-primary)" />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ letterSpacing: '-0.02em', lineHeight: 1.2 }}>Cyber Deception Gateway</span>
            <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 500, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Adaptive Defense
            </span>
          </div>
        </a>

        {/* Desktop Navigation Links */}
        <nav
          style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}
          className="desktop-nav"
          aria-label="Main Navigation"
        >
          <a
            href="#capabilities"
            onClick={(e) => handleNavClick(e, 'capabilities')}
            style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontWeight: 500 }}
            className="nav-link"
          >
            Product
          </a>
          <a
            href="#how-it-works"
            onClick={(e) => handleNavClick(e, 'how-it-works')}
            style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontWeight: 500 }}
            className="nav-link"
          >
            How It Works
          </a>
          <a
            href="#architecture"
            onClick={(e) => handleNavClick(e, 'architecture')}
            style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontWeight: 500 }}
            className="nav-link"
          >
            Architecture
          </a>
          <a
            href="#security"
            onClick={(e) => handleNavClick(e, 'security')}
            style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontWeight: 500 }}
            className="nav-link"
          >
            Security
          </a>
          <a
            href="#architecture"
            onClick={(e) => handleNavClick(e, 'architecture')}
            style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontWeight: 500 }}
            className="nav-link"
          >
            Documentation
          </a>
        </nav>

        {/* Action CTAs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }} className="desktop-actions">
          <Button
            variant="subtle"
            size="sm"
            onClick={() => handleActionClick('/login')}
          >
            Sign In
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => handleActionClick('/register')}
          >
            Get Started
          </Button>
        </div>

        {/* Mobile Hamburger Toggle */}
        <button
          type="button"
          className="mobile-toggle"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-expanded={mobileMenuOpen}
          aria-label="Toggle navigation menu"
          style={{
            display: 'none',
            padding: '0.5rem',
            color: 'var(--text-main)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <Icon name={mobileMenuOpen ? 'x' : 'menu'} size={22} />
        </button>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div
          style={{
            backgroundColor: 'var(--bg-secondary)',
            borderBottom: '1px solid var(--border-subtle)',
            padding: '1.5rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
          }}
          className="mobile-drawer"
        >
          <a
            href="#capabilities"
            onClick={(e) => handleNavClick(e, 'capabilities')}
            style={{ fontSize: '1rem', color: 'var(--text-main)', padding: '0.4rem 0' }}
          >
            Product
          </a>
          <a
            href="#how-it-works"
            onClick={(e) => handleNavClick(e, 'how-it-works')}
            style={{ fontSize: '1rem', color: 'var(--text-main)', padding: '0.4rem 0' }}
          >
            How It Works
          </a>
          <a
            href="#architecture"
            onClick={(e) => handleNavClick(e, 'architecture')}
            style={{ fontSize: '1rem', color: 'var(--text-main)', padding: '0.4rem 0' }}
          >
            Architecture
          </a>
          <a
            href="#security"
            onClick={(e) => handleNavClick(e, 'security')}
            style={{ fontSize: '1rem', color: 'var(--text-main)', padding: '0.4rem 0' }}
          >
            Security
          </a>
          <a
            href="#architecture"
            onClick={(e) => handleNavClick(e, 'architecture')}
            style={{ fontSize: '1rem', color: 'var(--text-main)', padding: '0.4rem 0' }}
          >
            Documentation
          </a>

          <div style={{ paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <Button
              variant="secondary"
              onClick={() => handleActionClick('/login')}
              style={{ width: '100%', justifyContent: 'center' }}
            >
              Sign In
            </Button>
            <Button
              variant="primary"
              onClick={() => handleActionClick('/register')}
              style={{ width: '100%', justifyContent: 'center' }}
            >
              Get Started
            </Button>
          </div>
        </div>
      )}

      {/* Inline styles for media query adjustments */}
      <style>{`
        @media (max-width: 860px) {
          .desktop-nav, .desktop-actions {
            display: none !important;
          }
          .mobile-toggle {
            display: inline-flex !important;
            align-items: center;
            justify-content: center;
          }
        }
        .nav-link:hover {
          color: var(--text-main) !important;
        }
      `}</style>
    </header>
  );
}
