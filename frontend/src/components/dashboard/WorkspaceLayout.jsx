import React, { useState } from 'react';
import WorkspaceSidebar from './WorkspaceSidebar';
import WorkspaceHeader from './WorkspaceHeader';

/**
 * Cyber Deception Gateway — Reusable Authenticated Workspace Layout
 * Two-column shell with collapsible sidebar, sticky header, and responsive drawer.
 */
export default function WorkspaceLayout({
  children,
  currentView = 'overview',
  onSelectView,
  onNavigate,
  onLogout,
  operator,
  organization,
  pageTitle = 'Security Overview',
  onRefresh,
  isRefreshing = false,
}) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);

  return (
    <div
      style={{
        display: 'flex',
        minHeight: '100vh',
        backgroundColor: 'var(--bg-main)',
        color: 'var(--text-main)',
      }}
    >
      <style>{`
        @media (max-width: 900px) {
          .mobile-menu-btn {
            display: inline-flex !important;
          }
          .dashboard-sidebar-container {
            position: fixed !important;
            top: 0;
            bottom: 0;
            left: 0;
            z-index: 100;
            transform: translateX(-100%);
            transition: transform 0.25s ease;
          }
          .dashboard-sidebar-container.open {
            transform: translateX(0);
          }
          .dashboard-backdrop {
            display: block !important;
          }
        }
      `}</style>

      {/* Mobile Backdrop */}
      {mobileDrawerOpen && (
        <div
          className="dashboard-backdrop"
          onClick={() => setMobileDrawerOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.65)',
            zIndex: 90,
            display: 'none',
          }}
        />
      )}

      {/* Sidebar Container */}
      <div className={`dashboard-sidebar-container ${mobileDrawerOpen ? 'open' : ''}`}>
        <WorkspaceSidebar
          currentView={currentView}
          onSelectView={(v) => {
            onSelectView(v);
            setMobileDrawerOpen(false);
          }}
          onNavigate={onNavigate}
          onLogout={onLogout}
          operator={operator}
          isCollapsed={isCollapsed}
          onToggleCollapse={() => setIsCollapsed(!isCollapsed)}
        />
      </div>

      {/* Main Content Area */}
      <div style={{ flexGrow: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <WorkspaceHeader
          organization={organization}
          operator={operator}
          title={pageTitle}
          onRefresh={onRefresh}
          isRefreshing={isRefreshing}
          onNavigate={onNavigate}
          onOpenMobileMenu={() => setMobileDrawerOpen(true)}
        />

        <main style={{ flexGrow: 1, padding: '2.5rem 2rem 4rem', overflowY: 'auto' }}>
          <div style={{ maxWidth: '1360px', margin: '0 auto', width: '100%' }}>
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
