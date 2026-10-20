import React from 'react';

/**
 * Cyber Deception Gateway — Lightweight SVG Icon Library
 * Restrained, enterprise-grade icons with clean stroke geometry.
 */
export default function Icon({ name, size = 20, className = '', color = 'currentColor', ...props }) {
  const icons = {
    shield: (
      <path
        d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
        fill="none"
        stroke={color}
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    ),
    route: (
      <>
        <circle cx="6" cy="19" r="3" fill="none" stroke={color} strokeWidth="1.8" />
        <path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="18" cy="5" r="3" fill="none" stroke={color} strokeWidth="1.8" />
      </>
    ),
    radar: (
      <>
        <path d="M12 2a10 10 0 1 0 10 10" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
        <path d="M12 6a6 6 0 1 0 6 6" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
        <path d="M12 10a2 2 0 1 0 2 2" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
        <path d="M12 12l5-5" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
      </>
    ),
    activity: (
      <path
        d="M22 12h-4l-3 9L9 3l-3 9H2"
        fill="none"
        stroke={color}
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    ),
    layers: (
      <>
        <polygon points="12 2 2 7 12 12 22 7 12 2" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points="2 17 12 22 22 17" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points="2 12 12 17 22 12" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </>
    ),
    server: (
      <>
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2" fill="none" stroke={color} strokeWidth="1.8" />
        <rect x="2" y="14" width="20" height="8" rx="2" ry="2" fill="none" stroke={color} strokeWidth="1.8" />
        <line x1="6" y1="6" x2="6.01" y2="6" stroke={color} strokeWidth="2.4" strokeLinecap="round" />
        <line x1="6" y1="18" x2="6.01" y2="18" stroke={color} strokeWidth="2.4" strokeLinecap="round" />
      </>
    ),
    cpu: (
      <>
        <rect x="4" y="4" width="16" height="16" rx="2" fill="none" stroke={color} strokeWidth="1.8" />
        <rect x="9" y="9" width="6" height="6" fill="none" stroke={color} strokeWidth="1.8" />
        <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
      </>
    ),
    lock: (
      <>
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" fill="none" stroke={color} strokeWidth="1.8" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
      </>
    ),
    check: (
      <polyline points="20 6 9 17 4 12" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    ),
    'arrow-right': (
      <>
        <line x1="5" y1="12" x2="19" y2="12" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points="12 5 19 12 12 19" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </>
    ),
    menu: (
      <>
        <line x1="3" y1="12" x2="21" y2="12" stroke={color} strokeWidth="2" strokeLinecap="round" />
        <line x1="3" y1="6" x2="21" y2="6" stroke={color} strokeWidth="2" strokeLinecap="round" />
        <line x1="3" y1="18" x2="21" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" />
      </>
    ),
    x: (
      <>
        <line x1="18" y1="6" x2="6" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        <line x1="6" y1="6" x2="18" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </>
    ),
    'external-link': (
      <>
        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points="15 3 21 3 21 9" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <line x1="10" y1="14" x2="21" y2="3" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </>
    ),
    chevronDown: (
      <polyline points="6 9 12 15 18 9" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    ),
    eye: (
      <>
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="12" cy="12" r="3" fill="none" stroke={color} strokeWidth="1.8" />
      </>
    ),
    'eye-off': (
      <>
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <line x1="1" y1="1" x2="23" y2="23" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </>
    ),
    'alert-triangle': (
      <>
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <line x1="12" y1="9" x2="12" y2="13" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
        <line x1="12" y1="17" x2="12.01" y2="17" stroke={color} strokeWidth="2.4" strokeLinecap="round" />
      </>
    ),
    user: (
      <>
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
        <circle cx="12" cy="7" r="4" fill="none" stroke={color} strokeWidth="1.8" />
      </>
    ),
    mail: (
      <>
        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points="22,6 12,13 2,6" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </>
    ),
    zap: (
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    ),
  };

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      className={className}
      aria-hidden="true"
      {...props}
    >
      {icons[name] || null}
    </svg>
  );
}
