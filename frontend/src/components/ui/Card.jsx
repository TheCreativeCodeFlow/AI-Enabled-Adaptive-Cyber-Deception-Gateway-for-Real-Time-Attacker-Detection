import React from 'react';

/**
 * Cyber Deception Gateway — Reusable Card Component
 */
export default function Card({
  children,
  className = '',
  style = {},
  as = 'div',
  ...props
}) {
  const Component = as;
  return (
    <Component
      className={`card ${className}`}
      style={style}
      {...props}
    >
      {children}
    </Component>
  );
}
