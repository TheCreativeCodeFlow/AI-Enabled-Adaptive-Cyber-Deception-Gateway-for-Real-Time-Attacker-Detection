import React from 'react';

/**
 * Cyber Deception Gateway — Reusable Button Component
 */
export default function Button({
  children,
  variant = 'primary', // 'primary' | 'secondary' | 'subtle'
  size = 'md', // 'sm' | 'md' | 'lg'
  icon = null,
  iconPosition = 'left',
  onClick,
  href,
  className = '',
  disabled = false,
  type = 'button',
  ...props
}) {
  const baseClass = 'btn';
  const variantClass = `btn-${variant}`;
  const sizeClass = size !== 'md' ? `btn-${size}` : '';
  const combinedClasses = [baseClass, variantClass, sizeClass, className].filter(Boolean).join(' ');

  if (href) {
    return (
      <a
        href={href}
        className={combinedClasses}
        onClick={onClick}
        role="button"
        {...props}
      >
        {icon && iconPosition === 'left' && <span className="btn-icon">{icon}</span>}
        <span>{children}</span>
        {icon && iconPosition === 'right' && <span className="btn-icon">{icon}</span>}
      </a>
    );
  }

  return (
    <button
      type={type}
      className={combinedClasses}
      onClick={onClick}
      disabled={disabled}
      {...props}
    >
      {icon && iconPosition === 'left' && <span className="btn-icon">{icon}</span>}
      <span>{children}</span>
      {icon && iconPosition === 'right' && <span className="btn-icon">{icon}</span>}
    </button>
  );
}
