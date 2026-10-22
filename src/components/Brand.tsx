import React, { useEffect, useState } from 'react';
import { Moon, Sun } from 'lucide-react';

/* ------------------------------------------------------------------ */
/*  BrandMark — a forged keyhole: the letter N cut through a shield     */
/*  plate, with a direct path out. One shape, no glow, no gradients.    */
/* ------------------------------------------------------------------ */

export interface BrandMarkProps {
  size?: number;
  className?: string;
}

export const BrandMark: React.FC<BrandMarkProps> = ({ size = 34, className = '' }) => (
  <span
    className={`brand-mark__tile ${className}`}
    style={{
      width: size,
      height: size,
      borderRadius: Math.round(size * 0.28),
      flex: 'none',
    }}
    aria-hidden="true"
  >
    <svg viewBox="0 0 32 32" width={size * 0.62} height={size * 0.62} fill="none">
      {/* shield outline */}
      <path
        d="M16 2.8 27 7.4v9.2c0 6.1-4.6 11.3-11 12.6C9.6 27.9 5 22.7 5 16.6V7.4L16 2.8Z"
        stroke="currentColor"
        strokeWidth="2.1"
        strokeLinejoin="round"
        opacity="0.55"
      />
      {/* the N, drawn as one continuous stroke, exiting bottom-right */}
      <path
        d="M10.5 21V11.6L17 19.4V11"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* exit tick */}
      <path d="M18.5 21h3" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" />
    </svg>
  </span>
);

/* ------------------------------------------------------------------ */
/*  BrandLogo — mark + name, optional private-studio identity          */
/* ------------------------------------------------------------------ */

export interface BrandLogoProps {
  size?: number;
  name?: string;
  kicker?: string;
  /** Renders the studio's own name instead of the product name. */
  custom?: boolean;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({
  size = 34,
  name = 'NPV//FORGE',
  kicker = 'سامانه تخصصی تبدیل کانفیگ NPV به V2Ray',
  custom = false,
}) => (
  <span className="brand-logo">
    <BrandMark size={size} />
    <span style={{ display: 'grid', minWidth: 0 }}>
      <span
        className="brand-logo__title"
        style={{ fontSize: size > 30 ? 15.5 : 14.5, color: custom ? 'var(--accent)' : 'var(--text)' }}
      >
        {custom ? name : <>{name}</>}
      </span>
      <span className="brand-logo__kicker">{custom ? 'استودیوی اختصاصی' : kicker}</span>
    </span>
  </span>
);

/* ------------------------------------------------------------------ */
/*  Theme toggle                                                       */
/* ------------------------------------------------------------------ */

export const ThemeToggle: React.FC = () => {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setDark(document.documentElement.classList.contains('dark'));
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    return () => observer.disconnect();
  }, []);

  return (
    <button
      type="button"
      onClick={() => {
        const isDark = document.documentElement.classList.contains('dark');
        document.documentElement.classList.toggle('dark', !isDark);
        document.documentElement.classList.toggle('light', isDark);
        try {
          localStorage.setItem('npvt_theme', !isDark ? 'dark' : 'light');
        } catch {}
      }}
      className="btn btn--icon btn--ghost"
      aria-label={dark ? 'تغییر به تم روشن' : 'تغییر به تم تیره'}
      title={dark ? 'حالت روشن' : 'حالت تیره'}
    >
      {dark ? <Sun style={{ width: 16, height: 16 }} /> : <Moon style={{ width: 16, height: 16 }} />}
    </button>
  );
};
