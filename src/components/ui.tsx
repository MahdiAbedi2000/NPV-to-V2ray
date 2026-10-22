import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  Check as CheckIcon,
  ShieldCheck as ShieldCheckIcon,
  ShieldAlert as ShieldAlertIcon,
  Info as InfoIcon,
  X as XIcon,
  type LucideIcon,
} from 'lucide-react';
import { BrandMark, BrandLogo, ThemeToggle } from './Brand';

export { BrandMark, BrandLogo, ThemeToggle };

/* ------------------------------------------------------------------ */
/*  Boot overlay — a short, honest loading line                        */
/* ------------------------------------------------------------------ */

const BOOT_STEPS: string[] = [
  'load cipher core',
  'load white-box tables',
  'prepare output writers',
];

export const BootOverlay: React.FC<{ done: boolean }> = ({ done }) => (
  <div className={`boot ${done ? 'is-done' : ''}`} aria-hidden="true">
    <div className="boot__inner">
      <BrandMark size={52} />
      <div>
        <div
          className="display"
          style={{ fontSize: 'clamp(22px,4vw,28px)', fontWeight: 800, letterSpacing: '-0.02em' }}
        >
          NPV<span style={{ color: 'var(--accent)' }}>//</span>FORGE
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--muted)', marginTop: 4 }}>
          موتور رمزگشایی در حال آماده‌سازی است
        </div>
      </div>
      <div className="boot__log">
        {BOOT_STEPS.map((s, i) => (
          <div key={s}>
            <span className="ok">✓</span> {s}
          </div>
        ))}
      </div>
      <div className="boot__bar">
        <span style={{ width: done ? '100%' : '65%' }} />
      </div>
    </div>
  </div>
);

/* ------------------------------------------------------------------ */
/*  Toasts                                                             */
/* ------------------------------------------------------------------ */

export interface ToastItem {
  id: number;
  icon: 'ok' | 'shield' | 'info' | 'error';
  text: string;
}

const TOAST_ICONS: Record<ToastItem['icon'], LucideIcon> = {
  ok: CheckIcon,
  shield: ShieldCheckIcon,
  info: InfoIcon,
  error: ShieldAlertIcon,
};

const ToastCtx = createContext<{ push: (icon: ToastItem['icon'], text: string) => void }>({
  push: () => {},
});

export const useToast = () => useContext(ToastCtx);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [items, setItems] = useState<ToastItem[]>([]);

  const push = useCallback((icon: ToastItem['icon'], text: string) => {
    const id = Date.now() + Math.random();
    setItems((prev) => [...prev.slice(-2), { id, icon, text }]);
    window.setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, 2600);
  }, []);

  return (
    <ToastCtx.Provider value={{ push }}>
      {children}
      {typeof document !== 'undefined' &&
        createPortal(
          <div className="toasts" dir="rtl">
            {items.map((t) => {
              const Icon = TOAST_ICONS[t.icon];
              return (
                <div key={t.id} className={`toast toast--${t.icon}`} role="status">
                  <Icon style={{ width: 15, height: 15 }} />
                  <span>{t.text}</span>
                </div>
              );
            })}
          </div>,
          document.body
        )}
    </ToastCtx.Provider>
  );
};

/* ------------------------------------------------------------------ */
/*  Copy hook + button                                                 */
/* ------------------------------------------------------------------ */

export function useClipboard() {
  const [copied, setCopied] = useState<string | null>(null);

  const copy = useCallback(async (text: string, key: string) => {
    if (!text) return false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      setCopied(key);
      window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 1800);
      return true;
    } catch {
      return false;
    }
  }, []);

  return { copied, copy };
}

export const CopyButton: React.FC<{
  text: string;
  copyKey: string;
  copied: string | null;
  onCopy: (text: string, key: string) => void;
  label?: string;
  doneLabel?: string;
  iconOnly?: boolean;
  className?: string;
  variant?: string;
}> = ({ text, copyKey, copied, onCopy, label = 'کپی', doneLabel = 'کپی شد', iconOnly = false, className = '', variant = 'btn--soft' }) => {
  const isDone = copied === copyKey;
  const Icon = isDone ? CheckIcon : ShieldCheckIcon;
  const base = iconOnly ? 'btn btn--icon btn--ghost' : variant === 'btn--primary' ? 'btn btn--primary' : 'btn btn--soft';
  return (
    <button
      type="button"
      disabled={!text}
      onMouseDown={(e) => e.preventDefault()}
      onClick={() => onCopy(text, copyKey)}
      className={`${base} ${className}`}
      title={label}
    >
      <Icon style={{ width: 14, height: 14, flex: 'none' }} />
      {!iconOnly && <span>{isDone ? doneLabel : label}</span>}
    </button>
  );
};

/* ------------------------------------------------------------------ */
/*  Modal                                                              */
/* ------------------------------------------------------------------ */

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

export const Modal: React.FC<ModalProps> = ({ open, onClose, title, subtitle, children, footer }) => {
  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener('keydown', onKey);
    };
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div className="modal" role="dialog" aria-modal="true" aria-label={title} onClick={onClose}>
      <div className="modal__panel" onClick={(e) => e.stopPropagation()}>
        <div className="modal__head">
          <div style={{ minWidth: 0 }}>
            <h3 className="modal__title">{title}</h3>
            {subtitle && <p className="modal__sub">{subtitle}</p>}
          </div>
          <button type="button" aria-label="بستن" onClick={onClose} className="btn btn--icon btn--ghost">
            <XIcon style={{ width: 16, height: 16 }} />
          </button>
        </div>
        <div className="modal__body">{children}</div>
        {footer && <div className="modal__foot">{footer}</div>}
      </div>
    </div>,
    document.body
  );
};

/* ------------------------------------------------------------------ */
/*  Section heading                                                    */
/* ------------------------------------------------------------------ */

export const PanelTitle: React.FC<{ icon: LucideIcon; title: string; note?: string }> = ({ icon: Icon, title, note }) => (
  <div style={{ display: 'flex', gap: 12, minWidth: 0 }}>
    <div className="disclosure__summary" style={{ padding: 0, cursor: 'default', flex: 'none' }} aria-hidden="true">
      <span className="icon">
        <Icon style={{ width: 15, height: 15 }} />
      </span>
    </div>
    <div style={{ minWidth: 0 }}>
      <h2 className="display" style={{ fontSize: 15.5, lineHeight: 1.5 }}>
        {title}
      </h2>
      {note && <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2, lineHeight: 1.8 }}>{note}</p>}
    </div>
  </div>
);

/* ------------------------------------------------------------------ */
/*  Latency helpers                                                    */
/* ------------------------------------------------------------------ */

export const latencyTone = (ms: number): 'ok' | 'warn' | 'bad' => (ms < 180 ? 'ok' : ms < 420 ? 'warn' : 'bad');

export const LatencyChip: React.FC<{ ms: number | null; status: 'idle' | 'testing' | 'ok' | 'timeout' }> = ({ ms, status }) => {
  const tone =
    status === 'testing'
      ? 'chip--blue'
      : status === 'idle'
      ? ''
      : status === 'timeout'
      ? 'chip--danger'
      : latencyTone(ms || 999) === 'ok'
      ? 'chip--accent'
      : latencyTone(ms || 999) === 'warn'
      ? 'chip--warn'
      : 'chip--danger';
  const label =
    status === 'idle'
      ? 'تست پینگ'
      : status === 'testing'
      ? 'در حال تست'
      : status === 'timeout'
      ? 'بی‌پاسخ'
      : `${ms} ms`;
  return <span className={`chip ${tone}`}>{label}</span>;
};
