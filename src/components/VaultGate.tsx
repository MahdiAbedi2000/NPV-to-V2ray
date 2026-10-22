import React, { useCallback, useEffect, useState } from 'react';
import {
  Lock,
  ShieldAlert,
  RefreshCw,
  Eye,
  EyeOff,
  ArrowLeft,
  Sparkles,
  ShieldCheck,
  HelpCircle,
  Wand2,
  Share2,
  Package,
} from 'lucide-react';
import { verifyPassword } from '../utils/vaultCrypto';

interface StudioGateProps {
  onUnlock: () => void;
  onBack?: () => void;
}

const MAX_ATTEMPTS = 5;
const COOLDOWN_MS = 30_000;
const ATTEMPT_STORE = 'npv_studio_attempts_v2';

interface AttemptState {
  count: number;
  until: number;
}

function readAttempts(): AttemptState {
  try {
    const raw = sessionStorage.getItem(ATTEMPT_STORE);
    if (!raw) return { count: 0, until: 0 };
    const parsed = JSON.parse(raw);
    return { count: Number(parsed.count) || 0, until: Number(parsed.until) || 0 };
  } catch {
    return { count: 0, until: 0 };
  }
}

function writeAttempts(state: AttemptState) {
  try {
    sessionStorage.setItem(ATTEMPT_STORE, JSON.stringify(state));
  } catch {}
}

export const VaultGate: React.FC<StudioGateProps> = ({ onUnlock, onBack }) => {
  const [key, setKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [attempts, setAttempts] = useState<AttemptState>(() => readAttempts());
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!attempts.until) return;
    const t = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(t);
  }, [attempts.until]);

  const coolingDown = attempts.until > now;
  const secondsLeft = Math.max(0, Math.ceil((attempts.until - now) / 1000));

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (busy || coolingDown) return;
      const candidate = key.trim();
      if (!candidate) {
        setError('رمز را وارد کنید.');
        return;
      }
      setBusy(true);
      setError('');
      try {
        if (await verifyPassword(candidate)) {
          writeAttempts({ count: 0, until: 0 });
          setAttempts({ count: 0, until: 0 });
          setKey('');
          onUnlock();
          return;
        }
        const next = attempts.count + 1;
        const until = next >= MAX_ATTEMPTS ? Date.now() + COOLDOWN_MS : 0;
        const state = { count: next >= MAX_ATTEMPTS ? 0 : next, until };
        writeAttempts(state);
        setAttempts(state);
        setKey('');
        setError(
          next >= MAX_ATTEMPTS
            ? 'تلاش‌های ناموفق بیش از حد مجاز بود. ۳۰ ثانیه صبر کنید.'
            : 'رمز عبور نادرست است.'
        );
      } catch {
        setError('بررسی رمز انجام نشد. دوباره امتحان کنید.');
      } finally {
        setBusy(false);
      }
    },
    [attempts, busy, coolingDown, key, onUnlock]
  );

  return (
    <div className="studio-gate">
      <div className="studio-gate__card">
        <div className="studio-gate__hero">
          <div className="studio-gate__seal">
            <Lock style={{ width: 22, height: 22 }} />
          </div>
          <h2 className="studio-gate__title">استودیوی اختصاصی</h2>
          <p className="studio-gate__note">
            ابزار بازنویسی برند، نام‌گذاری نودها و بسته‌بندی فایل برای انتشار.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="studio-gate__form">
          <label className="studio-gate__label" htmlFor="studio-key">
            <span>رمز عبور دسترسی</span>
            {coolingDown && <span style={{ color: 'var(--warn)', fontWeight: 500 }}>{secondsLeft} ثانیه تا بازگشایی</span>}
          </label>

          <div className="studio-gate__input">
            <input
              id="studio-key"
              type={showKey ? 'text' : 'password'}
              dir="ltr"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="رمز عبور را وارد کنید"
              autoComplete="off"
              spellCheck={false}
              autoFocus
              disabled={busy || coolingDown}
            />
            <button
              type="button"
              onClick={() => setShowKey((s) => !s)}
              className="btn btn--icon btn--ghost"
              style={{ width: 30, height: 30 }}
              aria-label={showKey ? 'پنهان کردن رمز' : 'نمایش رمز'}
            >
              {showKey ? <EyeOff style={{ width: 14, height: 14 }} /> : <Eye style={{ width: 14, height: 14 }} />}
            </button>
          </div>

          {error && (
            <div className="studio-gate__error" role="alert">
              <ShieldAlert style={{ width: 14, height: 14, flex: 'none' }} />
              <span>{error}</span>
            </div>
          )}

          {coolingDown && (
            <div className="studio-gate__cooldown">
              <RefreshCw style={{ width: 13, height: 13, flex: 'none' }} className="spin" />
              <span>ورود موقتاً غیرفعال است. لطفاً چند لحظه شکیبا باشید.</span>
            </div>
          )}

          <button
            type="submit"
            className="btn btn--primary btn--lg"
            style={{ width: '100%', marginTop: 2 }}
            disabled={busy || coolingDown || !key.trim()}
          >
            {busy ? 'در حال بررسی…' : 'ورود به استودیو'}
          </button>

          {onBack && (
            <button type="button" onClick={onBack} className="btn btn--ghost btn--sm" style={{ width: '100%' }}>
              <ArrowLeft style={{ width: 13, height: 13 }} />
              بازگشت به رمزگشایی
            </button>
          )}
        </form>

        <div className="studio-gate__meta">
          <span className="studio-gate__meta-item">
            <ShieldCheck style={{ width: 12, height: 12, color: 'var(--accent)' }} />
            تایید آفلاین در مرورگر شما
          </span>
          <span className="studio-gate__meta-item">
            <Lock style={{ width: 12, height: 12, color: 'var(--faint)' }} />
            بدون ارسال به سرور
          </span>
        </div>

        {/* Informational guide explaining studio purpose and why it's locked */}
        <div className="studio-explainer">
          <div className="studio-explainer__header">
            <HelpCircle style={{ width: 14, height: 14, color: 'var(--accent)' }} />
            <span>آشنایی با این بخش و علت حفاظت</span>
          </div>

          <div className="studio-explainer__grid">
            <div className="studio-explainer__item">
              <div className="studio-explainer__badge">
                <Wand2 style={{ width: 13, height: 13 }} />
                <span>کارکرد استودیو چیست؟</span>
              </div>
              <p>
                استودیوی اختصاصی به ادمین‌ها و ارائه‌دهندگان امکان می‌دهد کانفیگ‌های استخراج‌شده را
                با <b>نام، پیشوند و الگوی دلخواه</b> بازنویسی کنند، تبلیغات یا آیدی‌های تلگرام قبلی را پاک کنند
                و فایل آماده را با <b>کپشن انتشار</b> در قالب کانتینر اختصاصی <code className="mono">.npvs</code> یا{' '}
                <code className="mono">.npvt</code> بسته‌بندی نمایند.
              </p>
            </div>

            <div className="studio-explainer__item">
              <div className="studio-explainer__badge studio-explainer__badge--shield">
                <Lock style={{ width: 13, height: 13 }} />
                <span>چرا این بخش قفل است؟</span>
              </div>
              <p>
                برای جلوگیری از تغییر تصادفی هویت برند، حفظ یکپارچگی کانتینرهای خروجی و تفکیک
                محیط استفاده عمومی از ابزار انتشار حرفه‌ای. تمام اعتبارسنجی‌ها به صورت محلی و کلاینت‌ساید انجام می‌شود.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
