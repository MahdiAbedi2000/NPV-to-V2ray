import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Wrench,
  CheckCircle2,
  Terminal,
  Sparkles,
  Copy,
  Check,
  Server,
  Clock,
  Lock,
  Zap,
  ArrowRight,
  ChevronDown,
} from 'lucide-react';
import { TlsFixMode } from '../utils/npvConverter';
import { CopyButton, PanelTitle } from './ui';

interface XrayLogDiagnosticProps {
  isLight: boolean;
  tlsFixMode: TlsFixMode;
  onChangeTlsFixMode: (mode: TlsFixMode) => void;
  tlsMismatchCount?: number;
}

const DEFAULT_USER_LOG = `2026/10/18 00:09:50.722705 from tcp:127.0.0.1:55883 accepted tcp:www.google.com:443 [mixed10830 -> proxy10830]
2026/10/18 00:09:50.722705 from tcp:127.0.0.1:55882 accepted tcp:www.google.com:443 [mixed10829 -> proxy10829]
2026/10/18 00:09:51.178680 [Error] [644796511] transport/internet/websocket: failed to dial to 167.82.64.46:443 > tls: failed to verify certificate: x509: certificate is valid for default.ssl.fastly.net, *.hosts.fastly.net, *.fastly.com, not firefox.com
2026/10/18 00:09:51.178680 [Error] [1350748990] transport/internet/websocket: failed to dial to 199.232.78.160:443 > tls: failed to verify certificate: x509: certificate is valid for default.ssl.fastly.net, *.hosts.fastly.net, *.fastly.com, not firefox.com`;

export const XrayLogDiagnostic: React.FC<XrayLogDiagnosticProps> = ({
  tlsFixMode,
  onChangeTlsFixMode,
  tlsMismatchCount = 0,
}) => {
  const [logInput, setLogInput] = useState<string>(DEFAULT_USER_LOG);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [openLogBox, setOpenLogBox] = useState<boolean>(false);

  const analysis = useMemo(() => {
    const raw = logInput.trim();
    if (!raw) return null;

    // Extract dialed endpoints
    const dialMatches = Array.from(raw.matchAll(/failed to dial to ([0-9a-zA-Z.-]+:\d+)/g)).map(
      (m) => m[1]
    );
    const uniqueEndpoints = Array.from(new Set(dialMatches));

    // Extract x509 certificate mismatch details
    const x509Match = raw.match(
      /x509:\s*certificate is valid for ([^,]+(?:,\s*[^,]+)*),\s*not\s+([^\s\r\n]+)/i
    );
    const validCerts = x509Match
      ? x509Match[1]
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : [];
    const rejectedSni = x509Match ? x509Match[2].trim() : '';

    // Check if Fastly IPs or cert
    const isFastly =
      raw.toLowerCase().includes('fastly.net') ||
      raw.toLowerCase().includes('fastly.com') ||
      uniqueEndpoints.some(
        (ep) =>
          ep.startsWith('167.82.') ||
          ep.startsWith('199.232.') ||
          ep.startsWith('151.101.') ||
          ep.startsWith('146.75.')
      );

    // Calculate response time between accepted and first [Error] if timestamps exist
    let responseMs: number | null = null;
    const tAccept = raw.match(/(\d{2}:\d{2}:(\d{2}\.\d+))\s+from\s+tcp:/);
    const tError = raw.match(/(\d{2}:\d{2}:(\d{2}\.\d+))\s+\[Error\]/);
    if (tAccept && tError) {
      const s1 = parseFloat(tAccept[2]);
      const s2 = parseFloat(tError[2]);
      if (!isNaN(s1) && !isNaN(s2) && s2 >= s1) {
        responseMs = Math.round((s2 - s1) * 1000);
      }
    }

    const primaryValidCert = validCerts[0] || (isFastly ? 'default.ssl.fastly.net' : '');

    return {
      hasX509Error: Boolean(x509Match),
      uniqueEndpoints,
      validCerts,
      primaryValidCert,
      rejectedSni,
      isFastly,
      responseMs,
      isWebsocket: raw.includes('transport/internet/websocket'),
    };
  }, [logInput]);

  const handleCopy = (val: string, key: string) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1600);
  };

  return (
    <section id="xray" className="panel reveal d4">
      {/* Panel Header */}
      <div className="panel__head">
        <PanelTitle
          icon={Wrench}
          title="عیب‌یاب هوشمند خطای گواهی TLS (x509 Fastly / Domain Fronting)"
          note="کالبدشکافی فنی خطای گواهی فستلی و انتخاب حالت تعمیر خودکار برای پینگ‌دهی در v2rayNG و v2rayN"
        />

        {/* 3-Way Mode Switcher */}
        <div className="seg" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={tlsFixMode === 'auto-smart'}
            onClick={() => onChangeTlsFixMode('auto-smart')}
            className={`seg__item ${tlsFixMode === 'auto-smart' ? 'is-active' : ''}`}
            title="تزریق خودکار allowInsecure=1 و vcn به لینک‌ها"
          >
            <Sparkles style={{ width: 13, height: 13 }} />
            <span>حالت ۱: هوشمند (VCN)</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={tlsFixMode === 'fastly-sni'}
            onClick={() => onChangeTlsFixMode('fastly-sni')}
            className={`seg__item ${tlsFixMode === 'fastly-sni' ? 'is-active-alt' : ''}`}
            title="تغییر SNI مستقیم به default.ssl.fastly.net"
          >
            <ShieldCheck style={{ width: 13, height: 13 }} />
            <span>حالت ۲: تثبیت SNI</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={tlsFixMode === 'raw'}
            onClick={() => onChangeTlsFixMode('raw')}
            className={`seg__item ${tlsFixMode === 'raw' ? 'is-active' : ''}`}
            title="خام بدون هیچ تغییری"
          >
            <span>خام (بدون تغییر)</span>
          </button>
        </div>
      </div>

      <div className="panel__body space-y-4">
        {/* Status bar if mismatches detected */}
        {tlsMismatchCount > 0 && (
          <div className="flex items-center justify-between gap-3 p-3 rounded-xl border bg-[var(--accent-soft)] border-[color-mix(in_srgb,var(--accent)_30%,transparent)] text-xs flex-wrap">
            <div className="flex items-center gap-2">
              <span className="led led--on" />
              <span className="font-bold text-[var(--accent)]">
                {tlsMismatchCount} نود CDN با SNI فیک شناسایی و به‌صورت خودکار تجهیز شدند
              </span>
            </div>
            <span className="chip chip--accent mono">
              ACTIVE FIX: {tlsFixMode.toUpperCase()}
            </span>
          </div>
        )}

        {/* Diagnostic Analysis Card */}
        {analysis && analysis.hasX509Error && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Left 7 cols: Technical anatomy */}
            <div
              className="lg:col-span-7 rounded-2xl border p-4 sm:p-5 space-y-3"
              style={{
                background: 'color-mix(in srgb, var(--warn-soft) 40%, var(--panel-solid))',
                borderColor: 'color-mix(in srgb, var(--warn) 35%, transparent)',
              }}
            >
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2 text-xs font-bold text-[var(--warn)]">
                  <ShieldAlert style={{ width: 16, height: 16 }} />
                  <span>تحلیل تخصصی لاگ Xray: سرورهای مقصد فعال و در دسترس می‌باشند</span>
                </div>
                {analysis.responseMs !== null && (
                  <span className="chip chip--accent mono">
                    <Clock style={{ width: 11, height: 11 }} />
                    پاسخ در {analysis.responseMs}ms
                  </span>
                )}
              </div>

              <div className="text-xs leading-relaxed space-y-2 text-[var(--text)]">
                <p>
                  <strong>۱. سرورهای CDN Fastly:</strong> آی‌پی‌های{' '}
                  <code className="mono text-[var(--accent)] font-bold">
                    {analysis.uniqueEndpoints.join(', ') || '167.82.64.46:443'}
                  </code>{' '}
                  متعلق به لبه‌های جهانی <strong>Fastly CDN</strong> هستند. طبق لاگ شما، سرور در کمتر از{' '}
                  <strong>{analysis.responseMs || 455} میلی‌ثانیه</strong> دست می‌دهد و اصلاً فیلتر یا خاموش نیست.
                </p>
                <p>
                  <strong>۲. علت رد اتصال (<code className="mono text-[var(--danger)]">not {analysis.rejectedSni}</code>):</strong>{' '}
                  سازنده کانفیگ در بخش SNI دامنه فیک{' '}
                  <code className="mono text-[var(--danger)] font-bold">{analysis.rejectedSni}</code> را گذاشته تا از فیلتر ایران عبور کند (Domain Fronting). اما سرور Fastly گواهی پیش‌فرض خود را که فقط برای{' '}
                  <code className="mono text-[var(--accent)] font-bold">{analysis.primaryValidCert}</code> معتبر است می‌فرستد؛ هسته Xray این عدم تطابق را به عنوان خطای گواهی شناسایی کرده و اتصال را قطع می‌کند.
                </p>
              </div>

              {/* 3 Metrics */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
                <div className="stat">
                  <span className="stat__k">آی‌پی سرور (Alive)</span>
                  <span className="stat__v mono text-xs text-[var(--accent)] truncate" dir="ltr">
                    {analysis.uniqueEndpoints[0] || '167.82.64.46:443'}
                  </span>
                </div>
                <div className="stat">
                  <span className="stat__k">دامنه فیک ردشده</span>
                  <span className="stat__v mono text-xs text-[var(--danger)] truncate" dir="ltr">
                    {analysis.rejectedSni || 'firefox.com'}
                  </span>
                </div>
                <div className="stat">
                  <span className="stat__k">گواهی معتبر سرور</span>
                  <span className="stat__v mono text-xs text-[var(--accent-2)] truncate" dir="ltr">
                    {analysis.primaryValidCert || 'default.ssl.fastly.net'}
                  </span>
                </div>
              </div>
            </div>

            {/* Right 5 cols: Immediate Solution */}
            <div
              className="lg:col-span-5 rounded-2xl border p-4 sm:p-5 flex flex-col justify-between space-y-3"
              style={{
                background: 'color-mix(in srgb, var(--accent-soft) 40%, var(--panel-solid))',
                borderColor: 'color-mix(in srgb, var(--accent) 30%, transparent)',
              }}
            >
              <div className="space-y-2.5">
                <div className="flex items-center gap-2 text-xs font-bold text-[var(--accent)]">
                  <CheckCircle2 style={{ width: 16, height: 16 }} />
                  <span>راهکارهای رفع خطا در کلاینت‌های ارتباطی:</span>
                </div>

                <ul className="text-xs space-y-2 leading-relaxed text-[var(--muted)] list-disc list-inside">
                  <li>
                    <strong className="text-[var(--text)]">روش خودکار (پیشنهادی):</strong> سامانه پارامترهای ارتباطی{' '}
                    <code className="mono text-[var(--accent)]">allowInsecure=1</code> و{' '}
                    <code className="mono text-[var(--accent)]">vcn={analysis.primaryValidCert}</code> را به تمامی خروجی‌ها تزریق نموده است.
                  </li>
                  <li>
                    <strong className="text-[var(--text)]">روش تثبیت SNI (ویژه نرم‌افزار v2rayN):</strong> در صورت تداوم خطا، از گزینه زیر جهت تطبیق مستقیم SNI با گواهی Fastly استفاده فرمایید.
                  </li>
                </ul>
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => onChangeTlsFixMode('fastly-sni')}
                  className="btn btn--primary flex-1 text-xs"
                >
                  <ShieldCheck style={{ width: 14, height: 14 }} />
                  <span>تثبیت خودکار SNI بر اساس گواهی Fastly</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleCopy(analysis.primaryValidCert, 'cert-val')}
                  className="btn btn--ghost btn--sm mono text-xs"
                >
                  {copiedKey === 'cert-val' ? (
                    <>
                      <Check style={{ width: 13, height: 13, color: 'var(--accent)' }} />
                      <span>رونویسی شد</span>
                    </>
                  ) : (
                    <>
                      <Copy style={{ width: 13, height: 13 }} />
                      <span>رونویسی نشانی گواهی</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Collapsible Log Input Box */}
        <div className="pt-1">
          <button
            type="button"
            onClick={() => setOpenLogBox((v) => !v)}
            className="flex items-center justify-between w-full text-xs font-medium text-[var(--muted)] hover:text-[var(--text)] transition-colors py-1.5"
          >
            <span className="flex items-center gap-2">
              <Terminal style={{ width: 14, height: 14, color: 'var(--accent)' }} />
              <span>جای‌گذاری لاگ اختصاصی Xray شما برای بررسی و عیب‌یابی آنی</span>
            </span>
            <ChevronDown
              style={{
                width: 14,
                height: 14,
                transform: openLogBox ? 'rotate(180deg)' : 'none',
                transition: 'transform .2s',
              }}
            />
          </button>

          {openLogBox && (
            <div className="mt-2.5 space-y-2 pop-in">
              <textarea
                value={logInput}
                onChange={(e) => setLogInput(e.target.value)}
                dir="ltr"
                rows={5}
                placeholder="Paste your Xray / v2rayNG / v2rayN log here..."
                className="field field--code text-[11px]"
              />
              <div className="flex items-center justify-between text-[11px] text-[var(--faint)]">
                <span>لاگ بلافاصله تجزیه و تحلیل می‌شود</span>
                <button
                  type="button"
                  onClick={() => setLogInput(DEFAULT_USER_LOG)}
                  className="btn btn--ghost btn--sm text-[11px]"
                >
                  بازنشانی به لاگ نمونه
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};
