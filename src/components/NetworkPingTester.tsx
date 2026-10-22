import React, { useEffect, useState } from 'react';
import {
  Activity,
  Globe,
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  Plus,
  Wifi,
  Zap,
  ChevronDown,
  Globe2,
  Server,
  Signal,
  type LucideIcon,
} from 'lucide-react';
import { PanelTitle, LatencyChip } from './ui';

export interface PingTarget {
  id: string;
  name: string;
  subtitle: string;
  url: string;
  category: 'filtered' | 'global' | 'domestic' | 'custom';
  status: 'idle' | 'testing' | 'ok' | 'timeout';
  latencyMs: number | null;
  minMs?: number | null;
  maxMs?: number | null;
}

const INITIAL_TARGETS: PingTarget[] = [
  // Filtered in Iran
  {
    id: 'youtube',
    name: 'YouTube',
    subtitle: 'یوتیوب (ویدیو و استریم)',
    url: 'https://www.youtube.com/favicon.ico',
    category: 'filtered',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'telegram',
    name: 'Telegram Web',
    subtitle: 'تلگرام (پیام‌رسان)',
    url: 'https://telegram.org/favicon.ico',
    category: 'filtered',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'twitter',
    name: 'X (Twitter)',
    subtitle: 'توییتر / شبکه X',
    url: 'https://abs.twimg.com/favicons/twitter.3.ico',
    category: 'filtered',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'instagram',
    name: 'Instagram',
    subtitle: 'اینستاگرام (متا)',
    url: 'https://www.instagram.com/favicon.ico',
    category: 'filtered',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'whatsapp',
    name: 'WhatsApp',
    subtitle: 'واتساپ وب',
    url: 'https://web.whatsapp.com/favicon.ico',
    category: 'filtered',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'chatgpt',
    name: 'OpenAI / ChatGPT',
    subtitle: 'هوش مصنوعی (تحریم + فیلتر)',
    url: 'https://chatgpt.com/favicon.ico',
    category: 'filtered',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'bbc',
    name: 'BBC Persian',
    subtitle: 'بی‌بی‌سی فارسی (خبری)',
    url: 'https://www.bbc.com/favicon.ico',
    category: 'filtered',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'spotify',
    name: 'Spotify',
    subtitle: 'اسپاتیفای (موسیقی)',
    url: 'https://open.spotify.com/favicon.ico',
    category: 'filtered',
    status: 'idle',
    latencyMs: null,
  },
  // Global Connectivity & V2Ray 204 & Fastly/Cloudflare CDN
  {
    id: 'google204',
    name: 'Google Generate 204',
    subtitle: 'تست استاندارد پینگ V2Ray / Xray',
    url: 'https://www.gstatic.com/generate_204',
    category: 'global',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'fastly',
    name: 'Fastly CDN Edge',
    subtitle: 'شبکه CDN فستلی (سرور کانفیگ‌های نسل ۵)',
    url: 'https://www.fastly.com/favicon.ico',
    category: 'global',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare Edge',
    subtitle: 'شبکه CDN کلودفلر (1.1.1.1)',
    url: 'https://cp.cloudflare.com/generate_204',
    category: 'global',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'firefox',
    name: 'Firefox (Mozilla CDN)',
    subtitle: 'تست دامنه SNI فایرفاکس',
    url: 'https://www.mozilla.org/favicon.ico',
    category: 'global',
    status: 'idle',
    latencyMs: null,
  },
  // Domestic Iran Intranet
  {
    id: 'aparat',
    name: 'Aparat (آپارات)',
    subtitle: 'سرویس داخلی ایران (شبکه ملی)',
    url: 'https://www.aparat.com/favicon.ico',
    category: 'domestic',
    status: 'idle',
    latencyMs: null,
  },
  {
    id: 'digikala',
    name: 'Digikala (دیجی‌کالا)',
    subtitle: 'سرویس داخلی ایران (دیتاسنتر تهران)',
    url: 'https://www.digikala.com/favicon.ico',
    category: 'domestic',
    status: 'idle',
    latencyMs: null,
  },
];

export async function measureHttpPing(targetUrl: string, timeoutMs = 4500): Promise<number | null> {
  if (typeof window === 'undefined') return null;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  const sep = targetUrl.includes('?') ? '&' : '?';
  const cacheBusted = `${targetUrl}${sep}_cb=${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const start = performance.now();

  try {
    await fetch(cacheBusted, {
      method: 'GET',
      mode: 'no-cors',
      cache: 'no-store',
      signal: controller.signal,
    });
    window.clearTimeout(timer);
    return Math.max(1, Math.round(performance.now() - start));
  } catch {
    window.clearTimeout(timer);
    return null;
  }
}

interface NetworkPingTesterProps {
  isLight?: boolean;
  nested?: boolean;
}

export const NetworkPingTester: React.FC<NetworkPingTesterProps> = () => {
  const [targets, setTargets] = useState<PingTarget[]>(INITIAL_TARGETS);
  const [activeCategory, setActiveCategory] = useState<
    'all' | 'filtered' | 'global' | 'domestic'
  >('all');
  const [isTestingAll, setIsTestingAll] = useState(false);
  const [customHost, setCustomHost] = useState('');

  const pingSingleTarget = async (id: string, currentUrl: string) => {
    setTargets((prev) =>
      prev.map((t) => (t.id === id ? { ...t, status: 'testing' } : t))
    );

    const r1 = await measureHttpPing(currentUrl, 4200);
    let r2: number | null = null;
    if (r1 !== null) {
      r2 = await measureHttpPing(currentUrl, 3500);
    }

    const samples = [r1, r2].filter((x): x is number => x !== null);
    if (samples.length === 0) {
      setTargets((prev) =>
        prev.map((t) =>
          t.id === id ? { ...t, status: 'timeout', latencyMs: null, minMs: null, maxMs: null } : t
        )
      );
      return;
    }

    const avg = Math.round(samples.reduce((a, b) => a + b, 0) / samples.length);
    const min = Math.min(...samples);
    const max = Math.max(...samples);

    setTargets((prev) =>
      prev.map((t) =>
        t.id === id ? { ...t, status: 'ok', latencyMs: avg, minMs: min, maxMs: max } : t
      )
    );
  };

  const handlePingAll = async (filterCat?: 'all' | 'filtered' | 'global' | 'domestic') => {
    const catToRun = filterCat || activeCategory;
    setIsTestingAll(true);
    const list = targets.filter(
      (t) =>
        catToRun === 'all' ||
        t.category === catToRun ||
        (catToRun === 'filtered' && t.category === 'custom')
    );

    setTargets((prev) =>
      prev.map((t) => (list.some((item) => item.id === t.id) ? { ...t, status: 'testing' } : t))
    );

    await Promise.all(list.map((t) => pingSingleTarget(t.id, t.url)));
    setIsTestingAll(false);
  };

  const handleAddCustomTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    const raw = customHost.trim();
    if (!raw) return;

    let normalizedUrl = raw;
    if (!/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = `https://${normalizedUrl}`;
    }

    let hostname = raw;
    try {
      const u = new URL(normalizedUrl);
      hostname = u.hostname;
    } catch {
      // Keep raw
    }

    const id = `custom-${Date.now()}`;
    const newTarget: PingTarget = {
      id,
      name: hostname,
      subtitle: 'آدرس سفارشی کاربر',
      url: normalizedUrl,
      category: 'custom',
      status: 'testing',
      latencyMs: null,
    };

    setTargets((prev) => [newTarget, ...prev]);
    setCustomHost('');
    await pingSingleTarget(id, normalizedUrl);
  };

  const visibleTargets = targets.filter((t) => {
    if (activeCategory === 'all') return true;
    if (activeCategory === 'filtered') return t.category === 'filtered' || t.category === 'custom';
    return t.category === activeCategory;
  });

  const filteredTested = targets.filter(
    (t) => t.category === 'filtered' && (t.status === 'ok' || t.status === 'timeout')
  );
  const filteredReachable = filteredTested.filter((t) => t.status === 'ok');
  const globalReachable = targets.filter((t) => t.category === 'global' && t.status === 'ok');
  const allOkLatencies = targets
    .filter((t) => t.status === 'ok' && t.latencyMs !== null)
    .map((t) => t.latencyMs!);
  const avgOverallLatency =
    allOkLatencies.length > 0
      ? Math.round(allOkLatencies.reduce((a, b) => a + b, 0) / allOkLatencies.length)
      : null;

  const usagePercent = Math.min(
    100,
    Math.round((filteredReachable.length / Math.max(filteredTested.length, 1)) * 100)
  );

  return (
    <section id="ping" className="panel reveal d5">
      {/* Header */}
      <div className="panel__head">
        <PanelTitle
          icon={Activity}
          title="ارزیابی برخط پینگ و وضعیت دسترسی به سرویس‌های بین‌المللی و داخلی"
          note="بررسی مستقیم تاخیر زمانی (Latency) و امکان برقراری ارتباط با مقاصد اینترنتی و شبکه‌های توزیع محتوا درون مرورگر شما"
        />
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => handlePingAll('filtered')}
            disabled={isTestingAll}
            className="btn btn--ghost btn--sm"
          >
            <ShieldAlert style={{ width: 13, height: 13, color: 'var(--warn)' }} />
            <span>سرویس‌های بین‌المللی</span>
          </button>
          <button
            type="button"
            onClick={() => handlePingAll('all')}
            disabled={isTestingAll}
            className="btn btn--primary btn--sm"
          >
            <RefreshCw
              style={{ width: 13, height: 13 }}
              className={isTestingAll ? 'spin' : ''}
            />
            <span>{isTestingAll ? 'در حال ارزیابی...' : 'ارزیابی کلیه مقاصد'}</span>
          </button>
        </div>
      </div>

      <div className="panel__body space-y-4">
        {/* Live Connection Diagnosis Strip */}
        <div
          className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-2xl border"
          style={{ borderColor: 'var(--line)', background: 'color-mix(in srgb, var(--panel-solid) 50%, transparent)' }}
        >
          <div className="flex items-center gap-3 min-w-0">
            {filteredTested.length === 0 ? (
              <Wifi style={{ width: 17, height: 17, color: 'var(--faint)', flex: 'none' }} />
            ) : filteredReachable.length >= Math.ceil(filteredTested.length * 0.6) ? (
              <ShieldCheck style={{ width: 17, height: 17, color: 'var(--accent)', flex: 'none' }} />
            ) : (
              <ShieldAlert style={{ width: 17, height: 17, color: 'var(--warn)', flex: 'none' }} />
            )}
            <div className="text-xs min-w-0">
              <span className="text-[var(--faint)] ml-1.5">وضعیت پایداری اتصال:</span>
              {filteredTested.length === 0 ? (
                <span className="text-[var(--muted)] font-medium">
                  جهت بررسی وضعیت برقراری ارتباط و تخمین تاخیر زمانی، گزینه «ارزیابی کلیه مقاصد» را انتخاب فرمایید.
                </span>
              ) : filteredReachable.length >= Math.ceil(filteredTested.length * 0.6) ? (
                <span className="text-[var(--accent)] font-semibold">
                  ارتباط با مقاصد بین‌المللی برقرار است ({filteredReachable.length.toLocaleString('fa-IR')} از {filteredTested.length.toLocaleString('fa-IR')} مقصد پاسخگو) — تونل اتصال فعال است.
                </span>
              ) : globalReachable.length > 0 ? (
                <span className="text-[var(--warn)] font-semibold">
                  اتصال به شبکه جهانی برقرار است اما دسترسی به برخی سرویس‌ها با محدودیت مواجه می‌باشد ({filteredReachable.length.toLocaleString('fa-IR')} از {filteredTested.length.toLocaleString('fa-IR')} پاسخگو).
                </span>
              ) : (
                <span className="text-[var(--danger)] font-semibold">
                  عدم دریافت پاسخ از مقاصد بین‌المللی؛ احتمال وجود قطعی یا اختلال در شبکه اینترنت.
                </span>
              )}
            </div>
          </div>

          {avgOverallLatency !== null && (
            <div className="flex items-center gap-2 text-xs mono tabular-nums flex-none">
              <span className="chip chip--blue">
                <Zap style={{ width: 11, height: 11 }} />
                میانگین {avgOverallLatency}ms
              </span>
              <span className="chip chip--accent mono">
                <Signal style={{ width: 11, height: 11 }} />
                {usagePercent}% فیلترشده باز
              </span>
            </div>
          )}
        </div>

        {/* Custom Host Input */}
        <form onSubmit={handleAddCustomTarget} className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-0">
            <Globe
              style={{ width: 14, height: 14, color: 'var(--faint)', position: 'absolute', top: '50%', right: 13, transform: 'translateY(-50%)' }}
            />
            <input
              type="text"
              dir="ltr"
              value={customHost}
              onChange={(e) => setCustomHost(e.target.value)}
              placeholder="نشانی اینترنتی یا آدرس IP دلخواه (مثال: fastly.com یا 1.1.1.1)..."
              className="field field--code"
              style={{ paddingRight: 38, minHeight: 'auto', fontSize: 12 }}
            />
          </div>
          <button type="submit" className="btn btn--soft">
            <Plus style={{ width: 14, height: 14 }} />
            <span>افزودن و سنجش پینگ</span>
          </button>
        </form>

        {/* Category Tabs */}
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="seg hide-scroll overflow-x-auto">
            {[
              { id: 'all', label: `کلیه مقاصد (${targets.length.toLocaleString('fa-IR')})`, icon: Globe2 },
              { id: 'filtered', label: 'سرویس‌های بین‌المللی', icon: ShieldAlert },
              { id: 'global', label: 'شبکه‌های CDN / Fastly', icon: Globe },
              { id: 'domestic', label: 'سرویس‌های داخلی', icon: Server },
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveCategory(tab.id as 'all' | 'filtered' | 'global' | 'domestic')}
                  aria-pressed={activeCategory === tab.id}
                  className={`seg__item ${activeCategory === tab.id ? 'is-active' : ''}`}
                >
                  <Icon style={{ width: 13, height: 13 }} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
          <span className="text-[11px] text-[var(--faint)] hidden sm:block">
            جهت سنجش مجدد تاخیر زمانی هر سرویس، بر روی کارت مربوطه کلیک فرمایید.
          </span>
        </div>

        {/* Targets Grid: Mobile Cards + Desktop Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {visibleTargets.map((target) => (
            <div
              key={target.id}
              onClick={() => pingSingleTarget(target.id, target.url)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') pingSingleTarget(target.id, target.url);
              }}
              className="group flex items-center justify-between gap-3 p-3 rounded-xl border transition-colors pop-in"
              style={{
                borderColor: 'var(--line)',
                background: 'color-mix(in srgb, var(--panel-solid) 42%, transparent)',
                cursor: 'pointer',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'color-mix(in srgb, var(--accent) 7%, var(--panel-solid))';
                e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--accent) 28%, transparent)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'color-mix(in srgb, var(--panel-solid) 42%, transparent)';
                e.currentTarget.style.borderColor = 'var(--line)';
              }}
            >
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex items-center gap-1.5">
                  <span
                    className={`led ${
                      target.status === 'ok'
                        ? 'led--on'
                        : target.status === 'timeout'
                        ? 'led--bad'
                        : target.status === 'testing'
                        ? 'led--busy'
                        : ''
                    }`}
                  />
                  <span
                    className="text-xs font-semibold truncate text-[var(--text)]"
                    dir="ltr"
                  >
                    {target.name}
                  </span>
                  {target.category === 'filtered' && <span className="chip chip--danger mono !text-[9px] !px-1.5 !py-0.5">فیلتر</span>}
                  {target.category === 'domestic' && <span className="chip chip--blue mono !text-[9px] !px-1.5 !py-0.5">داخلی</span>}
                </div>
                <p className="text-[11px] text-[var(--faint)] truncate">{target.subtitle}</p>
              </div>

              <div className="shrink-0 flex flex-col items-end gap-1">
                <LatencyChip ms={target.latencyMs} status={target.status} />
                {target.status === 'ok' && target.minMs != null && target.maxMs != null && target.minMs !== target.maxMs && (
                  <span dir="ltr" className="text-[10px] mono text-[var(--faint)] tabular-nums">
                    {target.minMs}–{target.maxMs}ms
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
