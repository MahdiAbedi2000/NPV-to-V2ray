import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Lock,
  Unlock,
  ShieldCheck,
  Sparkles,
  Copy,
  Check,
  Download,
  Send,
  RefreshCw,
  Sliders,
  Type,
  Share2,
  ChevronDown,
  Eye,
  Palette,
  Megaphone,
  Package,
  Table2,
  Fingerprint,
  Wand2,
  Radio,
} from 'lucide-react';
import {
  ConvertedNode,
  buildNPVSV5ContainerFromLinks,
  buildNPVTContainerFromLinks,
  base64Utf8,
} from '../utils/npvConverter';
import { CopyButton, useClipboard, useToast } from './ui';
import { DEFAULT_ALIAS, type AliasProfile } from '../utils/aliasProfile';

type NamingMode = 'template' | 'fixed' | 'fixed-indexed';
type CaptionMode = 'template' | 'fixed';
type TargetContainer = 'npvs5' | 'npvt1' | 'base64';

export interface StealthRebrandStudioProps {
  nodes: ConvertedNode[];
  gen2Ready: boolean;
  onEnsureGen2: () => Promise<boolean>;
  onLock: () => void;
  alias: AliasProfile;
  onAliasChange: (next: AliasProfile) => void;
  onGoDecode: () => void;
  onLoadSample: () => void;
}

/* ------------------------------------------------------------------ */
/*  helpers                                                             */
/* ------------------------------------------------------------------ */

/** Replace the visible remark of a share link (vmess keeps its JSON body). */
function rewriteLinkRemark(link: string, name: string): string {
  if (/^vmess:\/\//i.test(link)) {
    try {
      const raw = link.slice('vmess://'.length).split('#')[0];
      const bin = atob(raw);
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      const json = JSON.parse(new TextDecoder().decode(bytes));
      json.ps = name;
      const encoded = base64Utf8(JSON.stringify(json));
      return `vmess://${encoded}#${encodeURIComponent(name)}`;
    } catch {
      /* fall through to plain fragment replacement */
    }
  }
  const hashIndex = link.indexOf('#');
  const base = hashIndex === -1 ? link : link.slice(0, hashIndex);
  return `${base}#${encodeURIComponent(name)}`;
}

const STRIP_PATTERNS: RegExp[] = [
  /@[A-Za-z0-9_]{3,}/g,
  /https?:\/\/[^\s]+/g,
  /t\.me\/[^\s]+/g,
  /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/gu,
];

function stripSellerTags(name: string): string {
  return STRIP_PATTERNS.reduce((acc, re) => acc.replace(re, ' '), name)
    .replace(/\s+/g, ' ')
    .trim();
}

function todayFa(): string {
  return new Date().toLocaleDateString('fa-IR', { year: 'numeric', month: 'long', day: 'numeric' });
}

/* ------------------------------------------------------------------ */
/*  accordion shell — progressive disclosure                            */
/* ------------------------------------------------------------------ */

interface SectionProps {
  step: number;
  title: string;
  note?: string;
  icon: React.ComponentType<{ style?: React.CSSProperties; className?: string }>;
  badge?: React.ReactNode;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}

const Section: React.FC<SectionProps> = ({ step, title, note, icon: Icon, badge, open, onToggle, children }) => (
  <section className={`vsec ${open ? 'is-open' : ''}`}>
    <button type="button" className="vsec__head" onClick={onToggle} aria-expanded={open}>
      <span className="vsec__step mono">{String(step).padStart(2, '0')}</span>
      <span className="vsec__icon">
        <Icon style={{ width: 15, height: 15 }} />
      </span>
      <span className="vsec__labels">
        <span className="vsec__title">{title}</span>
        {note && <span className="vsec__note">{note}</span>}
      </span>
      {badge}
      <ChevronDown className="vsec__chev" style={{ width: 15, height: 15 }} />
    </button>
    {open && <div className="vsec__body">{children}</div>}
  </section>
);

/* ------------------------------------------------------------------ */
/*  studio                                                              */
/* ------------------------------------------------------------------ */

export const StealthRebrandStudio: React.FC<StealthRebrandStudioProps> = ({
  nodes,
  onEnsureGen2,
  onLock,
  alias,
  onAliasChange,
  onGoDecode,
  onLoadSample,
}) => {
  const { push } = useToast();
  const { copied, copy } = useClipboard();

  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    identity: true,
    naming: true,
    caption: false,
    package: false,
  });

  /* ---- identity (alias) ---- */
  const [aliasDraft, setAliasDraft] = useState<AliasProfile>(alias);

  /* keep the editor in sync when the parent identity changes */
  useEffect(() => {
    setAliasDraft(alias);
  }, [alias]);

  /* ---- naming ---- */
  const [brandChannel, setBrandChannel] = useState('@MySecureProxy');
  const [brandPrefix, setBrandPrefix] = useState('VIP');
  const [brandSuffix, setBrandSuffix] = useState('');
  const [namingMode, setNamingMode] = useState<NamingMode>('template');
  const [namingTemplate, setNamingTemplate] = useState('{prefix} | {channel} #{i} ({proto})');
  const [fixedName, setFixedName] = useState('Secure Node');
  const [stripOldBrands, setStripOldBrands] = useState(true);
  const [customFindWord, setCustomFindWord] = useState('');
  const [customReplaceWord, setCustomReplaceWord] = useState('');

  /* ---- caption ---- */
  const [captionMode, setCaptionMode] = useState<CaptionMode>('template');
  const [captionHeader, setCaptionHeader] = useState(
    '🚀 کانفیگ‌های اختصاصی و پرسرعت (تست‌شده و بدون قطعی)\n🔒 رمزگشایی و بهینه‌سازی‌شده با فیلترشکن اختصاصی\n📡 پروتکل‌های V2Ray / Xray کاملاً سازگار'
  );
  const [captionFooter, setCaptionFooter] = useState(
    '⭐️ اختصاصی کانال: {channel}\n🔗 دریافت آخرین به‌روزرسانی‌ها با عضویت در کانال ما\nتاریخ انتشار: {date}'
  );
  const [fixedCaption, setFixedCaption] = useState(
    'کانفیگ‌های اختصاصی این کانال — تست‌شده و پایدار.\nبرای دریافت نسخه جدید همین پیام را دنبال کنید.'
  );
  const [includeLinks, setIncludeLinks] = useState(true);

  /* ---- packaging ---- */
  const [targetContainer, setTargetContainer] = useState<TargetContainer>('npvs5');
  const [customPassphrase, setCustomPassphrase] = useState('');
  const [customCreatorMsg, setCustomCreatorMsg] = useState('Published via private studio');

  const toggle = (id: string) => setOpenSections((prev) => ({ ...prev, [id]: !prev[id] }));

  /* ---------------------------------------------------------------- */
  /*  naming engine                                                    */
  /* ---------------------------------------------------------------- */

  const rebrandedNodes = useMemo(() => {
    if (!nodes || nodes.length === 0) return [];

    return nodes.map((node, index) => {
      let baseName = node.name;

      if (stripOldBrands) baseName = stripSellerTags(baseName);
      if (customFindWord.trim()) {
        baseName = baseName.split(customFindWord.trim()).join(customReplaceWord.trim());
      }

      let finalName: string;
      if (namingMode === 'fixed') {
        finalName = fixedName.trim() || 'Secure Node';
      } else if (namingMode === 'fixed-indexed') {
        finalName = `${fixedName.trim() || 'Secure Node'} ${String(index + 1).padStart(2, '0')}`;
      } else {
        finalName = namingTemplate
          .replace(/\{prefix\}/g, brandPrefix)
          .replace(/\{suffix\}/g, brandSuffix)
          .replace(/\{channel\}/g, brandChannel)
          .replace(/\{i\}/g, String(index + 1))
          .replace(/\{proto\}/g, node.protocol.toUpperCase())
          .replace(/\{server\}/g, node.server)
          .replace(/\{port\}/g, node.port)
          .replace(/\s+/g, ' ')
          .trim();
      }

      if (!finalName) finalName = `Node ${index + 1}`;

      return {
        ...node,
        name: finalName,
        link: rewriteLinkRemark(node.link, finalName),
      };
    });
  }, [
    nodes,
    namingMode,
    namingTemplate,
    fixedName,
    brandChannel,
    brandPrefix,
    brandSuffix,
    stripOldBrands,
    customFindWord,
    customReplaceWord,
  ]);

  /* ---------------------------------------------------------------- */
  /*  caption / broadcast text                                         */
  /* ---------------------------------------------------------------- */

  const broadcastText = useMemo(() => {
    if (rebrandedNodes.length === 0 && captionMode === 'template') return '';
    const now = todayFa();
    const linksList = rebrandedNodes
      .map((n, i) => `${i + 1}. 🔰 ${n.name}\n\`${n.link}\``)
      .join('\n\n');
    const divider = '\n\n━━━━━━━━━━━━━━━━━━━━\n';

    if (captionMode === 'fixed') {
      const head = fixedCaption
        .replace(/\{channel\}/g, brandChannel)
        .replace(/\{count\}/g, String(rebrandedNodes.length))
        .replace(/\{date\}/g, now)
        .trim();
      if (!includeLinks) return head;
      return `${head}${divider}${linksList}`;
    }

    const header = captionHeader
      .replace(/\{channel\}/g, brandChannel)
      .replace(/\{count\}/g, String(rebrandedNodes.length))
      .replace(/\{date\}/g, now);
    const footer = captionFooter
      .replace(/\{channel\}/g, brandChannel)
      .replace(/\{count\}/g, String(rebrandedNodes.length))
      .replace(/\{date\}/g, now);

    const body = includeLinks ? `${header}${divider}${linksList}${divider}\n${footer}` : `${header}\n\n${footer}`;
    return body;
  }, [
    rebrandedNodes,
    captionMode,
    captionHeader,
    captionFooter,
    fixedCaption,
    brandChannel,
    includeLinks,
  ]);

  const subscriptionBase64 = useMemo(() => {
    if (rebrandedNodes.length === 0) return '';
    const joined = rebrandedNodes.map((n) => n.link).join('\n');
    try {
      return base64Utf8(joined);
    } catch {
      return '';
    }
  }, [rebrandedNodes]);

  /* ---------------------------------------------------------------- */
  /*  actions                                                          */
  /* ---------------------------------------------------------------- */

  const handleApplyAlias = useCallback(() => {
    const next: AliasProfile = {
      ...aliasDraft,
      name: aliasDraft.name.trim() || DEFAULT_ALIAS.name,
      caption: aliasDraft.caption.trim() || DEFAULT_ALIAS.caption,
      kicker: aliasDraft.kicker.trim() || DEFAULT_ALIAS.kicker,
    };
    onAliasChange(next);
    push('ok', next.enabled ? `پوشش ظاهری روی «${next.name}» فعال شد` : 'پوشش ظاهری غیرفعال شد');
  }, [aliasDraft, onAliasChange, push]);

  const downloadBlob = useCallback(
    (content: string | Uint8Array, filename: string, mime: string) => {
      const payload =
        typeof content === 'string' ? content : (content.slice(0).buffer as ArrayBuffer);
      const blob = new Blob([payload], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.setTimeout(() => {
        URL.revokeObjectURL(a.href);
        a.remove();
      }, 200);
    },
    []
  );

  const handleExport = useCallback(async () => {
    if (rebrandedNodes.length === 0) {
      push('error', 'هیچ نودی برای بسته‌بندی موجود نیست.');
      return;
    }
    const links = rebrandedNodes.map((n) => n.link);
    const slug = (brandChannel || 'private').replace(/[@\s/\\]+/g, '_').replace(/^_|_$/g, '');

    try {
      if (targetContainer === 'npvs5') {
        await onEnsureGen2();
        const built = buildNPVSV5ContainerFromLinks(links, {
          passphrase: customPassphrase.trim() || undefined,
          displayMessage: customCreatorMsg.trim() || undefined,
        });
        if (!built) {
          push('error', 'خطا در ساخت باینری نسل ۵');
          return;
        }
        downloadBlob(built.bytes, `${slug}_v5.npvs`, 'application/octet-stream');
        push('ok', 'کانتینر NPVS v5 با برند شما دانلود شد.');
      } else if (targetContainer === 'npvt1') {
        const text = buildNPVTContainerFromLinks(links);
        downloadBlob(text, `${slug}.npvt`, 'text/plain;charset=utf-8');
        push('ok', 'کانتینر NPVT1 با برند شما دانلود شد.');
      } else {
        downloadBlob(subscriptionBase64, `subscription_${slug}.txt`, 'text/plain;charset=utf-8');
        push('ok', 'لینک اشتراک با برند شما دانلود شد.');
      }
    } catch (e: any) {
      push('error', `خطا در بسته‌بندی: ${e?.message || 'نامشخص'}`);
    }
  }, [
    rebrandedNodes,
    brandChannel,
    targetContainer,
    customPassphrase,
    customCreatorMsg,
    onEnsureGen2,
    downloadBlob,
    subscriptionBase64,
    push,
  ]);

  /* ---------------------------------------------------------------- */
  /*  render                                                           */
  /* ---------------------------------------------------------------- */

  return (
    <div className="vstudio">
      {/* ---------- top bar ---------- */}
      <div className="panel vstudio__bar">
        <div className="vstudio__bar-id">
          <div className="vstudio__bar-seal">
            <Sparkles style={{ width: 17, height: 17 }} />
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9, flexWrap: 'wrap' }}>
              <h2 className="display" style={{ fontSize: 'clamp(15px,2vw,18px)' }}>
                استودیوی اختصاصی انتشار
              </h2>
              <span className="chip chip--accent mono">
                <ShieldCheck style={{ width: 11, height: 11 }} />
                AUTHENTICATED
              </span>
            </div>
            <p style={{ fontSize: 11.5, color: 'var(--muted)', marginTop: 3 }}>
              {rebrandedNodes.length.toLocaleString('fa-IR')} سرور در حافظه · تغییر نام، کپشن ثابت و بسته‌بندی مجدد
            </p>
          </div>
        </div>

        <div className="vstudio__bar-actions">
          <button type="button" onClick={onLock} className="btn btn--danger btn--sm">
            <Lock style={{ width: 13, height: 13 }} />
            <span>قفل‌گذاری و خروج</span>
          </button>
        </div>
      </div>

      {/* ---------- empty state ---------- */}
      {rebrandedNodes.length === 0 && (
        <div className="panel vstudio__empty">
          <div className="vstudio__empty-icon">
            <Radio style={{ width: 20, height: 20 }} />
          </div>
          <div style={{ minWidth: 0 }}>
            <h3 className="display" style={{ fontSize: 15 }}>
              در حال حاضر کانفیگی در حافظه موجود نمی‌باشد
            </h3>
            <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 5, lineHeight: 1.9 }}>
              برای بازنویسی نام‌ها و انتشار، ابتدا یک فایل <code className="mono">.npvs</code> یا{' '}
              <code className="mono">.npvt</code> را در صفحه رمزگشایی باز کنید.
            </p>
          </div>
          <div className="vstudio__empty-actions">
            <button type="button" onClick={onLoadSample} className="btn btn--soft btn--sm">
              <Sparkles style={{ width: 13, height: 13 }} />
              <span>بارگذاری نمونه</span>
            </button>
            <button type="button" onClick={onGoDecode} className="btn btn--primary btn--sm">
              <Unlock style={{ width: 13, height: 13 }} />
              <span>مراجعه به بخش رمزگشایی</span>
            </button>
          </div>
        </div>
      )}

      {/* ---------- steps ---------- */}
      <div className="vsteps">
        {/* 01 — identity */}
        <Section
          step={1}
          title="شخصی‌سازی عنوان و هویت سامانه"
          note="تنظیم عنوان تجاری و توضیحات اختصاصی نمایش‌داده‌شده در سربرگ"
          icon={Palette}
          open={openSections.identity}
          onToggle={() => toggle('identity')}
          badge={
            <span className={`chip ${alias.enabled ? 'chip--accent' : ''} mono`}>
              {alias.enabled ? alias.name : 'OFF'}
            </span>
          }
        >
          <div className="vgrid vgrid--2">
            <label className="vfield">
              <span className="vfield__label">نام ثابت نمایش‌داده‌شده</span>
              <input
                type="text"
                dir="ltr"
                value={aliasDraft.name}
                onChange={(e) => setAliasDraft((p) => ({ ...p, name: e.target.value }))}
                className="field mono"
                style={{ fontSize: 12.5 }}
                placeholder="NODE//GRID"
              />
            </label>
            <label className="vfield">
              <span className="vfield__label">کپشن ثابت (زیر نام)</span>
              <input
                type="text"
                value={aliasDraft.caption}
                onChange={(e) => setAliasDraft((p) => ({ ...p, caption: e.target.value }))}
                className="field"
                style={{ fontSize: 12.5 }}
                placeholder="مجموعه کانفیگ اختصاصی"
              />
            </label>
            <label className="vfield">
              <span className="vfield__label">زیرنویس مونو</span>
              <input
                type="text"
                dir="ltr"
                value={aliasDraft.kicker}
                onChange={(e) => setAliasDraft((p) => ({ ...p, kicker: e.target.value }))}
                className="field mono"
                style={{ fontSize: 12.5 }}
                placeholder="PRIVATE DISTRIBUTION NODE"
              />
            </label>
            <div className="vfield">
              <span className="vfield__label">وضعیت</span>
              <label className="vtoggle">
                <input
                  type="checkbox"
                  checked={aliasDraft.enabled}
                  onChange={(e) => setAliasDraft((p) => ({ ...p, enabled: e.target.checked }))}
                />
                <span className="vtoggle__track">
                  <span className="vtoggle__thumb" />
                </span>
                <span className="vtoggle__text">هویت اختصاصی فعال گردد</span>
              </label>
            </div>
          </div>

          <div className="vpreview vpreview--identity">
            <div className="vpreview__chrome">
              <span className="mono">پیش‌نمایش هدر</span>
            </div>
            <div className="vpreview__stage">
              <div className="vpreview__mark">
                <Fingerprint style={{ width: 18, height: 18 }} />
              </div>
              <div style={{ minWidth: 0 }}>
                <div className="display" style={{ fontSize: 15 }}>
                  {aliasDraft.enabled ? aliasDraft.name || DEFAULT_ALIAS.name : 'NPV//FORGE'}
                </div>
                <div className="mono" style={{ fontSize: 9, letterSpacing: '0.18em', color: 'var(--faint)' }}>
                  {aliasDraft.enabled ? aliasDraft.kicker || DEFAULT_ALIAS.kicker : 'NPV TUNNEL UTILITIES'}
                </div>
              </div>
              <span className="vpreview__caption">
                {aliasDraft.enabled ? aliasDraft.caption || DEFAULT_ALIAS.caption : 'تبدیل‌کننده کانفیگ NPV'}
              </span>
            </div>
          </div>

          <div className="vactions">
            <button type="button" onClick={handleApplyAlias} className="btn btn--primary btn--sm">
              <Eye style={{ width: 13, height: 13 }} />
              <span>تثبیت و اعمال بر روی سامانه</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setAliasDraft({ ...DEFAULT_ALIAS });
                onAliasChange({ ...DEFAULT_ALIAS });
                push('info', 'هویت سامانه به تنظیمات پیش‌فرض بازنشانی گردید.');
              }}
              className="btn btn--ghost btn--sm"
            >
              <RefreshCw style={{ width: 13, height: 13 }} />
              <span>بازنشانی به هویت پیش‌فرض</span>
            </button>
          </div>
        </Section>

        {/* 02 — naming */}
        <Section
          step={2}
          title="الگوی نام‌گذاری سرورها"
          note="تنظیم ساختار عناوین سرورها به صورت یکسان، قالب‌دار یا ترتیبی"
          icon={Type}
          open={openSections.naming}
          onToggle={() => toggle('naming')}
          badge={<span className="chip mono">{rebrandedNodes.length} نود</span>}
        >
          <div className="vseg" role="tablist" aria-label="حالت نام‌گذاری">
            {(
              [
                { id: 'template', label: 'قالب‌دار', icon: Wand2 },
                { id: 'fixed', label: 'نام ثابت یکسان', icon: Type },
                { id: 'fixed-indexed', label: 'نام ثابت + شماره', icon: Sliders },
              ] as const
            ).map((m) => {
              const Icon = m.icon;
              return (
                <button
                  key={m.id}
                  type="button"
                  role="tab"
                  aria-selected={namingMode === m.id}
                  onClick={() => setNamingMode(m.id)}
                  className={`seg__item ${namingMode === m.id ? 'is-active' : ''}`}
                  style={{ fontSize: 11.5 }}
                >
                  <Icon style={{ width: 13, height: 13 }} />
                  <span>{m.label}</span>
                </button>
              );
            })}
          </div>

          {namingMode === 'template' ? (
            <div className="vgrid vgrid--2">
              <label className="vfield">
                <span className="vfield__label">نام کانال / برند ({'{channel}'})</span>
                <input
                  type="text"
                  dir="ltr"
                  value={brandChannel}
                  onChange={(e) => setBrandChannel(e.target.value)}
                  className="field mono"
                  style={{ fontSize: 12.5 }}
                />
              </label>
              <label className="vfield">
                <span className="vfield__label">قالب نام</span>
                <input
                  type="text"
                  dir="ltr"
                  value={namingTemplate}
                  onChange={(e) => setNamingTemplate(e.target.value)}
                  className="field mono"
                  style={{ fontSize: 12.5, color: 'var(--accent)' }}
                />
              </label>
              <label className="vfield">
                <span className="vfield__label">پیشوند ({'{prefix}'})</span>
                <input
                  type="text"
                  value={brandPrefix}
                  onChange={(e) => setBrandPrefix(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5 }}
                />
              </label>
              <label className="vfield">
                <span className="vfield__label">پسوند ({'{suffix}'})</span>
                <input
                  type="text"
                  value={brandSuffix}
                  onChange={(e) => setBrandSuffix(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5 }}
                />
              </label>
              <p className="vfield__hint vgrid__full">
                متغیرها: <code className="mono">{'{prefix}'}</code>,{' '}
                <code className="mono">{'{channel}'}</code>, <code className="mono">{'{i}'}</code>,{' '}
                <code className="mono">{'{proto}'}</code>, <code className="mono">{'{server}'}</code>,{' '}
                <code className="mono">{'{port}'}</code>, <code className="mono">{'{suffix}'}</code>
              </p>
            </div>
          ) : (
            <div className="vgrid vgrid--2">
              <label className="vfield">
                <span className="vfield__label">
                  {namingMode === 'fixed' ? 'متن ثابت نام (برای همه نودها یکی)' : 'متن ثابت نام (پایه شماره)'}
                </span>
                <input
                  type="text"
                  value={fixedName}
                  onChange={(e) => setFixedName(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5 }}
                  placeholder="Secure Node"
                />
              </label>
              <div className="vfield">
                <span className="vfield__label">نمونه خروجی</span>
                <div className="vfield__sample mono">
                  {namingMode === 'fixed'
                    ? fixedName || 'Secure Node'
                    : `${fixedName || 'Secure Node'} 01`}
                </div>
              </div>
            </div>
          )}

          <label className="vtoggle vtoggle--row">
            <input
              type="checkbox"
              checked={stripOldBrands}
              onChange={(e) => setStripOldBrands(e.target.checked)}
            />
            <span className="vtoggle__track">
              <span className="vtoggle__thumb" />
            </span>
            <span className="vtoggle__text">پاک‌سازی خودکار شناسه‌های تبلیغاتی، لینک‌ها و ایموجی‌های فروشنده پیشین</span>
          </label>

          <details className="vdetails">
            <summary>
              <span>جایگزینی کلمه خاص (پیشرفته)</span>
              <ChevronDown style={{ width: 13, height: 13 }} />
            </summary>
            <div className="vgrid vgrid--2" style={{ marginTop: 10 }}>
              <label className="vfield">
                <span className="vfield__label">این عبارت را پیدا کن</span>
                <input
                  type="text"
                  value={customFindWord}
                  onChange={(e) => setCustomFindWord(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5 }}
                />
              </label>
              <label className="vfield">
                <span className="vfield__label">با این جایگزین کن</span>
                <input
                  type="text"
                  value={customReplaceWord}
                  onChange={(e) => setCustomReplaceWord(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5 }}
                />
              </label>
            </div>
          </details>

          {rebrandedNodes.length > 0 && (
            <div className="vpreview">
              <div className="vpreview__chrome">
                <span className="mono">پیش‌نمایش نام‌ها</span>
                <span className="mono" style={{ color: 'var(--accent)' }}>{rebrandedNodes.length}</span>
              </div>
              <div className="vpreview__list">
                {rebrandedNodes.slice(0, 6).map((n) => (
                  <div key={n.id} className="vpreview__row">
                    <span className="chip chip--accent mono">{n.protocol.toUpperCase()}</span>
                    <span className="vpreview__name">{n.name}</span>
                    <span className="mono vpreview__old" dir="ltr">
                      {nodes.find((x) => x.id === n.id)?.name}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Section>

        {/* 03 — caption */}
        <Section
          step={3}
          title="پیکربندی کپشن و متن انتشار"
          note="تنظیم متن سربرگ، پاورقی و قالب انتشار متصل به سرورها"
          icon={Megaphone}
          open={openSections.caption}
          onToggle={() => toggle('caption')}
          badge={
            <span className={`chip ${captionMode === 'fixed' ? 'chip--warn' : ''} mono`}>
              {captionMode === 'fixed' ? 'FIXED' : 'TEMPLATE'}
            </span>
          }
        >
          <div className="vseg" role="tablist" aria-label="حالت کپشن">
            {(
              [
                { id: 'template', label: 'سربرگ + فوتر' },
                { id: 'fixed', label: 'کپشن ثابت' },
              ] as const
            ).map((m) => (
              <button
                key={m.id}
                type="button"
                role="tab"
                aria-selected={captionMode === m.id}
                onClick={() => setCaptionMode(m.id)}
                className={`seg__item ${captionMode === m.id ? 'is-active' : ''}`}
                style={{ fontSize: 11.5 }}
              >
                <span>{m.label}</span>
              </button>
            ))}
          </div>

          {captionMode === 'template' ? (
            <div className="vgrid">
              <label className="vfield">
                <span className="vfield__label">سربرگ پست</span>
                <textarea
                  rows={4}
                  value={captionHeader}
                  onChange={(e) => setCaptionHeader(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5, lineHeight: 1.9 }}
                />
              </label>
              <label className="vfield">
                <span className="vfield__label">پاورقی پست</span>
                <textarea
                  rows={3}
                  value={captionFooter}
                  onChange={(e) => setCaptionFooter(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5, lineHeight: 1.9 }}
                />
              </label>
              <p className="vfield__hint">
                متغیرها: <code className="mono">{'{channel}'}</code>,{' '}
                <code className="mono">{'{count}'}</code>, <code className="mono">{'{date}'}</code>
              </p>
            </div>
          ) : (
            <div className="vgrid">
              <label className="vfield">
                <span className="vfield__label">متن ثابت کپشن</span>
                <textarea
                  rows={5}
                  value={fixedCaption}
                  onChange={(e) => setFixedCaption(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5, lineHeight: 1.9 }}
                />
              </label>
            </div>
          )}

          <label className="vtoggle vtoggle--row">
            <input
              type="checkbox"
              checked={includeLinks}
              onChange={(e) => setIncludeLinks(e.target.checked)}
            />
            <span className="vtoggle__track">
              <span className="vtoggle__thumb" />
            </span>
            <span className="vtoggle__text">لینک‌ها زیر کپشن منتشر شوند</span>
          </label>

          <div className="codepane">
            <div className="codepane__chrome">
              <div className="codepane__dots">
                <i />
                <i />
                <i />
              </div>
              <span className="mono" style={{ fontSize: 10, letterSpacing: '0.16em', color: 'var(--faint)' }}>
                POST PREVIEW
              </span>
              <CopyButton
                text={broadcastText}
                copyKey="broadcast-caption"
                copied={copied}
                onCopy={copy}
                iconOnly
                label="کپی پست"
              />
            </div>
            <pre className="codepane__pre" dir="rtl" style={{ maxHeight: 300 }}>
              {broadcastText || '// برای دیدن پیش‌نمایش، یک کانفیگ بارگذاری کنید'}
            </pre>
          </div>
        </Section>

        {/* 04 — packaging */}
        <Section
          step={4}
          title="بسته‌بندی نهایی و صدور فایل"
          note="رمزنگاری و تولید کانتینرهای استاندارد با هویت و امضای اختصاصی"
          icon={Package}
          open={openSections.package}
          onToggle={() => toggle('package')}
          badge={<span className="chip chip--blue mono">EXPORT</span>}
        >
          <div className="vseg" role="tablist" aria-label="نوع خروجی">
            {(
              [
                { id: 'npvs5', label: 'NPVS v5 (.npvs)' },
                { id: 'npvt1', label: 'NPVT1 (.npvt)' },
                { id: 'base64', label: 'لینک اشتراک' },
              ] as const
            ).map((m) => (
              <button
                key={m.id}
                type="button"
                role="tab"
                aria-selected={targetContainer === m.id}
                onClick={() => setTargetContainer(m.id)}
                className={`seg__item ${targetContainer === m.id ? 'is-active' : ''}`}
                style={{ fontSize: 11.5 }}
              >
                <span>{m.label}</span>
              </button>
            ))}
          </div>

          {targetContainer === 'npvs5' && (
            <div className="vgrid vgrid--2">
              <label className="vfield">
                <span className="vfield__label">Passphrase قفل اختصاصی (اختیاری)</span>
                <input
                  type="text"
                  dir="ltr"
                  value={customPassphrase}
                  onChange={(e) => setCustomPassphrase(e.target.value)}
                  className="field mono"
                  style={{ fontSize: 12.5 }}
                />
              </label>
              <label className="vfield">
                <span className="vfield__label">پیام سازنده داخل فایل</span>
                <input
                  type="text"
                  value={customCreatorMsg}
                  onChange={(e) => setCustomCreatorMsg(e.target.value)}
                  className="field"
                  style={{ fontSize: 12.5 }}
                />
              </label>
            </div>
          )}

          <div className="vactions">
            <button
              type="button"
              onClick={handleExport}
              disabled={rebrandedNodes.length === 0}
              className="btn btn--primary"
            >
              <Download style={{ width: 14, height: 14 }} />
              <span>
                {targetContainer === 'npvs5'
                  ? 'دانلود فایل رمزنگاری‌شده NPVS v5'
                  : targetContainer === 'npvt1'
                  ? 'دانلود فایل NPVT1'
                  : 'دانلود لینک اشتراک'}
              </span>
            </button>
            <CopyButton
              text={subscriptionBase64}
              copyKey="rebrand-sub-b64"
              copied={copied}
              onCopy={copy}
              label="رونویسی Base64"
              doneLabel="کپی شد!"
              variant="btn--soft"
            />
            <CopyButton
              text={broadcastText}
              copyKey="broadcast-caption"
              copied={copied}
              onCopy={copy}
              label="رونویسی متن انتشار"
              doneLabel="کپی شد!"
              variant="btn--soft"
            />
            <button
              type="button"
              disabled={!broadcastText}
              onClick={() => downloadBlob(broadcastText, 'post.txt', 'text/plain;charset=utf-8')}
              className="btn btn--ghost"
            >
              <Send style={{ width: 14, height: 14 }} />
              <span>دریافت متن پست</span>
            </button>
          </div>
        </Section>
      </div>

      {/* ---------- live table ---------- */}
      {rebrandedNodes.length > 0 && (
        <section className="panel vtable">
          <div className="panel__head">
            <div style={{ display: 'flex', alignItems: 'center', gap: 11, minWidth: 0 }}>
              <div className="vstudio__bar-seal" style={{ width: 34, height: 34 }}>
                <Table2 style={{ width: 15, height: 15 }} />
              </div>
              <div style={{ minWidth: 0 }}>
                <h3 className="display" style={{ fontSize: 14 }}>
                  فهرست نهایی سرورهای بازنویسی‌شده ({rebrandedNodes.length})
                </h3>
                <p style={{ fontSize: 11, color: 'var(--muted)' }}>
                  ساختار آماده جهت توزیع و بهره‌برداری کاربران
                </p>
              </div>
            </div>
            <span className="chip chip--accent mono">
              <Share2 style={{ width: 11, height: 11 }} />
              READY TO BROADCAST
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="ntable">
              <thead>
                <tr>
                  <th style={{ width: 44 }}>#</th>
                  <th>نام نهایی</th>
                  <th>پروتکل</th>
                  <th>سرور</th>
                  <th style={{ textAlign: 'left' }}>عملیات</th>
                </tr>
              </thead>
              <tbody>
                {rebrandedNodes.slice(0, 60).map((node, idx) => (
                  <tr key={node.id}>
                    <td className="mono" style={{ color: 'var(--faint)' }}>
                      {idx + 1}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--accent)' }}>{node.name}</td>
                    <td>
                      <span className="chip chip--accent mono">{node.protocol.toUpperCase()}</span>
                    </td>
                    <td className="mono" dir="ltr" style={{ fontSize: 11.5, color: 'var(--muted)' }}>
                      {node.server}:{node.port}
                    </td>
                    <td style={{ textAlign: 'left' }}>
                      <button
                        type="button"
                        onClick={() => copy(node.link, `rebrand-${node.id}`)}
                        className="btn btn--ghost btn--sm mono"
                        style={{ fontSize: 10.5 }}
                      >
                        {copied === `rebrand-${node.id}` ? (
                          <Check style={{ width: 13, height: 13, color: 'var(--accent)' }} />
                        ) : (
                          <Copy style={{ width: 13, height: 13 }} />
                        )}
                        <span>کپی</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
};
