import React, { useState, useRef, useMemo, useEffect, useCallback } from 'react';
import {
  Copy,
  Check,
  Download,
  QrCode,
  FileCode2,
  Trash2,
  ArrowLeftRight,
  Search,
  ShieldCheck,
  Lock,
  KeyRound,
  CheckCircle2,
  Info,
  Activity,
  Cpu,
  Terminal,
  RefreshCw,
  Layers,
  Sun,
  Moon,
  Wrench,
  ChevronDown,
  X,
  Zap,
  Upload,
  Sparkles,
  HelpCircle,
  FolderArchive,
  Plus,
  type LucideIcon,
} from 'lucide-react';
import {
  convertAnyConfigInput,
  getSampleNPVTConfig,
  getSampleNPVSV5Config,
  buildNPVTContainerFromLinks,
  buildNPVSV5ContainerFromLinks,
  preloadGen2TablesBrowser,
  bytesToBase64,
  textToBytes,
  ConvertedNode,
  ConversionResult,
  TlsFixMode,
} from './utils/npvConverter';
import { NodeModal } from './components/NodeModal';
import { NetworkPingTester, measureHttpPing } from './components/NetworkPingTester';
import { XrayLogDiagnostic } from './components/XrayLogDiagnostic';
import { BootOverlay, ToastProvider, useToast, BrandLogo, ThemeToggle, LatencyChip, CopyButton } from './components/ui';
import { StealthRebrandStudio } from './components/StealthRebrandStudio';
import { VaultGate } from './components/VaultGate';
import { Stage, StageNav } from './components/StageFlow';
import { WelcomeModal, GUIDE_STORAGE_KEY } from './components/WelcomeGuide';
import {
  ConfigLibrary,
  SavedConfigBatch,
  loadSavedBatches,
  saveBatchesToStorage,
} from './components/ConfigLibrary';
import { InteractiveTour } from './components/InteractiveTour';
import { isSessionUnlocked, setSessionUnlocked } from './utils/vaultCrypto';
import {
  DEFAULT_ALIAS,
  applyDocumentIdentity,
  loadAliasProfile,
  saveAliasProfile,
  type AliasProfile,
} from './utils/aliasProfile';

/* ------------------------------------------------------------------ */
/*  Protocol palette                                                   */
/* ------------------------------------------------------------------ */

const PROTO_CHIP: Record<string, string> = {
  vless: 'chip chip--accent',
  vmess: 'chip chip--blue',
  trojan: 'chip chip--violet',
  ss: 'chip chip--warn',
  socks: 'chip',
};

const sec = (v: string) => {
  const s = String(v || '').toUpperCase();
  if (s === 'REALITY') return 'chip chip--warn';
  if (s === 'TLS') return 'chip chip--accent';
  return 'chip';
};

type OutputTab = 'links' | 'base64' | 'xray' | 'singbox' | 'clash' | 'raw';
type AppMode = 'decode' | 'forge' | 'vault';
type BuilderTargetVersion = 'npvs5' | 'npvt1';

const OUTPUT_TABS: { id: OutputTab; label: string; icon: LucideIcon }[] = [
  { id: 'links', label: 'لینک‌های اتصال', icon: ArrowLeftRight },
  { id: 'base64', label: 'اشتراک Base64', icon: Layers },
  { id: 'xray', label: 'قالب Xray', icon: FileCode2 },
  { id: 'singbox', label: 'قالب Sing-box', icon: Cpu },
  { id: 'clash', label: 'قالب Clash Meta', icon: Terminal },
  { id: 'raw', label: 'محتوای خام', icon: FileCode2 },
];

const PAGES: { id: AppMode; label: string; icon: LucideIcon }[] = [
  { id: 'decode', label: 'رمزگشایی کانفیگ', icon: Lock },
  { id: 'forge', label: 'تولید فایل کانتینر', icon: ArrowLeftRight },
  { id: 'vault', label: 'استودیوی اختصاصی', icon: Sparkles },
];

/* ------------------------------------------------------------------ */
/*  Step rail — progressive disclosure of the decode flow               */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  App                                                                */
/* ------------------------------------------------------------------ */

function AppInner() {
  const { push } = useToast();
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      const saved = localStorage.getItem('npvt_theme');
      if (saved === 'light' || saved === 'dark') return saved;
    } catch {}
    return 'dark';
  });
  const isLight = theme === 'light';

  const [appMode, setAppMode] = useState<AppMode>(() => {
    try {
      const hash = window.location.hash.replace('#', '').replace('/', '').trim();
      if (hash === 'forge' || hash === 'vault' || hash === 'decode') return hash;
    } catch {}
    return 'decode';
  });

  useEffect(() => {
    try {
      localStorage.setItem('npvt_theme', theme);
      document.documentElement.classList.toggle('dark', theme === 'dark');
      document.documentElement.classList.toggle('light', theme === 'light');
    } catch {}
  }, [theme]);

  /* hash routing — deep links + browser back/forward */
  useEffect(() => {
    const applyHash = () => {
      const hash = window.location.hash.replace('#', '').replace('/', '').trim();
      if (hash === 'forge' || hash === 'vault' || hash === 'decode') {
        setAppMode(hash);
      }
    };
    window.addEventListener('hashchange', applyHash);
    return () => window.removeEventListener('hashchange', applyHash);
  }, []);

  useEffect(() => {
    try {
      if (window.location.hash.replace('#', '').replace('/', '') !== appMode) {
        window.history.replaceState(null, '', `#/${appMode}`);
      }
    } catch {}
  }, [appMode]);

  const [vaultUnlocked, setVaultUnlocked] = useState(() => isSessionUnlocked());
  const [alias, setAlias] = useState<AliasProfile>(() => loadAliasProfile());
  const [inputText, setInputText] = useState('');
  const [sourceName, setSourceName] = useState('Direct Input');
  const [rawBytes, setRawBytes] = useState<Uint8Array | undefined>(undefined);
  const [passphrase, setPassphrase] = useState('');
  const [debouncedPassphrase, setDebouncedPassphrase] = useState('');

  useEffect(() => {
    const t = setTimeout(() => setDebouncedPassphrase(passphrase), 500);
    return () => clearTimeout(t);
  }, [passphrase]);
  const [tlsFixMode, setTlsFixMode] = useState<TlsFixMode>('auto-smart');
  const [gen2Ready, setGen2Ready] = useState(false);

  const [activeTab, setActiveTab] = useState<OutputTab>('links');
  const [searchQuery, setSearchQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  /* ---- identity (alias) ------------------------------------------ */
  const aliasActive = vaultUnlocked && alias.enabled && alias.name.trim().length > 0;
  const brandName = aliasActive ? alias.name : 'NPV//FORGE';
  const brandKicker = aliasActive ? alias.kicker : 'NPV TUNNEL UTILITIES';
  const brandCaption = aliasActive ? alias.caption : '';

  useEffect(() => {
    applyDocumentIdentity(alias, aliasActive);
  }, [alias, aliasActive]);

  const handleAliasChange = useCallback((next: AliasProfile) => {
    setAlias(next);
    saveAliasProfile(next);
  }, []);

  const handleVaultUnlock = useCallback(() => {
    setSessionUnlocked(true);
    setVaultUnlocked(true);
    push('ok', 'احراز هویت با موفقیت انجام شد؛ دسترسی به استودیوی اختصاصی فعال گردید.');
  }, [push]);

  const handleVaultLock = useCallback(() => {
    setSessionUnlocked(false);
    setVaultUnlocked(false);
    push('info', 'نشست استودیوی اختصاصی با موفقیت قفل گردید.');
  }, [push]);

  const [nodePings, setNodePings] = useState<Record<string, { status: 'testing' | 'ok' | 'timeout'; ms: number | null }>>({});
  const [isPingingNodes, setIsPingingNodes] = useState(false);

  const [modalNode, setModalNode] = useState<ConvertedNode | null>(null);
  const [modalMode, setModalMode] = useState<'qr' | 'details' | null>(null);

  const [reverseInput, setReverseInput] = useState('');
  const [builderVersion, setBuilderVersion] = useState<BuilderTargetVersion>('npvs5');
  const [builderPassphrase, setBuilderPassphrase] = useState('');
  const [builderMessage, setBuilderMessage] = useState('');
  const [reverseOutput, setReverseOutput] = useState('');
  const [reverseBinaryBytes, setReverseBinaryBytes] = useState<Uint8Array | null>(null);
  const [reverseError, setReverseError] = useState('');

  useEffect(() => {
    setReverseOutput('');
    setReverseBinaryBytes(null);
    setReverseError('');
  }, [builderVersion, reverseInput]);

  const [isBoot, setIsBoot] = useState(true);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [dragOver, setDragOver] = useState(false);

  /* Scroll-driven .reveal via IntersectionObserver (survives dynamic mounts) */
  useEffect(() => {
    if (typeof IntersectionObserver === 'undefined') {
      document.querySelectorAll<HTMLElement>('.reveal').forEach((el) => el.classList.add('in-view'));
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add('in-view');
            observed.delete(e.target as HTMLElement);
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.06, rootMargin: '0px 0px -6% 0px' }
    );
    const observed = new WeakSet<HTMLElement>();
    const sync = () => {
      document.querySelectorAll<HTMLElement>('.reveal:not(.in-view)').forEach((el) => {
        if (!observed.has(el)) {
          observed.add(el);
          io.observe(el);
        }
      });
    };
    sync();
    const mo = new MutationObserver(sync);
    mo.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['class'],
    });
    return () => {
      io.disconnect();
      mo.disconnect();
    };
  }, []);

  /* Boot: hide after the gen2 tables load (or fail) with a small delay */
  useEffect(() => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      window.setTimeout(() => setIsBoot(false), 420);
    };
    prefetchTable(finish);
    window.setTimeout(finish, 1700);
    return () => {};
  }, []);

  const prefetchTable = useCallback(async (then: () => void) => {
    try {
      const ok = await preloadGen2TablesBrowser();
      setGen2Ready(ok);
    } catch {}
    then();
  }, []);

  /* Welcome guide: auto-open on first visit, reopenable from the topbar */
  const [guideOpen, setGuideOpen] = useState(false);
  const [tourOpen, setTourOpen] = useState(false);
  const [savedBatches, setSavedBatches] = useState<SavedConfigBatch[]>(() => loadSavedBatches());

  useEffect(() => {
    saveBatchesToStorage(savedBatches);
  }, [savedBatches]);

  useEffect(() => {
    if (isBoot) return;
    try {
      if (localStorage.getItem(GUIDE_STORAGE_KEY) === '1') return;
    } catch {
      return;
    }
    const t = window.setTimeout(() => setGuideOpen(true), 700);
    return () => window.clearTimeout(t);
  }, [isBoot]);

  const closeGuide = useCallback(() => {
    setGuideOpen(false);
    try {
      localStorage.setItem(GUIDE_STORAGE_KEY, '1');
    } catch {}
  }, []);

  /* ---- conversion ---- */
  const liveConversion = useMemo(() => {
    if (!inputText.trim() && !rawBytes) return null;
    return convertAnyConfigInput(inputText, sourceName, rawBytes, debouncedPassphrase, tlsFixMode);
  }, [inputText, sourceName, rawBytes, debouncedPassphrase, tlsFixMode, gen2Ready]);

  const [pinnedConversion, setPinnedConversion] = useState<ConversionResult | null>(null);
  const conversion = liveConversion ?? pinnedConversion;
  const isPinnedResult = !liveConversion && Boolean(pinnedConversion);

  const protocolsInPlay = useMemo(() => {
    if (!conversion) return [] as string[];
    return Array.from(new Set(conversion.nodes.map((n) => n.protocol)));
  }, [conversion]);

  const filteredNodes = useMemo(() => {
    if (!conversion) return [];
    return conversion.nodes.filter((n) => {
      const matchesProto = protocolFilter === 'ALL' || n.protocol === protocolFilter;
      const q = searchQuery.trim().toLowerCase();
      const matchesSearch =
        !q ||
        n.name.toLowerCase().includes(q) ||
        n.server.toLowerCase().includes(q) ||
        n.protocol.toLowerCase().includes(q) ||
        n.network.toLowerCase().includes(q) ||
        n.sni.toLowerCase().includes(q) ||
        n.hostHeader.toLowerCase().includes(q);
      return matchesProto && matchesSearch;
    });
  }, [conversion, protocolFilter, searchQuery]);

  useEffect(() => {
    if (protocolFilter !== 'ALL' && !protocolsInPlay.includes(protocolFilter)) {
      setProtocolFilter('ALL');
    }
  }, [protocolsInPlay, protocolFilter]);

  const formattedOutputText = useMemo(() => {
    if (!conversion) return '';
    const nodes = filteredNodes;
    if (activeTab === 'links') {
      return nodes.map((n) => n.link).join('\n');
    }
    if (activeTab === 'base64') {
      const joined = nodes.map((n) => n.link).join('\n');
      if (!joined) return '';
      try {
        return bytesToBase64(textToBytes(joined));
      } catch {
        return '';
      }
    }
    if (activeTab === 'xray') {
      if (nodes.length === 0) return '';
      if (nodes.length === 1) return nodes[0].xrayJson;
      try {
        const configs = nodes.map((n) => JSON.parse(n.xrayJson));
        const merged = configs[0];
        const proxyOutbounds = configs.map((c, i) => ({
          ...(c.outbounds?.[0] || {}),
          tag: `proxy-${i + 1}`,
        }));
        merged.outbounds = [
          ...proxyOutbounds,
          { tag: 'direct', protocol: 'freedom', settings: {} },
          { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'http' } } },
        ];
        return JSON.stringify(merged, null, 2);
      } catch {
        return nodes.map((n) => n.xrayJson).join('\n\n');
      }
    }
    if (activeTab === 'singbox') {
      if (nodes.length === 0) return '';
      if (nodes.length === 1) return nodes[0].singBoxJson;
      try {
        const configs = nodes.map((n) => JSON.parse(n.singBoxJson));
        const merged = configs[0];
        const proxyOutbounds = configs.map((c, i) => ({
          ...(c.outbounds?.[0] || {}),
          tag: `proxy-${i + 1}`,
        }));
        merged.outbounds = [
          ...proxyOutbounds,
          { type: 'direct', tag: 'direct' },
          { type: 'block', tag: 'block' },
        ];
        return JSON.stringify(merged, null, 2);
      } catch {
        return nodes.map((n) => n.singBoxJson).join('\n\n');
      }
    }
    if (activeTab === 'clash') {
      if (nodes.length === 0) return '';
      const proxyBlocks = nodes.map((n) => n.clashYaml.split('\n').slice(1).join('\n'));
      return `proxies:\n${proxyBlocks.join('\n')}`;
    }
    if (activeTab === 'raw') {
      if (conversion.decryptedChunks.length > 0) {
        return conversion.decryptedChunks
          .map((c) => `// --- Chunk ${c.index} ---\n${c.text}`)
          .join('\n\n');
      }
      return '';
    }
    return '';
  }, [conversion, filteredNodes, activeTab]);

  /* ---- helpers ---- */
  const copy = useCallback(
    async (text: string, key: string) => {
      if (!text) return;
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
        setCopiedKey(key);
        window.setTimeout(() => setCopiedKey((c) => (c === key ? null : c)), 1800);
      } catch {
        push('error', 'خطا در دسترسی به حافظه موقت سیستم (Clipboard).');
      }
    },
    [push]
  );

  const download = useCallback(
    (content: string | Uint8Array, filename: string, mime = 'text/plain;charset=utf-8') => {
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
        URL.revokeObjectURL(url);
        a.remove();
      }, 180);
      push('ok', `فایل «${filename}» با موفقیت ذخیره گردید.`);
    },
    [push]
  );

  const handleFileUpload = useCallback(
    (file: File) => {
      if (file.size > 30 * 1024 * 1024) {
        push('error', 'حجم فایل انتخابی بیش از سقف مجاز (۳۰ مگابایت) است.');
        return;
      }
      setSourceName(file.name);
      const reader = new FileReader();
      reader.onload = () => {
        const buf = reader.result as ArrayBuffer;
        const bytes = new Uint8Array(buf);
        setRawBytes(bytes);
        if (
          bytes.length >= 4 &&
          bytes[0] === 0x4e &&
          bytes[1] === 0x50 &&
          bytes[2] === 0x56 &&
          (bytes[3] === 0x53 || bytes[3] === 0x54)
        ) {
          let bin = '';
          for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
          setInputText(btoa(bin));
        } else {
          setInputText(new TextDecoder('utf-8', { fatal: false }).decode(bytes));
        }
        push('ok', `فایل «${file.name}» با موفقیت بارگذاری و پردازش گردید.`);
      };
      reader.onerror = () => push('error', 'خطا در بازخوانی محتوای فایل انتخابی.');
      reader.readAsArrayBuffer(file);
    },
    [push]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files?.[0];
      if (file) handleFileUpload(file);
    },
    [handleFileUpload]
  );

  const clearInput = () => {
    if (conversion) setPinnedConversion(conversion);
    setInputText('');
    setRawBytes(undefined);
    setPassphrase('');
    setSourceName('Direct Input');
    push('info', conversion ? 'کادر ورودی بازنشانی شد؛ نتایج آخرین استخراج در حافظه حفظ گردید.' : 'کادر ورودی بازنشانی شد.');
  };

  const clearAll = () => {
    setPinnedConversion(null);
    setInputText('');
    setRawBytes(undefined);
    setPassphrase('');
    setSourceName('Direct Input');
    setNodePings({});
    setProtocolFilter('ALL');
    setSearchQuery('');
    setModalNode(null);
    setModalMode(null);
    setActiveTab('links');
    push('info', 'کلیه ورودی‌ها، نتایج و فیلترها بازنشانی شدند.');
  };

  const handleLoadSampleV4 = () => {
    const sample = getSampleNPVTConfig();
    setSourceName('sample_config_v4.npvt');
    setRawBytes(undefined);
    setPassphrase('');
    setInputText(sample);
    setAppMode('decode');
    push('info', 'کانفیگ نمونه نسل ۴ (NPVT1) بارگذاری گردید.');
  };

  const handleLoadSampleV5 = useCallback(async () => {
    let ready = gen2Ready;
    if (!ready) {
      ready = await preloadGen2TablesBrowser();
      setGen2Ready(ready);
    }
    const sampleV5 = getSampleNPVSV5Config();
    if (sampleV5) {
      setSourceName('sample_gen5_fastly.npvs');
      setRawBytes(sampleV5.bytes);
      setPassphrase('');
      setInputText(sampleV5.base64);
      setAppMode('decode');
      push('ok', 'کانفیگ نمونه نسل ۵ (White-Box Fastly) بارگذاری گردید.');
    } else {
      push('error', 'خطا در بارگذاری نمونه نسل ۵؛ جداول رمزگشایی در دسترس نمی‌باشند.');
    }
  }, [gen2Ready, push]);

  const handlePingNode = useCallback(async (node: ConvertedNode): Promise<boolean> => {
    setNodePings((prev) => ({ ...prev, [node.id]: { status: 'testing', ms: null } }));
    const targetHost = node.isFastly
      ? 'www.fastly.com/favicon.ico'
      : node.hostHeader || node.sni || node.server;
    const probeUrl = targetHost.startsWith('http') ? targetHost : `https://${targetHost}`;
    const ms = await measureHttpPing(probeUrl, 3800);
    setNodePings((prev) => ({
      ...prev,
      [node.id]: { status: ms !== null ? 'ok' : 'timeout', ms },
    }));
    return ms !== null;
  }, []);

  const handlePingAllNodes = async () => {
    if (!filteredNodes.length) return;
    setIsPingingNodes(true);
    const ids = filteredNodes.map((n) => n.id);
    const results = await Promise.all(filteredNodes.map((n) => handlePingNode(n)));
    setIsPingingNodes(false);
    const fast = results.filter(Boolean).length;
    push('info', `فرآیند سنجش پینگ تکمیل شد (${fast.toLocaleString('fa-IR')} سرور پاسخگو از مجموع ${ids.length.toLocaleString('fa-IR')}).`);
  };

  const handleDownloadOutput = () => {
    if (!formattedOutputText) return;
    const extMap: Record<OutputTab, { ext: string; mime: string }> = {
      links: { ext: 'txt', mime: 'text/plain;charset=utf-8' },
      base64: { ext: 'txt', mime: 'text/plain;charset=utf-8' },
      xray: { ext: 'json', mime: 'application/json;charset=utf-8' },
      singbox: { ext: 'json', mime: 'application/json;charset=utf-8' },
      clash: { ext: 'yaml', mime: 'text/yaml;charset=utf-8' },
      raw: { ext: 'txt', mime: 'text/plain;charset=utf-8' },
    };
    const meta = extMap[activeTab];
    download(formattedOutputText, `npv-forge-${activeTab}-${Date.now()}.${meta.ext}`, meta.mime);
  };

  const handleBuildReverseNPV = async () => {
    setReverseError('');
    setReverseOutput('');
    setReverseBinaryBytes(null);
    const lines = reverseInput
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => /^(vless|vmess|trojan|ss|socks):\/\//i.test(l));
    if (lines.length === 0) {
      setReverseError('لطفاً حداقل یک لینک اتصال معتبر با پروتکل‌های vless، vmess، trojan یا shadowsocks وارد نمایید.');
      return;
    }
    try {
      if (builderVersion === 'npvt1') {
        const container = buildNPVTContainerFromLinks(lines);
        setReverseOutput(container);
        push('ok', `کانتینر NPVT1 با موفقیت تولید گردید (${lines.length.toLocaleString('fa-IR')} نود).`);
      } else {
        if (!gen2Ready) {
          const ready = await preloadGen2TablesBrowser();
          setGen2Ready(ready);
        }
        const built = buildNPVSV5ContainerFromLinks(lines, {
          passphrase: builderPassphrase.trim() || undefined,
          displayMessage: builderMessage.trim() || undefined,
        });
        if (!built) {
          setReverseError('خطا در تولید کانتینر نسل ۵؛ جداول رمزنگاری White-Box در دسترس نمی‌باشند.');
          return;
        }
        setReverseBinaryBytes(built.bytes);
        setReverseOutput(built.base64);
        push('ok', `کانتینر امن NPVS v5 با موفقیت رمزنگاری و تولید شد (${lines.length.toLocaleString('fa-IR')} نود).`);
      }
    } catch (e: any) {
      const msg = e?.message || 'خطا در ساخت کانتینر NPV';
      setReverseError(msg);
      push('error', msg);
    }
  };

  /* ---- library actions ---- */
  const handleSaveCurrentToLibrary = useCallback(() => {
    if (!conversion || conversion.nodes.length === 0) return;
    const newBatch: SavedConfigBatch = {
      id: `batch-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      title: sourceName && sourceName !== 'Direct Input' ? sourceName : `کانفیگ ${savedBatches.length + 1}`,
      sourceName,
      detectedFormat: conversion.detectedFormat || 'V2Ray',
      timestamp: Date.now(),
      nodes: [...conversion.nodes],
    };
    setSavedBatches((prev) => [newBatch, ...prev]);
    push('ok', `کانفیگ با ${conversion.nodes.length} سرور در مجموعه ذخیره شد.`);
  }, [conversion, sourceName, savedBatches.length, push]);

  const handleSaveAndNext = useCallback(() => {
    if (!conversion || conversion.nodes.length === 0) return;
    const count = conversion.nodes.length;
    const newBatch: SavedConfigBatch = {
      id: `batch-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      title: sourceName && sourceName !== 'Direct Input' ? sourceName : `کانفیگ ${savedBatches.length + 1}`,
      sourceName,
      detectedFormat: conversion.detectedFormat || 'V2Ray',
      timestamp: Date.now(),
      nodes: [...conversion.nodes],
    };
    setSavedBatches((prev) => [newBatch, ...prev]);
    setInputText('');
    setRawBytes(undefined);
    setPassphrase('');
    setSourceName('Direct Input');
    push('ok', `کانفیگ با موفقیت در مجموعه ذخیره شد (${count.toLocaleString('fa-IR')} سرور). کادر ورودی جهت دریافت کانفیگ بعدی آماده است.`);
    scrollTo('decode-studio');
  }, [conversion, sourceName, savedBatches.length, push]);

  const handleRemoveBatch = useCallback((id: string) => {
    setSavedBatches((prev) => prev.filter((b) => b.id !== id));
    push('info', 'بسته انتخابی از مجموعه حذف گردید.');
  }, [push]);

  const handleClearAllLibrary = useCallback(() => {
    if (!window.confirm('آیا از پاک‌سازی کل مجموعه کانفیگ‌های ذخیره‌شده اطمینان دارید؟')) return;
    setSavedBatches([]);
    push('info', 'کلیه بسته‌های ذخیره‌شده از مجموعه پاک‌سازی شدند.');
  }, [push]);

  const handleLoadBatchIntoActive = useCallback((batch: SavedConfigBatch) => {
    setPinnedConversion({
      detectedFormat: batch.detectedFormat,
      nodes: batch.nodes,
      decryptedChunks: [],
      errors: [],
      sshProfiles: [],
      notes: [],
      npvsInspection: null,
    });
    setInputText('');
    setRawBytes(undefined);
    setSourceName(batch.title);
    push('info', `بسته «${batch.title}» در پیش‌نمایش خروجی فعال شد.`);
    scrollTo('output-panel');
  }, [push]);

  const scrollTo = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });

  /* ---------------------------------------------------------------- */
  /*  Render                                                          */
  /* ---------------------------------------------------------------- */

    return (
      <div className="shell flex min-h-screen flex-col">
        <BootOverlay done={!isBoot} />

      {/* Header — brand, three destinations, one help button */}
      <header className="topbar">
        <div className="wrap topbar__row">
          <a href="#top" className="topbar__brand" onClick={(e) => { e.preventDefault(); setAppMode('decode'); }}>
            <BrandLogo
              size={34}
              name={aliasActive ? brandName : 'NPV//FORGE'}
              custom={aliasActive}
            />
          </a>

          <nav className="topbar__nav topbar__nav--desktop" aria-label="بخش‌های برنامه">
            {PAGES.map((p) => {
              const Icon = p.icon;
              const isActive = appMode === p.id;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setAppMode(p.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`topnav__item ${isActive ? 'is-active' : ''}`}
                >
                  <Icon style={{ width: 14, height: 14 }} />
                  <span>{p.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="topbar__end">
            <button
              type="button"
              onClick={() => setTourOpen(true)}
              className="btn btn--ghost btn--sm"
              title="راهنمای تعاملی گام‌به‌گام"
            >
              <HelpCircle style={{ width: 14, height: 14 }} />
              <span className="hidden sm:inline">راهنما</span>
            </button>
            <ThemeToggle />
          </div>

          {/* mobile destination picker */}
          <nav className="topbar__sub" aria-label="بخش‌های برنامه">
            {PAGES.map((p) => {
              const Icon = p.icon;
              const isActive = appMode === p.id;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setAppMode(p.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`topnav__item ${isActive ? 'is-active' : ''}`}
                  style={{ padding: '6px 10px', fontSize: 12.5 }}
                >
                  <Icon style={{ width: 13, height: 13 }} />
                  <span>{p.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Page intro */}
      <div className="wrap">
        {appMode === 'decode' ? (
          <div className="pagehead reveal">
            <h1 className="pagehead__title">
              رمزگشایی کانتینرهای NPV Tunnel و تبدیل به سرورهای <span style={{ color: 'var(--accent)' }}>V2Ray</span>
            </h1>
            <p className="pagehead__note">
              فایل‌های رمزنگاری‌شده <code>.npvs</code>، <code>.npvt</code> یا لینک‌های اشتراک را وارد نمایید. کلیه مراحل رمزگشایی،
              تولید خروجی‌های Xray، Sing-box و Clash Meta به صورت ۱۰۰٪ آفلاین و بدون انتقال داده به سرور انجام می‌پذیرد.
            </p>
          </div>
        ) : appMode === 'forge' ? (
          <div className="pagehead reveal">
            <h1 className="pagehead__title">تولید و رمزنگاری کانتینرهای اختصاصی NPV Tunnel</h1>
            <p className="pagehead__note">
              فرآیند معکوس: لینک‌های اتصال V2Ray را وارد نموده و کانتینر رمزنگاری‌شده استاندارد <code>.npvs</code> (نسل ۵)
              یا <code>.npvt</code> (نسل ۴) را جهت استفاده در نرم‌افزار NapsternetV دریافت نمایید.
            </p>
          </div>
        ) : (
          <div className="pagehead reveal">
            <h1 className="pagehead__title">استودیوی اختصاصی بازنویسی و انتشار</h1>
            <p className="pagehead__note">
              مدیریت یکپارچه عناوین سرورها، پاک‌سازی تبلیغات، تنظیم کپشن انتشار و بسته‌بندی مجدد کانتینرها با هویت برند اختصاصی شما.
            </p>
          </div>
        )}
      </div>

      {appMode === 'decode' && (
        <div className="wrap" style={{ marginTop: 18 }}>
          <StageNav
            steps={[
              { id: 'decode-studio', label: 'ورودی کانفیگ', state: inputText || rawBytes ? 'done' : 'active' },
              { id: 'output-panel', label: 'قالب‌های خروجی', state: formattedOutputText ? 'done' : conversion ? 'active' : 'idle' },
              { id: 'nodes', label: 'فهرست سرورها', state: filteredNodes.length > 0 ? 'done' : 'idle' },
              { id: 'library-space', label: `مجموعه ذخیره‌شده (${savedBatches.length.toLocaleString('fa-IR')})`, state: savedBatches.length > 0 ? 'done' : 'idle' },
            ]}
            onJump={scrollTo}
          />
        </div>
      )}

      <main className="wrap flex-1" style={{ display: 'grid', gap: 24 }}>
        {appMode === 'decode' ? (
          <React.Fragment>
            {/* Stage 1: Input */}
            <Stage
              id="decode-studio"
              n={1}
              title="ورودی"
              hint="فایل، متن یا لینک"
              state={inputText || rawBytes ? 'done' : 'active'}
            >
              <div className="panel">
                <div className="panel__body" style={{ display: 'grid', gap: 12 }}>
                  <div
                    onDragOver={(e) => {
                      e.preventDefault();
                      setDragOver(true);
                    }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    className={`dropzone ${dragOver ? 'is-over' : ''}`}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
                    }}
                  >
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".npvt,.npv4,.npvs,.nm,.txt,.json"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) handleFileUpload(f);
                      }}
                    />
                    <div className="dropzone__icon">
                      <Upload style={{ width: 18, height: 18 }} />
                    </div>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <p style={{ fontSize: 13, fontWeight: 650, margin: 0 }}>فایل کانفیگ را به این کادر بکشید یا جهت انتخاب کلیک فرمایید</p>
                      <p
                        style={{
                          fontSize: 11.5,
                          color: 'var(--faint)',
                          marginTop: 2,
                          marginBottom: 0,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        <span dir="ltr">{sourceName}</span>
                        {rawBytes ? ` · ${(rawBytes.length / 1024).toFixed(1)} KB` : ''}
                        <span> — یا جهت انتخاب فایل کلیک فرمایید</span>
                      </p>
                    </div>
                    {(inputText || conversion) && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          clearAll();
                        }}
                        className="btn btn--icon btn--ghost"
                        title="بازنشانی کامل ورودی‌ها"
                        aria-label="بازنشانی کامل"
                      >
                        <Trash2 style={{ width: 15, height: 15 }} />
                      </button>
                    )}
                  </div>

                  <textarea
                    value={inputText}
                    onChange={(e) => {
                      setInputText(e.target.value);
                      setRawBytes(undefined);
                    }}
                    dir="ltr"
                    placeholder="لینک‌های اتصال یا متن محتوای کانفیگ رمزنگاری‌شده را در این بخش الصاق فرمایید..."
                    className="field field--code"
                    style={{ minHeight: 140 }}
                  />

                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: '8px 12px',
                      borderRadius: 10,
                      border: '1px solid',
                      borderColor: conversion?.needsPassphrase ? 'color-mix(in srgb, var(--warn) 50%, transparent)' : 'var(--line)',
                      background: conversion?.needsPassphrase ? 'var(--warn-soft)' : 'transparent',
                    }}
                  >
                    <KeyRound
                      style={{
                        width: 14,
                        height: 14,
                        color: conversion?.needsPassphrase ? 'var(--warn)' : 'var(--faint)',
                        flex: 'none',
                      }}
                    />
                    <input
                      type="password"
                      dir="ltr"
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                      placeholder="رمز عبور کانتینر (اختیاری — ویژه فایل‌های قفل‌شده)"
                      style={{
                        flex: 1,
                        background: 'transparent',
                        border: 0,
                        outline: 'none',
                        color: 'var(--text)',
                        fontFamily: 'inherit',
                        fontSize: 12.5,
                        minWidth: 0,
                      }}
                    />
                  </div>

                  {conversion && (
                    <div style={{ display: 'grid', gap: 8 }}>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: 10,
                          fontSize: 12.5,
                          color: 'var(--muted)',
                        }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0 }}>
                          {conversion.nodes.length > 0 ? (
                            <CheckCircle2 style={{ width: 15, height: 15, color: 'var(--ok)', flex: 'none' }} />
                          ) : (
                            <ShieldCheck style={{ width: 15, height: 15, color: 'var(--warn)', flex: 'none' }} />
                          )}
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {conversion.detectedFormat}
                          </span>
                        </span>
                        <span style={{ fontWeight: 700, color: 'var(--text)', flex: 'none' }}>
                          {conversion.nodes.length.toLocaleString('fa-IR')} سرور
                        </span>
                      </div>

                      {conversion.errors.length > 0 && conversion.nodes.length === 0 && (
                        <div
                          role="alert"
                          style={{
                            padding: '11px 13px',
                            borderRadius: 10,
                            border: '1px solid color-mix(in srgb, var(--danger) 26%, transparent)',
                            background: 'var(--danger-soft)',
                            fontSize: 12.5,
                            color: 'var(--text)',
                            lineHeight: 1.9,
                          }}
                        >
                          {conversion.errors[0]}
                        </div>
                      )}

                      {conversion.recoveredKeys && Object.keys(conversion.recoveredKeys).length > 0 && (
                        <details className="vdetails">
                          <summary>
                            <span>کلیدهای بازیابی‌شده</span>
                            <ChevronDown style={{ width: 14, height: 14 }} />
                          </summary>
                          <div style={{ display: 'grid', gap: 5, marginTop: 10 }}>
                            {Object.entries(conversion.recoveredKeys).map(([k, v]) => (
                              <div
                                key={k}
                                className="mono"
                                style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: 11 }}
                                dir="ltr"
                              >
                                <span style={{ color: 'var(--faint)' }}>{k}</span>
                                <span style={{ color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</span>
                              </div>
                            ))}
                          </div>
                          {conversion.creatorMessage && (
                            <p style={{ marginTop: 9, paddingTop: 9, borderTop: '1px solid var(--line)', fontSize: 11.5, color: 'var(--muted)' }}>
                              <b style={{ color: 'var(--text)' }}>پیام داخل فایل:</b> {conversion.creatorMessage}
                            </p>
                          )}
                        </details>
                      )}
                    </div>
                  )}

                  {!inputText && !rawBytes && (
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      <button type="button" onClick={handleLoadSampleV5} className="btn btn--soft btn--sm">
                        <Cpu style={{ width: 13, height: 13 }} />
                        <span>بارگذاری نمونه نسل ۵ (NPVS v5)</span>
                      </button>
                      <button type="button" onClick={handleLoadSampleV4} className="btn btn--ghost btn--sm">
                        <span>بارگذاری نمونه نسل ۴ (NPVT1)</span>
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </Stage>

            {/* Stage 2: Output */}
            <Stage
              id="output-panel"
              n={2}
              title="خروجی"
              hint="یک قالب انتخاب کن و بردار"
              state={formattedOutputText ? 'done' : conversion ? 'active' : 'idle'}
            >
              <div className="panel">
                <div className="panel__body" style={{ display: 'grid', gap: 12 }}>
                  <div className="seg hide-scroll w-full overflow-x-auto">
                    {OUTPUT_TABS.map((t) => {
                      const Icon = t.icon;
                      return (
                        <button
                          key={t.id}
                          type="button"
                          onClick={() => setActiveTab(t.id)}
                          aria-pressed={activeTab === t.id}
                          className={`seg__item ${activeTab === t.id ? 'is-active' : ''}`}
                        >
                          <Icon style={{ width: 13, height: 13 }} />
                          <span>{t.label}</span>
                        </button>
                      );
                    })}
                  </div>

                  {!conversion ? (
                    <div className="emptystate">
                      <div className="emptystate__icon">
                        <FileCode2 style={{ width: 19, height: 19 }} />
                      </div>
                      <h3 style={{ fontSize: 14.5, fontWeight: 700, margin: 0 }}>
                        در حال حاضر خروجی جهت نمایش وجود ندارد
                      </h3>
                      <p style={{ fontSize: 12.5, color: 'var(--muted)', lineHeight: 1.9, maxWidth: '48ch', margin: 0 }}>
                        جهت تولید خروجی، لطفاً فایل کانفیگ یا لینک‌های اتصال موردنظر را در مرحله اول وارد نمایید.
                      </p>
                    </div>
                  ) : (
                    <>
                      <div className="codepane">
                        <div className="codepane__chrome">
                          <span style={{ fontSize: 11.5, color: 'var(--muted)' }}>
                            {filteredNodes.length.toLocaleString('fa-IR')} سرور
                          </span>
                          {isPinnedResult && (
                            <span className="chip chip--blue" style={{ fontSize: 10.5 }}>
                              نتیجه قبلی
                            </span>
                          )}
                          <div style={{ display: 'flex', gap: 6, marginInlineStart: 'auto' }}>
                            <CopyButton
                              text={formattedOutputText}
                              copyKey="main-output"
                              copied={copiedKey}
                              onCopy={copy}
                              iconOnly
                              label="کپی"
                            />
                            <button
                              type="button"
                              disabled={!formattedOutputText}
                              onClick={handleDownloadOutput}
                              className="btn btn--icon btn--ghost"
                              title="دانلود خروجی"
                            >
                              <Download style={{ width: 15, height: 15 }} />
                            </button>
                          </div>
                        </div>
                        <textarea
                          readOnly
                          value={formattedOutputText}
                          dir="ltr"
                          placeholder="// خروجی اینجا ساخته می‌شود"
                          className="codepane__pre"
                          style={{ minHeight: 200, resize: 'none' }}
                        />
                      </div>

                      <div
                        style={{
                          display: 'flex',
                          flexWrap: 'wrap',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: 10,
                        }}
                      >
                        <button
                          type="button"
                          onClick={() => setTlsFixMode(tlsFixMode === 'fastly-sni' ? 'auto-smart' : 'fastly-sni')}
                          className="btn btn--ghost btn--sm"
                          title="تعمیر خودکار خطای گواهی Fastly"
                        >
                          <ShieldCheck
                            style={{
                              width: 13,
                              height: 13,
                              color: tlsFixMode === 'fastly-sni' ? 'var(--accent)' : 'var(--faint)',
                            }}
                          />
                          <span>
                            {tlsFixMode === 'fastly-sni' ? 'تعمیر TLS فعال است' : 'تعمیر خودکار TLS'}
                          </span>
                        </button>
                        <div className="flex items-center gap-2 flex-wrap">
                          <button
                            type="button"
                            onClick={handleSaveCurrentToLibrary}
                            className="btn btn--soft btn--sm"
                            title="افزودن این سرورها به مجموعه آرشیو"
                          >
                            <FolderArchive style={{ width: 14, height: 14 }} />
                            <span>افزودن به مجموعه</span>
                          </button>
                          <button
                            type="button"
                            onClick={handleSaveAndNext}
                            className="btn btn--soft btn--sm"
                            title="ذخیره در مجموعه و بازنشانی کادر جهت دریافت کانفیگ بعدی"
                          >
                            <Plus style={{ width: 14, height: 14 }} />
                            <span>ذخیره و دریافت کانفیگ بعدی</span>
                          </button>
                          <CopyButton
                            text={formattedOutputText}
                            copyKey="main-output"
                            copied={copiedKey}
                            onCopy={copy}
                            label="رونویسی کلیه خروجی‌ها"
                            doneLabel="خروجی‌ها رونویسی شدند"
                            variant="btn--primary"
                          />
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </Stage>

            {/* Stage 3: Nodes */}
            <Stage
              id="nodes"
              n={3}
              title="مرحله سوم: فهرست و مدیریت سرورها"
              hint={conversion ? `${conversion.nodes.length.toLocaleString('fa-IR')} سرور استخراج‌شده` : 'پس از رمزگشایی نودها نمایش داده می‌شوند'}
              state={filteredNodes.length > 0 ? 'done' : 'idle'}
            >
              {conversion && (conversion.nodes.length > 0 || conversion.sshProfiles.length > 0) ? (
                <section className="panel">
                  <div
                    style={{
                      padding: '12px 16px',
                      display: 'flex',
                      gap: 10,
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      borderBottom: '1px solid var(--line)',
                    }}
                  >
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                      <div className="seg" style={{ overflowX: 'auto' }}>
                        {['ALL', ...protocolsInPlay].map((p) => (
                          <button
                            key={p}
                            type="button"
                            onClick={() => setProtocolFilter(p)}
                            className={`seg__item ${protocolFilter === p ? 'is-active' : ''}`}
                            style={{ fontSize: 11.5 }}
                          >
                            {p === 'ALL' ? 'همه' : p.toUpperCase()}
                          </button>
                        ))}
                      </div>
                      <button
                        type="button"
                        onClick={handlePingAllNodes}
                        disabled={isPingingNodes}
                        className="btn btn--ghost btn--sm"
                      >
                        <RefreshCw style={{ width: 13, height: 13 }} className={isPingingNodes ? 'spin' : ''} />
                        <span>سنجش پینگ سرورها</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleSaveCurrentToLibrary}
                        className="btn btn--soft btn--sm"
                        title="ذخیره این سرورها در مجموعه"
                      >
                        <FolderArchive style={{ width: 13, height: 13 }} />
                        <span>افزودن به مجموعه</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleSaveAndNext}
                        className="btn btn--primary btn--sm"
                        title="ذخیره این کانفیگ و خالی کردن کادر برای استخراج کانفیگ بعدی"
                      >
                        <Plus style={{ width: 13, height: 13 }} />
                        <span>ذخیره و دریافت کانفیگ بعدی</span>
                      </button>
                    </div>

                    <div style={{ position: 'relative', minWidth: 200, flex: '1 1 200px', maxWidth: 320 }}>
                      <Search
                        style={{
                          position: 'absolute',
                          top: '50%',
                          right: 11,
                          transform: 'translateY(-50%)',
                          width: 14,
                          height: 14,
                          color: 'var(--faint)',
                        }}
                      />
                      <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="جستجو بر اساس نام سرور، آدرس IP یا پروتکل..."
                        className="field"
                        style={{ paddingRight: 32, paddingTop: 6, paddingBottom: 6, fontSize: 12.5 }}
                      />
                    </div>
                  </div>

                  {/* Mobile cards */}
                  <div className="nodecards">
                    {filteredNodes.map((node) => {
                      const pingInfo = nodePings[node.id];
                      return (
                        <div
                          key={node.id}
                          style={{
                            padding: 13,
                            borderRadius: 12,
                            border: '1px solid var(--line)',
                            background: 'var(--surface-2)',
                            display: 'grid',
                            gap: 10,
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 }}>
                            <div style={{ minWidth: 0, flex: 1 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                                <span className={PROTO_CHIP[node.protocol.toLowerCase()] || 'chip'}>
                                  {node.protocol.toUpperCase()}
                                </span>
                                <span style={{ fontWeight: 650, fontSize: 12.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {node.name}
                                </span>
                              </div>
                              <div className="mono" dir="ltr" style={{ fontSize: 11.5, color: 'var(--accent)', marginTop: 4 }}>
                                {node.server}:{node.port}
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={() => handlePingNode(node)}
                              style={{ cursor: 'pointer', background: 'transparent', border: 0, padding: 0 }}
                            >
                              <LatencyChip ms={pingInfo?.ms ?? null} status={pingInfo?.status ?? 'idle'} />
                            </button>
                          </div>

                          <div style={{ display: 'flex', gap: 6 }}>
                            <button
                              type="button"
                              onClick={() => copy(node.link, node.id)}
                              className="btn btn--primary btn--sm flex-1"
                            >
                              {copiedKey === node.id ? <Check style={{ width: 13, height: 13 }} /> : <Copy style={{ width: 13, height: 13 }} />}
                              <span>رونویسی لینک</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setModalNode(node);
                                setModalMode('details');
                              }}
                              className="btn btn--ghost btn--sm"
                            >
                              <FileCode2 style={{ width: 13, height: 13 }} />
                              <span>جزئیات و بارکد QR</span>
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Desktop table */}
                  <div className="hidden md:block overflow-x-auto ntablet-wrap">
                    <table className="ntable">
                      <thead>
                        <tr>
                          <th>عنوان سرور</th>
                          <th>پروتکل</th>
                          <th>آدرس و پورت</th>
                          <th>بستر انتقال / امنیت</th>
                          <th>وضعیت پینگ</th>
                          <th style={{ textAlign: 'left' }}>عملیات</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredNodes.map((node) => {
                          const pingInfo = nodePings[node.id];
                          return (
                            <tr key={node.id}>
                              <td style={{ fontWeight: 600, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', direction: 'ltr', textAlign: 'right' }}>
                                {node.name}
                              </td>
                              <td>
                                <span className={PROTO_CHIP[node.protocol.toLowerCase()] || 'chip'}>
                                  {node.protocol.toUpperCase()}
                                </span>
                              </td>
                              <td className="mono" dir="ltr" style={{ color: 'var(--accent)', fontSize: 12 }}>
                                {node.server}:{node.port}
                              </td>
                              <td>
                                <span className="chip mono" style={{ fontSize: 10.5 }}>
                                  {node.network} · {node.security || 'none'}
                                </span>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  onClick={() => handlePingNode(node)}
                                  style={{ cursor: 'pointer', background: 'transparent', border: 0, padding: 0 }}
                                >
                                  <LatencyChip ms={pingInfo?.ms ?? null} status={pingInfo?.status ?? 'idle'} />
                                </button>
                              </td>
                              <td style={{ textAlign: 'left' }}>
                                <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', alignItems: 'center' }}>
                                  <button
                                    type="button"
                                    onClick={() => copy(node.link, node.id)}
                                    className="btn btn--ghost btn--sm"
                                    title="کپی لینک"
                                  >
                                    {copiedKey === node.id ? (
                                      <Check style={{ width: 13, height: 13, color: 'var(--ok)' }} />
                                    ) : (
                                      <Copy style={{ width: 13, height: 13 }} />
                                    )}
                                    <span>رونویسی</span>
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setModalNode(node);
                                      setModalMode('qr');
                                    }}
                                    className="btn btn--icon btn--ghost"
                                    title="کد QR و جزئیات"
                                    aria-label="کد QR"
                                  >
                                    <QrCode style={{ width: 14, height: 14 }} />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setModalNode(node);
                                      setModalMode('details');
                                    }}
                                    className="btn btn--icon btn--ghost"
                                    title="جزئیات و خروجی‌ها"
                                    aria-label="جزئیات"
                                  >
                                    <FileCode2 style={{ width: 14, height: 14 }} />
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </section>
              ) : (
                <div className="pending">
                  <span className="pending__dot" />
                  <p className="pending__text">
                    پس از انجام فرآیند رمزگشایی، فهرست سرورها به همراه قابلیت سنجش پینگ و بارکد QR در این بخش نمایان خواهد شد.
                  </p>
                </div>
              )}
            </Stage>

            {/* Saved Configs Space / Library */}
            <ConfigLibrary
              batches={savedBatches}
              onRemoveBatch={handleRemoveBatch}
              onClearAll={handleClearAllLibrary}
              onSelectNodeForModal={(node, mode) => {
                setModalNode(node);
                setModalMode(mode);
              }}
              onPingNode={handlePingNode}
              nodePings={nodePings}
              onToast={push}
              onLoadBatchIntoActive={handleLoadBatchIntoActive}
            />

            {/* Advanced tools — collapsed by default so the page stays quiet */}
            <details className="disclosure">
              <summary className="disclosure__summary">
                <span className="icon">
                  <Wrench style={{ width: 15, height: 15 }} />
                </span>
                <span>ابزارهای جانبی و تشخیصی</span>
                <span className="note">تحلیل خطاهای لاگ Xray و ارزیابی پینگ سرویس‌های ارتباطی</span>
                <ChevronDown className="chev" style={{ width: 16, height: 16 }} />
              </summary>
              <div className="disclosure__body">
                <div id="xray">
                  <XrayLogDiagnostic
                    isLight={isLight}
                    tlsFixMode={tlsFixMode}
                    onChangeTlsFixMode={setTlsFixMode}
                    tlsMismatchCount={conversion?.tlsMismatchCount || 0}
                  />
                </div>
                <div id="ping">
                  <NetworkPingTester />
                </div>
              </div>
            </details>
          </React.Fragment>
        ) : appMode === 'forge' ? (
          <div className="flow">
            <Stage
              id="forge-input"
              n={1}
              title="مرحله اول: دریافت لینک‌های ورودی"
              hint="پشتیبانی از پروتکل‌های vless، vmess، trojan و shadowsocks"
              state={reverseInput.trim() ? 'active' : 'idle'}
            >
              <div className="panel">
                <div className="panel__body" style={{ display: 'grid', gap: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                    <div className="seg">
                      <button
                        type="button"
                        onClick={() => setBuilderVersion('npvs5')}
                        className={`seg__item ${builderVersion === 'npvs5' ? 'is-active' : ''}`}
                      >
                        نسل ۵ (.npvs)
                      </button>
                      <button
                        type="button"
                        onClick={() => setBuilderVersion('npvt1')}
                        className={`seg__item ${builderVersion === 'npvt1' ? 'is-active' : ''}`}
                      >
                        نسل ۴ (.npvt)
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        setReverseInput(
                          'vless://a3b8d920-41e5-4f88-9a1e-8c7b6f5d4e3a@167.82.64.46:443?encryption=none&security=tls&sni=firefox.com&allowInsecure=1&vcn=default.ssl.fastly.net&type=ws&host=npv5-relay.global.ssl.fastly.net&path=%2Fws#Fastly-VLESS'
                        )
                      }
                      className="btn btn--ghost btn--sm"
                    >
                      <Zap style={{ width: 13, height: 13, color: 'var(--warn)' }} />
                      <span>لینک نمونه</span>
                    </button>
                  </div>

                  {builderVersion === 'npvs5' && (
                    <div className="grid grid-cols-1 sm:grid-cols-2" style={{ gap: 8 }}>
                      <input
                        type="text"
                        dir="ltr"
                        value={builderPassphrase}
                        onChange={(e) => setBuilderPassphrase(e.target.value)}
                        placeholder="رمز عبور کانتینر خروجی (اختیاری)"
                        className="field"
                        style={{ fontSize: 12.5 }}
                      />
                      <input
                        type="text"
                        value={builderMessage}
                        onChange={(e) => setBuilderMessage(e.target.value)}
                        placeholder="پیام سازنده کانتینر (اختیاری)"
                        className="field"
                        style={{ fontSize: 12.5 }}
                      />
                    </div>
                  )}

                  <textarea
                    value={reverseInput}
                    onChange={(e) => setReverseInput(e.target.value)}
                    dir="ltr"
                    placeholder="لینک‌های اتصال موردنظر را هر کدام در یک سطر وارد نمایید..."
                    className="field field--code"
                    style={{ minHeight: 180 }}
                  />

                  {reverseError && (
                    <div
                      role="alert"
                      style={{
                        padding: '10px 12px',
                        borderRadius: 10,
                        border: '1px solid color-mix(in srgb, var(--danger) 26%, transparent)',
                        background: 'var(--danger-soft)',
                        fontSize: 12.5,
                        color: 'var(--danger)',
                      }}
                    >
                      {reverseError}
                    </div>
                  )}

                  <button type="button" onClick={handleBuildReverseNPV} className="btn btn--primary btn--lg" style={{ width: '100%' }}>
                    <ArrowLeftRight style={{ width: 14, height: 14 }} />
                    <span>{builderVersion === 'npvs5' ? 'رمزنگاری و تولید کانتینر .npvs (نسل ۵)' : 'تولید کانتینر متنی .npvt (نسل ۴)'}</span>
                  </button>
                </div>
              </div>
            </Stage>

            <Stage
              id="forge-output"
              n={2}
              title="مرحله دوم: کانتینر تولیدشده"
              hint={builderVersion === 'npvs5' ? 'کانتینر استاندارد NPVS v5' : 'کانتینر استاندارد NPVT1'}
              state={reverseOutput ? 'done' : 'idle'}
            >
              <div className="panel">
                <div className="panel__body" style={{ display: 'grid', gap: 12 }}>
                  {!reverseOutput ? (
                    <div className="emptystate">
                      <p style={{ margin: 0, fontSize: 13, color: 'var(--muted)' }}>
                        لطفاً لینک‌های اتصال را در مرحله اول وارد نموده و بر روی دکمه تولید کلیک فرمایید.
                      </p>
                    </div>
                  ) : (
                    <>
                      <div className="codepane">
                        <div className="codepane__chrome">
                          <span style={{ fontSize: 11.5, color: 'var(--muted)' }}>
                            {builderVersion === 'npvs5' ? 'کانتینر NPVS v5' : 'کانتینر NPVT1'}
                          </span>
                          <div style={{ display: 'flex', gap: 6, marginInlineStart: 'auto' }}>
                            <CopyButton text={reverseOutput} copyKey="reverse-npvt" copied={copiedKey} onCopy={copy} iconOnly label="کپی" />
                            <button
                              type="button"
                              onClick={() =>
                                builderVersion === 'npvs5' && reverseBinaryBytes
                                  ? download(reverseBinaryBytes, 'config-gen5.npvs', 'application/octet-stream')
                                  : download(reverseOutput, 'config.npvt')
                              }
                              className="btn btn--icon btn--ghost"
                              title="دانلود"
                            >
                              <Download style={{ width: 14, height: 14 }} />
                            </button>
                          </div>
                        </div>
                        <textarea
                          readOnly
                          value={reverseOutput}
                          dir="ltr"
                          className="codepane__pre"
                          style={{ minHeight: 180, resize: 'none' }}
                        />
                      </div>

                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <button
                          type="button"
                          onClick={() =>
                            builderVersion === 'npvs5' && reverseBinaryBytes
                              ? download(reverseBinaryBytes, 'config-gen5.npvs', 'application/octet-stream')
                              : download(reverseOutput, 'config.npvt')
                          }
                          className="btn btn--primary"
                        >
                          <Download style={{ width: 14, height: 14 }} />
                          <span>{builderVersion === 'npvs5' ? 'بارگیری فایل کانتینر .npvs' : 'بارگیری فایل کانتینر .npvt'}</span>
                        </button>
                        <CopyButton
                          text={reverseOutput}
                          copyKey="reverse-npvt"
                          copied={copiedKey}
                          onCopy={copy}
                          label="رونویسی محتوای کانتینر"
                          doneLabel="محتوا رونویسی گردید"
                          variant="btn--soft"
                        />
                      </div>
                    </>
                  )}
                </div>
              </div>
            </Stage>
          </div>
        ) : (
          /* Studio (password-gated) */
          <div>
            {vaultUnlocked ? (
              <StealthRebrandStudio
                nodes={conversion?.nodes || []}
                gen2Ready={gen2Ready}
                onEnsureGen2={async () => {
                  if (gen2Ready) return true;
                  const ok = await preloadGen2TablesBrowser();
                  setGen2Ready(ok);
                  return ok;
                }}
                onLock={handleVaultLock}
                alias={alias}
                onAliasChange={handleAliasChange}
                onGoDecode={() => setAppMode('decode')}
                onLoadSample={handleLoadSampleV5}
              />
            ) : (
              <VaultGate onUnlock={handleVaultUnlock} onBack={() => setAppMode('decode')} />
            )}
          </div>
        )}
      </main>

      {/* Footer — one quiet line */}
      <footer className="site-footer">
        <div className="wrap site-footer__row">
          <span>سامانه NPV//FORGE — پردازش و رمزگشایی ۱۰۰٪ آفلاین درون مرورگر کاربر. بدون انتقال داده به سرور.</span>
          <nav className="site-footer__links" aria-label="مراجع">
            <a href="https://github.com/XTLS/Xray-core" target="_blank" rel="noreferrer">Xray-core</a>
            <a href="https://github.com/2dust/v2rayNG" target="_blank" rel="noreferrer">v2rayNG</a>
            <a href="https://github.com/hiddify/hiddify-app" target="_blank" rel="noreferrer">Hiddify</a>
            <a href="https://github.com/MatsuriDayne/nekoray" target="_blank" rel="noreferrer">Nekoray</a>
          </nav>
        </div>
      </footer>

      <NodeModal
        node={modalNode}
        mode={modalMode || 'details'}
        isLight={isLight}
        onClose={() => {
          setModalNode(null);
          setModalMode(null);
        }}
        onCopy={copy}
        copiedLabel={copiedKey}
      />

      <WelcomeModal
        open={guideOpen && !modalNode}
        onClose={closeGuide}
        onGoToDecode={() => {
          setAppMode('decode');
          setTourOpen(true);
        }}
      />

      <InteractiveTour
        open={tourOpen}
        onClose={() => setTourOpen(false)}
        onSwitchMode={setAppMode}
      />
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AppInner />
    </ToastProvider>
  );
}
