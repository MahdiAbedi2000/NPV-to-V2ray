import React, { useEffect, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import {
  X,
  Copy,
  Check,
  Download,
  ShieldCheck,
  QrCode,
  FileCode2,
  Terminal,
  Cpu,
  Layers,
  ExternalLink,
} from 'lucide-react';
import { ConvertedNode } from '../utils/npvConverter';
import { Modal, CopyButton } from './ui';

interface NodeModalProps {
  node: ConvertedNode | null;
  mode: 'qr' | 'details';
  onClose: () => void;
  onCopy: (text: string, label: string) => void;
  copiedLabel: string | null;
  isLight?: boolean;
}

export const NodeModal: React.FC<NodeModalProps> = ({
  node,
  mode: initialMode,
  onClose,
  onCopy,
  copiedLabel,
}) => {
  const [tab, setTab] = useState<'qr' | 'xray' | 'singbox' | 'clash'>(
    initialMode === 'qr' ? 'qr' : 'xray'
  );

  useEffect(() => {
    setTab(initialMode === 'qr' ? 'qr' : 'xray');
  }, [node?.id, initialMode]);

  if (!node) return null;

  const downloadJson = (content: string, filename: string, mime = 'application/json;charset=utf-8') => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      a.remove();
    }, 300);
  };

  const currentPayload =
    tab === 'xray'
      ? node.xrayJson
      : tab === 'singbox'
      ? node.singBoxJson
      : tab === 'clash'
      ? node.clashYaml
      : node.link;

  return (
    <Modal
      open={Boolean(node)}
      onClose={onClose}
      title={node.name}
      subtitle={
        <span className="mono" dir="ltr" style={{ color: 'var(--accent)' }}>
          {node.protocol.toUpperCase()} · {node.server}:{node.port}
        </span>
      }
      footer={
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[11.5px] text-[var(--muted)]">
            <span className="led led--on" />
            <span className="mono" dir="ltr">
              {node.network} / {node.security || 'none'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {tab !== 'qr' && (
              <button
                type="button"
                onClick={() =>
                  downloadJson(
                    currentPayload,
                    `${node.name.replace(/\s+/g, '_')}-${tab}.${tab === 'clash' ? 'yaml' : 'json'}`,
                    tab === 'clash' ? 'text/yaml;charset=utf-8' : 'application/json;charset=utf-8'
                  )
                }
                className="btn btn--ghost btn--sm"
              >
                <Download style={{ width: 13, height: 13 }} />
                <span>دریافت این فایل</span>
              </button>
            )}

            <CopyButton
              text={node.link}
              copyKey={`modal-link-${node.id}`}
              copied={copiedLabel}
              onCopy={onCopy}
              label="رونویسی لینک سرور"
              doneLabel="لینک رونویسی گردید"
              variant="btn--primary"
            />
          </div>
        </div>
      }
    >
      {/* Sub Tabs: QR / Xray JSON / Sing-box / Clash */}
      <div className="flex items-center justify-between gap-2 border-b pb-3 mb-4 flex-wrap">
        <div className="seg" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'qr'}
            onClick={() => setTab('qr')}
            className={`seg__item ${tab === 'qr' ? 'is-active' : ''}`}
          >
            <QrCode style={{ width: 13, height: 13 }} />
            <span>بارکد QR</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'xray'}
            onClick={() => setTab('xray')}
            className={`seg__item ${tab === 'xray' ? 'is-active' : ''}`}
          >
            <FileCode2 style={{ width: 13, height: 13 }} />
            <span>قالب Xray JSON</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'singbox'}
            onClick={() => setTab('singbox')}
            className={`seg__item ${tab === 'singbox' ? 'is-active' : ''}`}
          >
            <Cpu style={{ width: 13, height: 13 }} />
            <span>قالب Sing-box</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'clash'}
            onClick={() => setTab('clash')}
            className={`seg__item ${tab === 'clash' ? 'is-active' : ''}`}
          >
            <Layers style={{ width: 13, height: 13 }} />
            <span>قالب Clash YAML</span>
          </button>
        </div>

        <span className="chip chip--accent mono" dir="ltr">
          شناسه: {node.id.slice(0, 8)}
        </span>
      </div>

      {/* Tab 1: QR Code display */}
      {tab === 'qr' && (
        <div className="flex flex-col items-center justify-center gap-4 py-3">
          <div
            style={{
              padding: 16,
              background: '#ffffff',
              borderRadius: 20,
              boxShadow: '0 20px 50px -20px var(--glow), 0 0 0 1px rgba(0,0,0,0.1)',
            }}
          >
            <QRCodeSVG
              value={node.link}
              size={230}
              level="M"
              includeMargin={false}
              style={{ display: 'block' }}
            />
          </div>

          <p className="text-center text-xs text-[var(--muted)] max-w-sm">
            جهت اتصال سریع، این بارکد را توسط دوربین برنامه‌های کلاینت نظیر <b className="text-[var(--text)]">v2rayNG</b>،{' '}
            <b className="text-[var(--text)]">Streisand</b>، <b className="text-[var(--text)]">Nekoray</b> یا{' '}
            <b className="text-[var(--text)]">Hiddify</b> اسکن فرمایید.
          </p>

          <div
            className="w-full p-2.5 rounded-xl border bg-[var(--panel-2)] text-[11px] font-mono break-all text-[var(--muted)]"
            dir="ltr"
          >
            {node.link}
          </div>
        </div>
      )}

      {/* Tab 2, 3, 4: Code display */}
      {tab !== 'qr' && (
        <div className="space-y-3">
          {/* Key Parameters Pill Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <div className="stat">
              <span className="stat__k">پروتکل ارتباطی</span>
              <span className="stat__v stat__v--accent">{node.protocol.toUpperCase()}</span>
            </div>
            <div className="stat">
              <span className="stat__k">آدرس سرور و پورت</span>
              <span className="stat__v mono text-xs truncate" dir="ltr">
                {node.server}:{node.port}
              </span>
            </div>
            <div className="stat">
              <span className="stat__k">نوع شبکه انتقال</span>
              <span className="stat__v mono text-xs">{node.network}</span>
            </div>
            <div className="stat">
              <span className="stat__k">لایه امنیت TLS</span>
              <span className="stat__v mono text-xs">{node.security || 'فاقد رمزنگاری'}</span>
            </div>
          </div>

          {node.sni && (
            <div
              className="p-2.5 rounded-xl border flex items-center justify-between text-xs font-mono"
              dir="ltr"
              style={{ background: 'var(--panel-2)' }}
            >
              <span className="text-[var(--faint)]">SNI / ServerName:</span>
              <span className="text-[var(--accent)] font-semibold truncate ml-2">
                {node.sni}
              </span>
            </div>
          )}

          {node.tlsFixed && (
            <div className="p-3 rounded-xl border bg-[var(--accent-soft)] border-[color-mix(in_srgb,var(--accent)_30%,transparent)] text-xs text-[var(--text)] space-y-1">
              <div className="flex items-center gap-1.5 font-bold text-[var(--accent)]">
                <ShieldCheck style={{ width: 14, height: 14 }} />
                <span>تثبیت خودکار گواهی ارتباطی Fastly (x509 Auto-Fix)</span>
              </div>
              <p className="text-[11.5px] text-[var(--muted)]">
                {node.tlsFixNote || 'این سرور با پارامترهای ارتباطی allowInsecure=1 و vcn=default.ssl.fastly.net بازپیکربندی گردید تا تداخل گواهی امنیتی برطرف شود.'}
              </p>
            </div>
          )}

          <div className="codepane">
            <div className="codepane__chrome">
              <div className="codepane__dots">
                <i /><i /><i />
              </div>
              <span className="mono text-[10px] text-[var(--faint)] uppercase">
                {tab === 'xray' ? 'outbound config (xray json)' : tab === 'singbox' ? 'sing-box outbound' : 'clash proxy block'}
              </span>
              <button
                type="button"
                onClick={() => onCopy(currentPayload, `modal-code-${tab}`)}
                className="btn btn--ghost btn--sm mono text-[10px]"
              >
                {copiedLabel === `modal-code-${tab}` ? 'COPIED!' : 'COPY CODE'}
              </button>
            </div>
            <pre className="codepane__pre" dir="ltr">
              {currentPayload}
            </pre>
          </div>
        </div>
      )}
    </Modal>
  );
};
