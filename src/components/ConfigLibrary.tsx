import React, { useState, useMemo, useCallback } from 'react';
import {
  FolderArchive,
  Copy,
  Check,
  Download,
  Trash2,
  ChevronDown,
  FileCode2,
  Eye,
  QrCode,
} from 'lucide-react';
import { ConvertedNode } from '../utils/npvConverter';
import { CopyButton, LatencyChip } from './ui';

export interface SavedConfigBatch {
  id: string;
  title: string;
  sourceName: string;
  detectedFormat: string;
  timestamp: number;
  nodes: ConvertedNode[];
}

const STORAGE_KEY = 'npv_extracted_library_v2';

export function loadSavedBatches(): SavedConfigBatch[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveBatchesToStorage(batches: SavedConfigBatch[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(batches));
  } catch {}
}

interface ConfigLibraryProps {
  batches: SavedConfigBatch[];
  onRemoveBatch: (id: string) => void;
  onClearAll: () => void;
  onSelectNodeForModal?: (node: ConvertedNode, mode: 'qr' | 'details') => void;
  onPingNode?: (node: ConvertedNode) => Promise<boolean>;
  nodePings?: Record<string, { status: 'testing' | 'ok' | 'timeout'; ms: number | null }>;
  onToast: (type: 'ok' | 'info' | 'error', text: string) => void;
  onLoadBatchIntoActive?: (batch: SavedConfigBatch) => void;
}

export const ConfigLibrary: React.FC<ConfigLibraryProps> = ({
  batches,
  onRemoveBatch,
  onClearAll,
  onSelectNodeForModal,
  onPingNode,
  nodePings = {},
  onToast,
  onLoadBatchIntoActive,
}) => {
  const [expandedBatchId, setExpandedBatchId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const totalNodesCount = useMemo(
    () => batches.reduce((acc, b) => acc + b.nodes.length, 0),
    [batches]
  );

  const allCombinedLinks = useMemo(
    () => batches.flatMap((b) => b.nodes.map((n) => n.link)).join('\n'),
    [batches]
  );

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
        setTimeout(() => setCopiedKey((k) => (k === key ? null : k)), 1800);
      } catch {
        onToast('error', 'خطا در دسترسی به حافظه موقت سیستم (Clipboard).');
      }
    },
    [onToast]
  );

  const downloadFile = useCallback(
    (content: string, filename: string, mime = 'text/plain;charset=utf-8') => {
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
      }, 200);
      onToast('ok', `فایل «${filename}» با موفقیت ذخیره گردید.`);
    },
    [onToast]
  );

  const handleDownloadAllLinks = () => {
    if (!allCombinedLinks) return;
    downloadFile(allCombinedLinks, `npv-forge-all-nodes-${Date.now()}.txt`);
  };

  const handleDownloadCombinedXray = () => {
    const allNodes = batches.flatMap((b) => b.nodes);
    if (allNodes.length === 0) return;
    try {
      const configs = allNodes.map((n) => JSON.parse(n.xrayJson));
      const merged = configs[0] || {};
      merged.outbounds = configs.map((c, i) => ({
        ...(c.outbounds?.[0] || {}),
        tag: `proxy-${i + 1}`,
      }));
      merged.outbounds.push(
        { tag: 'direct', protocol: 'freedom', settings: {} },
        { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'http' } } }
      );
      downloadFile(JSON.stringify(merged, null, 2), `npv-forge-xray-combined-${Date.now()}.json`);
    } catch {
      onToast('error', 'خطا در یکپارچه‌سازی ساختار پیکربندی Xray JSON.');
    }
  };

  if (batches.length === 0) {
    return (
      <section id="library-space" className="library-space library-space--empty">
        <div className="library-card library-card--empty">
          <div className="library-card__icon">
            <FolderArchive style={{ width: 22, height: 22 }} />
          </div>
          <div style={{ textAlign: 'center', maxWidth: 460 }}>
            <h3 className="display" style={{ fontSize: 16, margin: 0, fontWeight: 700 }}>
              آرشیو محلی کانفیگ‌های استخراج‌شده (در حال حاضر خالی است)
            </h3>
            <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 8, lineHeight: 1.9, margin: 0 }}>
              پس از رمزگشایی هر کانفیگ، با انتخاب گزینه‌های <b>«افزودن به مجموعه»</b> یا{' '}
              <b>«ذخیره و دریافت کانفیگ بعدی»</b>، سرورهای استخراج‌شده در این بخش بایگانی خواهند شد تا امکان رونویسی و
              دریافت تجمیعی کلیه سرورها در یک مرحله فراهم گردد.
            </p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section id="library-space" className="library-space">
      <div className="library-card">
        {/* Header bar */}
        <div className="library-card__head">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="library-card__badge-icon">
              <FolderArchive style={{ width: 17, height: 17 }} />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="display" style={{ fontSize: 15.5, fontWeight: 700, margin: 0 }}>
                  مجموعه کانفیگ‌های ذخیره‌شده
                </h3>
                <span className="chip chip--accent mono" style={{ fontSize: 11 }}>
                  {batches.length.toLocaleString('fa-IR')} بسته · {totalNodesCount.toLocaleString('fa-IR')} سرور تجمیعی
                </span>
              </div>
              <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 3, margin: 0 }}>
                پایگاه محلی سرورهای استخراج‌شده؛ آماده رونویسی یکپارچه و صدور دسته‌ای
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <CopyButton
              text={allCombinedLinks}
              copyKey="all-library-links"
              copied={copiedKey}
              onCopy={copy}
              label="رونویسی کلیه لینک‌ها"
              doneLabel="کلیه لینک‌ها رونویسی شدند"
              variant="btn--primary"
            />
            <button
              type="button"
              onClick={handleDownloadAllLinks}
              className="btn btn--soft btn--sm"
              title="بارگیری فایل متنی حاوی کلیه لینک‌های تجمیعی"
            >
              <Download style={{ width: 14, height: 14 }} />
              <span>دریافت متنی</span>
            </button>
            <button
              type="button"
              onClick={handleDownloadCombinedXray}
              className="btn btn--ghost btn--sm"
              title="بارگیری فایل پیکربندی یکپارچه Xray JSON شامل کلیه سرورها"
            >
              <FileCode2 style={{ width: 14, height: 14 }} />
              <span className="hidden sm:inline">دریافت Xray تجمیعی</span>
            </button>
            <button
              type="button"
              onClick={onClearAll}
              className="btn btn--danger btn--sm"
              title="پاک‌سازی کامل کلیه بسته‌های ذخیره‌شده"
            >
              <Trash2 style={{ width: 14, height: 14 }} />
              <span>پاک‌سازی آرشیو</span>
            </button>
          </div>
        </div>

        {/* Batches list */}
        <div className="library-batches">
          {batches.map((batch, batchIdx) => {
            const isExpanded = expandedBatchId === batch.id;
            const batchLinks = batch.nodes.map((n) => n.link).join('\n');
            const protoCounts = Array.from(
              new Set(batch.nodes.map((n) => n.protocol.toUpperCase()))
            );

            return (
              <div key={batch.id} className={`library-batch ${isExpanded ? 'is-open' : ''}`}>
                <div
                  className="library-batch__bar"
                  onClick={() => setExpandedBatchId(isExpanded ? null : batch.id)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      setExpandedBatchId(isExpanded ? null : batch.id);
                    }
                  }}
                >
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <span className="idx mono" style={{ fontSize: 11 }}>
                      {batchIdx + 1}
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-sm truncate" style={{ color: 'var(--text)' }}>
                          {batch.title}
                        </span>
                        <span className="chip mono" style={{ fontSize: 10.5 }}>
                          {batch.detectedFormat}
                        </span>
                        <span className="chip chip--accent mono" style={{ fontSize: 10.5 }}>
                          {batch.nodes.length} سرور
                        </span>
                        {protoCounts.map((p) => (
                          <span key={p} className="chip mono" style={{ fontSize: 9.5 }}>
                            {p}
                          </span>
                        ))}
                      </div>
                      <div className="text-[11.5px] text-[var(--faint)] mt-0.5 truncate" dir="ltr">
                        {new Date(batch.timestamp).toLocaleTimeString('fa-IR', {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}{' '}
                        · {batch.sourceName}
                      </div>
                    </div>
                  </div>

                  <div
                    className="flex items-center gap-2"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      type="button"
                      onClick={() => copy(batchLinks, `batch-${batch.id}`)}
                      className="btn btn--soft btn--sm mono"
                      title="رونویسی لینک‌های متعلق به این بسته"
                    >
                      {copiedKey === `batch-${batch.id}` ? (
                        <Check style={{ width: 13, height: 13, color: 'var(--ok)' }} />
                      ) : (
                        <Copy style={{ width: 13, height: 13 }} />
                      )}
                      <span>رونویسی بسته</span>
                    </button>
                    {onLoadBatchIntoActive && (
                      <button
                        type="button"
                        onClick={() => onLoadBatchIntoActive(batch)}
                        className="btn btn--ghost btn--sm"
                        title="انتقال این بسته به پیش‌نمایش خروجی فعال"
                      >
                        <Eye style={{ width: 13, height: 13 }} />
                        <span className="hidden md:inline">مشاهده در خروجی</span>
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => onRemoveBatch(batch.id)}
                      className="btn btn--icon btn--ghost"
                      title="حذف این بسته از آرشیو"
                      aria-label="حذف این بسته"
                    >
                      <Trash2 style={{ width: 14, height: 14, color: 'var(--danger)' }} />
                    </button>
                    <button
                      type="button"
                      onClick={() => setExpandedBatchId(isExpanded ? null : batch.id)}
                      className="btn btn--icon btn--ghost"
                      aria-label={isExpanded ? 'بستن فهرست سرورها' : 'مشاهده فهرست سرورها'}
                    >
                      <ChevronDown
                        style={{
                          width: 15,
                          height: 15,
                          transform: isExpanded ? 'rotate(180deg)' : 'none',
                          transition: 'transform 0.2s',
                        }}
                      />
                    </button>
                  </div>
                </div>

                {/* Expanded server nodes */}
                {isExpanded && (
                  <div className="library-batch__nodes">
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                      {batch.nodes.map((node) => {
                        const ping = nodePings[node.id];
                        return (
                          <div key={node.id} className="library-node-item">
                            <div className="flex items-center justify-between gap-2 min-w-0">
                              <span className="chip mono !text-[9.5px]">
                                {node.protocol.toUpperCase()}
                              </span>
                              <span
                                className="font-semibold text-xs truncate flex-1 text-right"
                                style={{ color: 'var(--text)' }}
                              >
                                {node.name}
                              </span>
                              {onPingNode && (
                                <button
                                  type="button"
                                  onClick={() => onPingNode(node)}
                                  style={{ cursor: 'pointer', background: 'transparent', border: 0, padding: 0 }}
                                  title="سنجش پینگ این سرور"
                                >
                                  <LatencyChip ms={ping?.ms ?? null} status={ping?.status ?? 'idle'} />
                                </button>
                              )}
                            </div>
                            <div className="mono text-[11px] text-[var(--accent)] truncate mt-1" dir="ltr">
                              {node.server}:{node.port}
                            </div>
                            <div className="flex items-center justify-end gap-1.5 mt-2 pt-1 border-t border-[var(--line)]">
                              <button
                                type="button"
                                onClick={() => copy(node.link, `node-${node.id}`)}
                                className="btn btn--ghost btn--sm mono !py-0.5 !px-2 !text-[11px]"
                              >
                                {copiedKey === `node-${node.id}` ? (
                                  <Check style={{ width: 12, height: 12, color: 'var(--ok)' }} />
                                ) : (
                                  <Copy style={{ width: 12, height: 12 }} />
                                )}
                                <span>رونویسی</span>
                              </button>
                              {onSelectNodeForModal && (
                                <>
                                  <button
                                    type="button"
                                    onClick={() => onSelectNodeForModal(node, 'qr')}
                                    className="btn btn--icon btn--ghost !w-7 !h-7"
                                    title="بارکد QR"
                                    aria-label="بارکد QR"
                                  >
                                    <QrCode style={{ width: 13, height: 13 }} />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => onSelectNodeForModal(node, 'details')}
                                    className="btn btn--icon btn--ghost !w-7 !h-7"
                                    title="مشاهده جزئیات پیکربندی"
                                    aria-label="جزئیات"
                                  >
                                    <FileCode2 style={{ width: 13, height: 13 }} />
                                  </button>
                                </>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
