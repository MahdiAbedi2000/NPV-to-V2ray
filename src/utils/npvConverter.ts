// @ts-nocheck
import { tyBoxes, mbl, tboxesLast, xorTable, shiftOrder } from './npvCryptoTables.ts';
import {
  isNpvGen2Bytes,
  isNpvV1Bytes,
  decryptNpvGen2Envelope,
  decryptNpvV1Envelope,
  buildNpvGen2Container,
  decryptNetModPayload,
  decodeNpvSentinels,
  deepDecodeSentinels,
  b64UrlOrStdToBytes,
  preloadGen2TablesBrowser,
  isGen2TablesLoaded,
} from './npvCryptV5.ts';

export { preloadGen2TablesBrowser, isGen2TablesLoaded };

export type TlsFixMode = 'auto-smart' | 'fastly-sni' | 'raw';

export interface ConvertedNode {
  id: string;
  name: string;
  protocol: string;
  server: string;
  port: string;
  network: string;
  security: string;
  sni: string;
  originalSni?: string;
  hostHeader: string;
  path: string;
  alpn: string;
  fp: string;
  pbk: string;
  sid: string;
  spx: string;
  flow: string;
  uuidOrPassword: string;
  method: string;
  insecure: boolean;
  vcn: string;
  tlsFixed: boolean;
  tlsFixNote?: string;
  isFastly?: boolean;
  link: string;
  fastlyFixedLink?: string;
  xrayJson: string;
  singBoxJson: string;
  clashYaml: string;
  source: string;
}

export interface ConversionResult {
  detectedFormat: string;
  nodes: ConvertedNode[];
  sshProfiles: Array<{
    name: string;
    host: string;
    port: string;
    username: string;
    password?: string;
    payload?: string;
    sni?: string;
  }>;
  decryptedChunks: Array<{ index: string; text: string }>;
  npvsInspection: {
    version: number;
    unlockMethod: string;
    recipients: number;
    iterations?: number;
    bytes: number;
    decrypted?: boolean;
  } | null;
  recoveredKeys?: Record<string, string>;
  creatorMessage?: string;
  needsPassphrase?: boolean;
  tlsMismatchCount?: number;
  errors: string[];
  notes: string[];
}

function shiftRowsLike(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = b[shiftOrder[i]];
  return out;
}

export function coreTransform(block: Uint8Array): Uint8Array {
  let buf = new Uint8Array(block);
  buf = shiftRowsLike(buf);
  for (let i11 = 0; i11 < 4; i11++) {
    const i13 = i11 * 4;
    const i14 = i13 + 1, i15 = i13 + 2, i16 = i13 + 3;
    const iC  = tyBoxes[i13][buf[i13]] >>> 0;
    const iC2 = tyBoxes[i14][buf[i14]] >>> 0;
    const iC3 = tyBoxes[i15][buf[i15]] >>> 0;
    const iC4 = tyBoxes[i16][buf[i16]] >>> 0;
    for (let i17 = 0; i17 < 4; i17++) {
      const i18 = (i11 * 24) + (i17 * 6);
      const i19 = i17 * 8;
      const i20 = 28 - i19;
      const i22 = 24 - i19;
      const n1 = (iC >>> i20) & 15;
      const n2 = (iC2 >>> i20) & 15;
      const n3 = (iC3 >>> i20) & 15;
      const n4 = (iC4 >>> i20) & 15;
      const b10 = xorTable[i18][n1][n2];
      const b11 = xorTable[i18 + 1][n3][n4];
      const m1 = (iC >>> i22) & 15;
      const m2 = (iC2 >>> i22) & 15;
      const m3 = (iC3 >>> i22) & 15;
      const m4 = (iC4 >>> i22) & 15;
      const lo = xorTable[i18 + 5][xorTable[i18 + 2][m1][m2]][xorTable[i18 + 3][m3][m4]];
      const hi = xorTable[i18 + 4][b10][b11];
      buf[i13 + i17] = lo | (hi << 4);
    }
    const iC5 = mbl[i13][buf[i13]] >>> 0;
    const iC6 = mbl[i14][buf[i14]] >>> 0;
    const iC7 = mbl[i15][buf[i15]] >>> 0;
    const iC8 = mbl[i16][buf[i16]] >>> 0;
    for (let i27 = 0; i27 < 4; i27++) {
      const i28 = (i11 * 24) + (i27 * 6);
      const i29 = i27 * 8;
      const i30 = 28 - i29;
      const i31 = 24 - i29;
      const n1 = (iC5 >>> i30) & 15;
      const n2 = (iC6 >>> i30) & 15;
      const n3 = (iC7 >>> i30) & 15;
      const n4 = (iC8 >>> i30) & 15;
      const a1 = xorTable[i28][n1][n2];
      const a2 = xorTable[i28 + 1][n3][n4];
      const hi = xorTable[i28 + 4][a1][a2];
      const m1 = (iC5 >>> i31) & 15;
      const m2 = (iC6 >>> i31) & 15;
      const m3 = (iC7 >>> i31) & 15;
      const m4 = (iC8 >>> i31) & 15;
      const b1 = xorTable[i28 + 2][m1][m2];
      const b2 = xorTable[i28 + 3][m3][m4];
      const lo = xorTable[i28 + 5][b1][b2];
      buf[i13 + i27] = (hi << 4) | lo;
    }
  }
  buf = shiftRowsLike(buf);
  for (let i = 0; i < 16; i++) buf[i] = tboxesLast[i][buf[i]];
  return buf;
}

function ctrIncrement(counter: Uint8Array): void {
  for (let i = 15; i >= 0; i--) {
    counter[i] = (counter[i] + 1) & 255;
    if (counter[i] !== 0) break;
  }
}

export function ctrCrypt(nonce: Uint8Array, data: Uint8Array): Uint8Array {
  const counter = new Uint8Array(nonce);
  const out = new Uint8Array(data.length);
  let keystream = new Uint8Array(16);
  for (let i = 0; i < data.length; i++) {
    if (i % 16 === 0) {
      keystream = coreTransform(counter);
      ctrIncrement(counter);
    }
    out[i] = keystream[i % 16] ^ data[i];
  }
  return out;
}

export function decryptNPVTBytes(ciphertextWithNonce: Uint8Array): Uint8Array {
  if (!ciphertextWithNonce || ciphertextWithNonce.length < 16) {
    throw new Error('Ciphertext must be at least 16 bytes');
  }
  const nonce = ciphertextWithNonce.slice(0, 16);
  const ct = ciphertextWithNonce.slice(16);
  return ctrCrypt(nonce, ct);
}

export function stripWs(s: string): string {
  return String(s || '').replace(/[\s\uFEFF]+/g, '');
}

export function isHex(s: string): boolean {
  return s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function b64ToBytes(s: string): Uint8Array {
  s = stripWs(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.slice(i, i + chunk));
  }
  return btoa(bin);
}

export function base64Utf8(text: string): string {
  return bytesToBase64(textToBytes(text));
}

export function base64UrlUtf8(text: string): string {
  return base64Utf8(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(String(value || '').replace(/\+/g, ' '));
  } catch (_) {
    return String(value || '');
  }
}

/** Strict percent-decoder — keeps literal `+` intact (for userinfo and names, not query strings). */
export function decodeUriStrict(value: string): string {
  try {
    return decodeURIComponent(String(value || ''));
  } catch (_) {
    return String(value || '');
  }
}

function firstValue(...values: any[]): any {
  for (const v of values) {
    if (v !== undefined && v !== null && String(v).trim() !== '') return v;
  }
  return '';
}

function truthyParam(v: any): boolean {
  if (v === true) return true;
  const s = String(v ?? '').trim().toLowerCase();
  return ['1', 'true', 'yes', 'y', 'on'].includes(s);
}

function splitHostPort(addr: string): { host?: string; port?: string } {
  addr = String(addr || '').trim();
  if (!addr) return {};
  if (addr.startsWith('[')) {
    const end = addr.indexOf(']');
    if (end >= 0) {
      const host = addr.slice(1, end);
      const rest = addr.slice(end + 1);
      const port = rest.startsWith(':') ? rest.slice(1) : '';
      return { host, port };
    }
  }
  const idx = addr.lastIndexOf(':');
  if (idx > 0 && addr.indexOf(':') === idx) {
    return { host: addr.slice(0, idx), port: addr.slice(idx + 1) };
  }
  return { host: addr };
}

function splitHostPortLoose(value: string): { host: string; port: string } {
  const raw = String(value || '').trim();
  const out = splitHostPort(raw);
  return { host: out.host || raw, port: out.port || '' };
}

function cleanRemarkName(name: string, fallback = 'NPV Config'): string {
  const raw = decodeUriStrict(String(name || '').trim());
  return raw.replace(/[\r\n\t]+/g, ' ').trim().slice(0, 120) || fallback;
}

function normalizeNetworkId(v: string): string {
  const n = String(v || '').trim().toLowerCase();
  if (!n) return 'tcp';
  if (n === 'websocket') return 'ws';
  if (n === 'http2' || n === 'h2') return 'http';
  if (n === 'split-http') return 'splithttp';
  if (n === 'http-upgrade') return 'httpupgrade';
  return n;
}

function getHeaderValue(headers: any, ...keys: string[]): string {
  if (!headers || typeof headers !== 'object') return '';
  for (const k of keys) {
    const val = headers[k];
    if (Array.isArray(val) && val.length) return String(val[0]);
    if (typeof val === 'string' && val.trim()) return val.trim();
  }
  return '';
}

function isUuid(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(s || ''));
}

function enc(v: any): string {
  return encodeURIComponent(String(v ?? ''));
}

function addParam(arr: string[], key: string, val: any): void {
  if (val === undefined || val === null || val === '') return;
  arr.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(val))}`);
}

function formatUriHost(host: string): string {
  const h = String(host || '').trim();
  if (h.includes(':') && !h.startsWith('[')) return `[${h}]`;
  return h;
}

export function decodeOneNPVTToken(text: string): Uint8Array {
  let tok = String(text || '').trim();
  tok = tok.replace(/^npv-tunnel:\/\//i, '').replace(/^npvt:\/\//i, '');
  tok = tok.replace(/^\s*NPVT(?:SUB)?1\s*[:=,-]?\s*/i, '');
  tok = tok.replace(/^["'`]+|["'`]+$/g, '');
  tok = stripWs(tok);
  if (!tok) throw new Error('Empty NPVT token');
  tok = tok.replace(/^[^A-Za-z0-9+/_-]+|[^A-Za-z0-9+/=_-]+$/g, '');
  if (isHex(tok) && tok.length >= 32) return hexToBytes(tok);
  return b64ToBytes(tok);
}

export function decodeNPVTPlainChunks(text: string): Array<{ part: number; text: string }> {
  let tok = String(text || '').trim();
  tok = tok.replace(/^npv-tunnel:\/\//i, '').replace(/^npvt:\/\//i, '').replace(/^\s*NPVT(?:SUB)?1\s*[:=\-]?\s*/i, '').trim();
  const parts = tok.includes(',') ? tok.split(',').map(x => x.trim()).filter(Boolean) : [tok];
  const out: Array<{ part: number; text: string }> = [];
  for (let i = 0; i < parts.length; i++) {
    const encrypted = decodeOneNPVTToken(parts[i]);
    const plainBytes = decryptNPVTBytes(encrypted);
    const plain = bytesToText(plainBytes).replace(/\0+$/g, '').trim();
    out.push({ part: i + 1, text: plain });
  }
  return out;
}

export function extractNPVTTokens(text: string, forceNPVT = false): string[] {
  const raw = String(text || '');
  const tokens: string[] = [];
  const seen = new Set<string>();
  const re = /(?:NPVT(?:SUB)?1|npvt:\/\/|npv-tunnel:\/\/)\s*[:=\-]?\s*([A-Za-z0-9+/_=-]{8,}(?:\s*,\s*[A-Za-z0-9+/_=-]{8,})*)/gi;
  let m;
  while ((m = re.exec(raw))) {
    const body = m[1].split(',').map(x => stripWs(x)).filter(Boolean).join(',');
    const tok = 'NPVT1 ' + body;
    if (!seen.has(tok)) {
      seen.add(tok);
      tokens.push(tok);
    }
  }
  if (forceNPVT && !tokens.length) {
    const compact = raw.trim().replace(/^npv-tunnel:\/\//i, '').replace(/^npvt:\/\//i, '').replace(/^NPVT(?:SUB)?1\s*[:=\-]?/i, '').trim();
    if (compact.length >= 8 && /^[A-Za-z0-9+/_=\-,\s]+$/.test(compact)) {
      const tok = 'NPVT1 ' + compact.split(',').map(x => stripWs(x)).filter(Boolean).join(',');
      if (!seen.has(tok)) tokens.push(tok);
    }
  }
  return tokens;
}

export function extractRawLinks(text: string): string[] {
  const links: string[] = [];
  const re = /(^|[^A-Za-z0-9+.-])((?:vless|vmess|trojan|ss|ssr|socks|hysteria2\+realm\+http|hysteria2\+realm|hysteria2?|hy2|tuic|anytls):\/\/[^\s"'<>]+)/gi;
  let m;
  while ((m = re.exec(String(text || '')))) {
    const link = String(m[2] || '').replace(/[),.;\]\}]+$/g, '');
    if (link && !links.includes(link)) links.push(link);
  }
  return links;
}

export function parseJSONCandidates(text: string): any[] {
  const out: any[] = [];
  const tried = new Set<string>();
  function pushParse(s: string) {
    s = String(s || '').trim();
    if (!s || tried.has(s)) return;
    tried.add(s);
    try {
      out.push(JSON.parse(s));
    } catch (_) {}
  }
  const raw = String(text || '').replace(/^\uFEFF/, '');
  pushParse(raw);
  const firstBrace = raw.search(/[\[{]/);
  const lastBrace = Math.max(raw.lastIndexOf('}'), raw.lastIndexOf(']'));
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    pushParse(raw.slice(firstBrace, lastBrace + 1));
  }
  return out;
}

export function tryDecodeBase64Text(text: string): string | null {
  const compact = stripWs(text);
  if (compact.length < 12 || compact.length > 2_000_000) return null;
  if (!/^[A-Za-z0-9+/_=-]+$/.test(compact)) return null;
  try {
    const decoded = bytesToText(b64ToBytes(compact));
    if (extractRawLinks(decoded).length || decoded.trim().startsWith('{') || decoded.trim().startsWith('[')) {
      return decoded;
    }
  } catch (_) {}
  return null;
}

function streamSettingsToProfile(stream: any = {}) {
  stream = stream || {};
  const tls = stream.tlsSettings || {};
  const reality = stream.realitySettings || {};
  const ws = stream.wsSettings || {};
  const grpc = stream.grpcSettings || {};
  const http = stream.httpSettings || {};
  const httpUpgrade = stream.httpupgradeSettings || stream.httpUpgradeSettings || {};
  const splithttp = stream.splithttpSettings || stream.splitHttpSettings || {};
  const xhttp = stream.xhttpSettings || {};
  const tcp = stream.tcpSettings || {};
  const tcpHeader = tcp.header || {};
  const tcpRequest = tcpHeader.request || {};
  const security = firstValue(
    stream.security,
    reality && Object.keys(reality).length ? 'reality' : '',
    tls && Object.keys(tls).length ? 'tls' : '',
    'none'
  );
  const network = normalizeNetworkId(firstValue(
    stream.network,
    stream.method,
    stream.net,
    ws.path !== undefined ? 'ws' : '',
    grpc.serviceName !== undefined ? 'grpc' : '',
    xhttp.path !== undefined ? 'xhttp' : '',
    'tcp'
  ));
  return {
    network,
    security,
    headerType: firstValue(tcpHeader.type, http.host ? 'http' : '', 'none'),
    sni: firstValue(tls.serverName, reality.serverName, stream.serverName, stream.sni),
    fp: firstValue(tls.fingerprint, tls.fp, reality.fingerprint, reality.fp),
    publicKey: firstValue(reality.publicKey, reality.pbk, stream.publicKey, stream.pbk),
    shortId: firstValue(reality.shortId, reality.shortIds, reality.sid, stream.shortId, stream.sid),
    spiderX: firstValue(reality.spiderX, reality.spx, stream.spiderX, stream.spx),
    alpn: Array.isArray(tls.alpn) ? tls.alpn.join(',') : firstValue(tls.alpn, reality.alpn, stream.alpn),
    hostHeader: firstValue(
      ws.host,
      getHeaderValue(ws.headers, 'Host', 'host'),
      getHeaderValue(httpUpgrade.headers, 'Host', 'host'),
      getHeaderValue(splithttp.headers, 'Host', 'host'),
      getHeaderValue(tcpRequest.headers, 'Host', 'host'),
      Array.isArray(http.host) ? http.host[0] : http.host,
      xhttp.host
    ),
    path: firstValue(xhttp.path, ws.path, http.path, httpUpgrade.path, splithttp.path, tcpRequest.path),
    xhttpMode: firstValue(xhttp.mode),
    xhttpExtra: xhttp.extra && typeof xhttp.extra === 'object' ? xhttp.extra : null,
    serviceName: firstValue(grpc.serviceName),
    authority: firstValue(grpc.authority),
    insecure: truthyParam(firstValue(tls.allowInsecure, reality.allowInsecure, stream.allowInsecure)),
    pinnedPeerCertSha256: firstValue(tls.pinnedPeerCertSha256),
    verifyPeerCertByName: firstValue(tls.verifyPeerCertByName)
  };
}

function outboundToProfiles(outbound: any, inheritedName = ''): any[] {
  const profiles: any[] = [];
  if (!outbound || typeof outbound !== 'object') return profiles;
  const protocol = String(outbound.protocol || outbound.type || '').toLowerCase();
  if (!protocol) return profiles;
  const common = streamSettingsToProfile(outbound.streamSettings || {});
  const settings = outbound.settings || {};
  const outboundTag = String(outbound.tag || '').trim();
  const genericOutboundTag = /^(proxy|direct|block|dns|dns-out|blackhole|freedom)$/i.test(outboundTag);
  const baseName = firstValue(outbound.name, outbound.remarks, genericOutboundTag ? '' : outboundTag, inheritedName, protocol.toUpperCase());

  if ((protocol === 'vless' || protocol === 'vmess') && Array.isArray(settings.vnext)) {
    for (const server of settings.vnext) {
      const users = Array.isArray(server.users) && server.users.length ? server.users : [{}];
      for (const user of users) {
        profiles.push({
          ...common,
          protocol,
          name: firstValue(user.email, user.name, baseName),
          server: firstValue(server.address, server.add, server.host),
          serverPort: firstValue(server.port, server.serverPort),
          id: firstValue(user.id, user.uuid, user.password),
          method: firstValue(user.encryption, user.security, user.scy, protocol === 'vless' ? 'none' : 'auto'),
          alterId: firstValue(user.alterId, user.aid, '0'),
          flow: firstValue(user.flow, common.flow),
        });
      }
    }
  }
  if ((protocol === 'vless' || protocol === 'vmess') && !Array.isArray(settings.vnext) && settings.address && settings.port && settings.id) {
    profiles.push({
      ...common,
      protocol,
      name: baseName,
      server: settings.address,
      serverPort: settings.port,
      id: settings.id,
      method: protocol === 'vless' ? firstValue(settings.encryption, 'none') : firstValue(settings.security, 'auto'),
      alterId: protocol === 'vmess' ? firstValue(settings.alterId, '0') : '0',
      flow: firstValue(settings.flow),
    });
  }
  if ((protocol === 'trojan' || protocol === 'shadowsocks' || protocol === 'ss' || protocol === 'socks') && Array.isArray(settings.servers)) {
    for (const server of settings.servers) {
      profiles.push({
        ...common,
        protocol: protocol === 'shadowsocks' ? 'ss' : protocol,
        name: firstValue(server.email, server.name, server.remarks, baseName),
        server: firstValue(server.address, server.server, server.host),
        serverPort: firstValue(server.port, server.serverPort),
        id: firstValue(server.password, server.pass, server.id, server.uuid),
        method: firstValue(server.method, server.cipher, server.security, protocol === 'shadowsocks' || protocol === 'ss' ? 'aes-128-gcm' : 'none'),
        username: firstValue(server.users && server.users[0] && server.users[0].user, server.username, server.user),
        password: firstValue(server.users && server.users[0] && server.users[0].pass, server.password, server.pass)
      });
    }
  }
  // Sing-box direct outbound format
  if (outbound.server && outbound.server_port && ['vless', 'vmess', 'trojan', 'shadowsocks', 'ss', 'socks', 'hysteria2', 'tuic'].includes(protocol)) {
    const tls = outbound.tls || {};
    const transport = outbound.transport || {};
    profiles.push({
      protocol: protocol === 'shadowsocks' ? 'ss' : protocol,
      name: baseName,
      server: outbound.server,
      serverPort: String(outbound.server_port),
      id: firstValue(outbound.uuid, outbound.password),
      method: firstValue(outbound.method, outbound.security, protocol === 'vless' ? 'none' : 'auto'),
      network: firstValue(transport.type, 'tcp'),
      security: tls.enabled ? (tls.reality && tls.reality.enabled ? 'reality' : 'tls') : 'none',
      sni: firstValue(tls.server_name),
      fp: firstValue(tls.utls && tls.utls.fingerprint),
      publicKey: firstValue(tls.reality && tls.reality.public_key),
      shortId: firstValue(tls.reality && tls.reality.short_id),
      hostHeader: firstValue(transport.headers && transport.headers.Host, Array.isArray(transport.host) ? transport.host[0] : transport.host),
      path: firstValue(transport.path),
      serviceName: firstValue(transport.service_name),
      flow: firstValue(outbound.flow),
    });
  }
  return profiles;
}

export function flattenJSONProfiles(obj: any): Array<{ profile: any; name: string }> {
  const profiles: Array<{ profile: any; name: string }> = [];
  const seen = new WeakSet();
  const pushProfile = (profile: any, name = '') => {
    if (!profile || typeof profile !== 'object') return;
    const resolvedName = name || profile.name || profile.remarks || profile.ps || profile.tag || '';
    const enriched = resolvedName && !profile.remarks && !profile.name ? { ...profile, remarks: resolvedName } : profile;
    profiles.push({ profile: enriched, name: resolvedName });
  };
  function visit(x: any, inheritedName = '') {
    if (!x || typeof x !== 'object') return;
    if (seen.has(x)) return;
    seen.add(x);
    if (Array.isArray(x)) {
      x.forEach(v => visit(v, inheritedName));
      return;
    }
    const name = x.name || x.remarks || x.ps || x.tag || inheritedName || '';
    let embeddedJsonParsed = false;
    if (typeof x.v2rayJson === 'string' && x.v2rayJson.trim()) {
      const embeddedCandidates = parseJSONCandidates(x.v2rayJson);
      embeddedJsonParsed = embeddedCandidates.length > 0;
      for (const embedded of embeddedCandidates) visit(embedded, name);
    } else if (x.v2rayJson && typeof x.v2rayJson === 'object') {
      const before = profiles.length;
      const embeddedCandidates = Array.isArray(x.v2rayJson) ? x.v2rayJson : [x.v2rayJson];
      for (const embedded of embeddedCandidates) visit(embedded, name);
      embeddedJsonParsed = profiles.length > before;
    }
    if (Array.isArray(x.outbounds)) {
      for (const outbound of x.outbounds) {
        const converted = outboundToProfiles(outbound, name);
        if (converted.length) converted.forEach(p => pushProfile(p, p.name || name));
        else visit(outbound, name);
      }
    }
    const asOutbound = outboundToProfiles(x, name);
    if (asOutbound.length) asOutbound.forEach(p => pushProfile(p, p.name || name));

    if (x.v2rayProfile && typeof x.v2rayProfile === 'object') {
      const vp = x.v2rayProfile;
      const vpName = firstValue(vp.remarks, vp.name, name);
      let vpEmbeddedJsonParsed = false;
      if (typeof vp.v2rayJson === 'string' && vp.v2rayJson.trim()) {
        const embeddedCandidates = parseJSONCandidates(vp.v2rayJson);
        vpEmbeddedJsonParsed = embeddedCandidates.length > 0;
        for (const embedded of embeddedCandidates) visit(embedded, vpName);
      } else if (vp.v2rayJson && typeof vp.v2rayJson === 'object') {
        const before = profiles.length;
        const embeddedCandidates = Array.isArray(vp.v2rayJson) ? vp.v2rayJson : [vp.v2rayJson];
        for (const embedded of embeddedCandidates) visit(embedded, vpName);
        vpEmbeddedJsonParsed = profiles.length > before;
      }
      if (!vpEmbeddedJsonParsed) {
        const enrichedVp = x.address && !vp.address ? { address: x.address, ...vp } : vp;
        pushProfile(enrichedVp, vpName);
      }
    }
    if (
      (x.server || x.add || x.address || x.serverAddress || x.host) &&
      (x.serverPort || x.port) &&
      (x.password || x.id || x.uuid || x.userId || x.method || x.protocol || x.configType)
    ) {
      if (!embeddedJsonParsed) pushProfile(x, name);
    }
    for (const [k, v] of Object.entries(x)) {
      if (k === 'v2rayProfile' || k === 'lockConfig' || k === 'outbounds' || k === 'streamSettings' || k === 'settings') continue;
      visit(v, name);
    }
  }
  visit(obj);
  return profiles;
}

export function isFastlyEndpoint(server: string, hostHeader: string, sni: string): boolean {
  const s = String(server || '').trim().toLowerCase();
  const h = String(hostHeader || '').trim().toLowerCase();
  const n = String(sni || '').trim().toLowerCase();
  if (
    s.startsWith('167.82.') ||
    s.startsWith('199.232.') ||
    s.startsWith('151.101.') ||
    s.startsWith('146.75.')
  ) {
    return true;
  }
  return (
    s.includes('fastly.net') ||
    s.includes('fastly.com') ||
    h.includes('fastly.net') ||
    h.includes('fastly.com') ||
    n.includes('fastly.net') ||
    n.includes('fastly.com')
  );
}

export function inspectTlsDomainFronting(
  server: string,
  hostHeader: string,
  sni: string,
  security: string
): {
  isFastly: boolean;
  hasMismatch: boolean;
  suggestedCertName: string;
  originalSni: string;
  reason: string;
} {
  const sec = String(security || '').toLowerCase();
  const origSni = String(sni || '').trim();
  const h = String(hostHeader || '').trim();
  const srv = String(server || '').trim();
  const isFastly = isFastlyEndpoint(srv, h, origSni);

  if (sec !== 'tls') {
    return { isFastly, hasMismatch: false, suggestedCertName: '', originalSni: origSni, reason: '' };
  }

  const sniLower = origSni.toLowerCase();
  const hostLower = h.toLowerCase();

  // Case 1: Fastly CDN endpoint where SNI is a fake domain (like firefox.com) not matching Fastly's wildcard certificate
  if (isFastly && sniLower && !sniLower.endsWith('.fastly.net') && !sniLower.endsWith('.fastly.com')) {
    return {
      isFastly: true,
      hasMismatch: true,
      suggestedCertName: 'default.ssl.fastly.net',
      originalSni: origSni,
      reason: `آی‌پی/هاست Fastly CDN با SNI فیک (${origSni}) — گواهی سرور فقط برای default.ssl.fastly.net معتبر است`
    };
  }

  // Case 2: General CDN Domain Fronting where SNI differs from WebSocket/HTTP Host header
  if (sniLower && hostLower && sniLower !== hostLower) {
    const certTarget = isFastly ? 'default.ssl.fastly.net' : h;
    return {
      isFastly,
      hasMismatch: true,
      suggestedCertName: certTarget,
      originalSni: origSni,
      reason: `عدم تطابق SNI (${origSni}) با هدر Host (${h}) در تکنیک Domain Fronting`
    };
  }

  return { isFastly, hasMismatch: false, suggestedCertName: '', originalSni: origSni, reason: '' };
}

export function normalizedProfile(p: any, fallbackName = '', tlsFixMode: TlsFixMode = 'auto-smart') {
  p = p || {};
  const fromAddr = splitHostPort(p.address || p.serverAddress || '');
  const streamLike: any = p.streamSettings ? streamSettingsToProfile(p.streamSettings) : {};
  const network = normalizeNetworkId(firstValue(p.network, p.net, streamLike.network, 'tcp'));
  const security = String(firstValue(p.security, p.streamSecurity, p.tls, streamLike.security, 'none')).toLowerCase();
  const remoteHost = firstValue(p.server, p.add, p.addressHost, fromAddr.host, p.host);
  const npvWsHost = firstValue(p.server, p.add, fromAddr.host) && p.host ? p.host : '';

  const rawSni = firstValue(p.sni, p.serverName, p.peer, streamLike.sni);
  const rawHostHeader = firstValue(p.hostHeader, p.requestHost, p.wsHost, p.hostName, p.headersHost, streamLike.hostHeader, npvWsHost);
  const explicitInsecure = truthyParam(firstValue(p.tlsAllowInsecure, p.insecure, p.allowInsecure, p.skipCertVerify, streamLike.insecure));
  const explicitVcn = firstValue(p.verifyPeerCertByName, p.vcn, streamLike.verifyPeerCertByName);

  const fronting = inspectTlsDomainFronting(remoteHost, rawHostHeader, rawSni, security);

  let finalSni = rawSni;
  let finalInsecure = explicitInsecure;
  let finalVcn = explicitVcn;
  let tlsFixed = false;
  let tlsFixNote = '';

  if (fronting.hasMismatch) {
    if (tlsFixMode === 'auto-smart') {
      finalInsecure = true;
      if (!finalVcn && fronting.suggestedCertName) {
        finalVcn = fronting.suggestedCertName;
      }
      tlsFixed = true;
      tlsFixNote = `${fronting.reason} ← فعال‌سازی خودکار allowInsecure=1 و vcn=${finalVcn}`;
    } else if (tlsFixMode === 'fastly-sni') {
      finalInsecure = true;
      if (fronting.suggestedCertName) {
        finalSni = fronting.suggestedCertName;
        finalVcn = fronting.suggestedCertName;
      }
      tlsFixed = true;
      tlsFixNote = `تغییر SNI از ${rawSni} به ${finalSni} برای تطابق مستقیم با گواهی x509 سرور`;
    }
  }

  return {
    name: cleanRemarkName(firstValue(p.remarks, p.ps, p.name, p.tag, fallbackName, 'NPVT Node')),
    host: remoteHost,
    port: String(firstValue(p.serverPort, p.port, fromAddr.port, '443')),
    id: firstValue(p.password, p.id, p.uuid, p.userId, p.pass),
    username: firstValue(p.username, p.user),
    password: firstValue(p.password, p.pass),
    method: firstValue(p.method, p.securityCipher, p.cipher, p.scy, p.encryption, 'none'),
    plugin: firstValue(p.plugin),
    pluginOpts: firstValue(p.pluginOpts, p.pluginOptions),
    alterId: String(firstValue(p.alterId, p.aid, '0')),
    network,
    headerType: firstValue(p.headerType, p.type, streamLike.headerType, 'none'),
    security,
    sni: finalSni,
    originalSni: rawSni,
    hostHeader: rawHostHeader,
    path: firstValue(p.path, p.requestPath, p.wsPath, streamLike.path),
    serviceName: firstValue(p.serviceName, p.grpcServiceName, streamLike.serviceName),
    authority: firstValue(p.authority, p.grpcAuthority, streamLike.authority),
    xhttpMode: firstValue(p.xhttpMode, p.mode, streamLike.xhttpMode),
    xhttpExtra: p.xhttpExtra || p.extra || streamLike.xhttpExtra || null,
    flow: firstValue(p.flow, streamLike.flow),
    fp: firstValue(p.fingerPrint, p.fingerprint, p.fp, streamLike.fp),
    publicKey: firstValue(p.publicKey, p.pbk, streamLike.publicKey),
    shortId: firstValue(p.shortId, p.shortIds, p.sid, streamLike.shortId),
    spiderX: firstValue(p.spiderX, p.spx, streamLike.spiderX),
    alpn: firstValue(p.alpn, streamLike.alpn),
    insecure: finalInsecure,
    pinnedPeerCertSha256: firstValue(p.pinnedPeerCertSha256, p.pcs, streamLike.pinnedPeerCertSha256),
    verifyPeerCertByName: finalVcn,
    tlsFixed,
    tlsFixNote,
    isFastly: fronting.isFastly,
    hasMismatch: fronting.hasMismatch,
    configType: p.configType,
    protocol: firstValue(p.protocol, p.configProtocol, p.outboundProtocol)
  };
}

export function detectProtocol(p: any): string {
  const proto = String(firstValue(p && p.protocol, p && p.configProtocol, p && p.outboundProtocol)).toLowerCase();
  const ctype = String((p && p.configType) ?? '').toLowerCase();
  if (proto.includes('vless')) return 'vless';
  if (proto.includes('vmess')) return 'vmess';
  if (proto.includes('trojan')) return 'trojan';
  if (proto.includes('shadow') || proto === 'ss') return 'ss';
  if (proto.includes('socks')) return 'socks';
  if (proto.includes('hysteria') || proto === 'hy2') return 'hysteria2';
  if (p && typeof p.v2rayJson === 'string' && p.v2rayJson.trim()) {
    try {
      const embedded = JSON.parse(p.v2rayJson);
      const obProto = String((embedded?.outbounds?.[0]?.protocol) || '').toLowerCase();
      if (obProto === 'vless') return 'vless';
      if (obProto === 'vmess') return 'vmess';
      if (obProto === 'trojan') return 'trojan';
      if (obProto === 'shadowsocks') return 'ss';
      if (obProto === 'socks') return 'socks';
    } catch (_) {}
  }
  if (ctype === '5') return 'vless';
  if (ctype === '6') return 'trojan';
  if (ctype === '3') return 'ss';
  if (ctype === '7') return 'socks';
  if (ctype === '1') return 'vmess';

  const n = normalizedProfile(p || {});
  if (n.username && n.password && !n.id) return 'socks';
  if (n.method && n.method !== 'none' && n.id && !isUuid(n.id)) return 'ss';
  if (n.alterId && String(n.alterId) !== '0' && isUuid(n.id)) return 'vmess';
  if (n.publicKey || n.flow || n.method === 'none') return isUuid(n.id) ? 'vless' : 'trojan';
  if (isUuid(n.id)) return 'vless';
  return 'trojan';
}

export function profileToLink(p: any, fallbackName = '', tlsFixMode: TlsFixMode = 'auto-smart'): string {
  const n = normalizedProfile(p, fallbackName, tlsFixMode);
  const protocol = detectProtocol(p);
  if (!n.host || !n.port) throw new Error('Missing server host or port');
  const tag = enc(n.name);

  if (protocol === 'vless') {
    if (!n.id) throw new Error('Missing VLESS UUID');
    const q: string[] = [];
    addParam(q, 'encryption', n.method && n.method !== 'auto' ? n.method : 'none');
    if (n.flow) addParam(q, 'flow', n.flow);
    addParam(q, 'security', n.security || 'none');
    addParam(q, 'type', n.network === 'http' || n.network === 'h2' ? 'h2' : n.network || 'tcp');
    if (n.headerType && n.headerType !== 'none' && n.network === 'tcp') addParam(q, 'headerType', n.headerType);
    if (n.sni) addParam(q, 'sni', n.sni);
    if (n.fp) addParam(q, 'fp', n.fp);
    if (n.publicKey) addParam(q, 'pbk', n.publicKey);
    if (n.shortId) addParam(q, 'sid', n.shortId);
    if (n.spiderX) addParam(q, 'spx', n.spiderX);
    if (n.alpn) addParam(q, 'alpn', n.alpn);
    if (n.hostHeader && ['ws', 'httpupgrade', 'splithttp', 'xhttp', 'http'].includes(n.network)) addParam(q, 'host', n.hostHeader);
    if (n.network === 'xhttp') {
      addParam(q, 'mode', n.xhttpMode);
      if (n.xhttpExtra) addParam(q, 'extra', JSON.stringify(n.xhttpExtra));
    }
    if (n.path) addParam(q, 'path', n.path);
    if (n.serviceName || n.network === 'grpc') addParam(q, 'serviceName', n.serviceName);
    if (n.authority && n.network === 'grpc') addParam(q, 'authority', n.authority);
    if (n.insecure) {
      addParam(q, 'allowInsecure', '1');
      addParam(q, 'insecure', '1');
    }
    if (n.verifyPeerCertByName) addParam(q, 'vcn', n.verifyPeerCertByName);
    if (n.pinnedPeerCertSha256) addParam(q, 'pcs', n.pinnedPeerCertSha256);
    return `vless://${enc(n.id)}@${formatUriHost(n.host)}:${n.port}${q.length ? '?' + q.join('&') : ''}#${tag}`;
  }

  if (protocol === 'vmess') {
    if (!n.id) throw new Error('Missing VMess UUID');
    const obj: any = {
      v: '2',
      ps: n.name,
      add: n.host,
      port: String(n.port),
      id: n.id,
      aid: String(n.alterId || '0'),
      scy: n.method && n.method !== 'none' ? n.method : 'auto',
      net: n.network || 'tcp',
      type: n.headerType || 'none',
      host: n.hostHeader || '',
      path: n.path || n.serviceName || '',
      tls: n.security && n.security !== 'none' ? n.security : '',
      sni: n.sni || '',
      fp: n.fp || '',
      alpn: n.alpn || '',
      ...(n.insecure ? { insecure: '1', allowInsecure: true } : {}),
      ...(n.verifyPeerCertByName ? { vcn: n.verifyPeerCertByName, verifyPeerCertByName: n.verifyPeerCertByName } : {})
    };
    return `vmess://${base64Utf8(JSON.stringify(obj))}`;
  }

  if (protocol === 'trojan') {
    if (!n.id) throw new Error('Missing Trojan password');
    const q: string[] = [];
    addParam(q, 'type', n.network === 'http' || n.network === 'h2' ? 'h2' : n.network || 'tcp');
    addParam(q, 'security', n.security && n.security !== 'none' ? n.security : 'tls');
    if (n.sni) addParam(q, 'sni', n.sni);
    if (n.fp) addParam(q, 'fp', n.fp);
    if (n.hostHeader && ['ws', 'httpupgrade', 'splithttp', 'xhttp', 'http'].includes(n.network)) addParam(q, 'host', n.hostHeader);
    if (n.network === 'xhttp' || n.network === 'splithttp') {
      addParam(q, 'mode', n.xhttpMode);
      if (n.xhttpExtra) addParam(q, 'extra', JSON.stringify(n.xhttpExtra));
    }
    if (n.path) addParam(q, 'path', n.path);
    if (n.serviceName && n.network === 'grpc') addParam(q, 'serviceName', n.serviceName);
    if (n.alpn) addParam(q, 'alpn', n.alpn);
    if (n.insecure) {
      addParam(q, 'allowInsecure', '1');
      addParam(q, 'insecure', '1');
    }
    if (n.verifyPeerCertByName) addParam(q, 'vcn', n.verifyPeerCertByName);
    if (n.pinnedPeerCertSha256) addParam(q, 'pcs', n.pinnedPeerCertSha256);
    return `trojan://${enc(n.id)}@${formatUriHost(n.host)}:${n.port}${q.length ? '?' + q.join('&') : ''}#${tag}`;
  }

  if (protocol === 'ss') {
    const method = n.method && n.method !== 'none' ? n.method : 'aes-128-gcm';
    if (!n.id) throw new Error('Missing Shadowsocks password');
    const userInfo = method.startsWith('2022-') ? `${enc(method)}:${enc(n.id)}` : base64UrlUtf8(`${method}:${n.id}`);
    const pluginQuery = n.plugin ? `?plugin=${enc(n.plugin + (n.pluginOpts ? `;${n.pluginOpts}` : ''))}` : '';
    return `ss://${userInfo}@${formatUriHost(n.host)}:${n.port}${pluginQuery}#${tag}`;
  }

  if (protocol === 'socks') {
    const auth = n.username && n.password ? `${enc(n.username)}:${enc(n.password)}@` : '';
    return `socks://${auth}${formatUriHost(n.host)}:${n.port}#${tag}`;
  }

  throw new Error(`Unsupported protocol: ${protocol}`);
}

export function parseShareLinkToProfile(link: string): any {
  const str = String(link || '').trim();
  const proto = (str.split('://')[0] || '').toLowerCase();

  if (proto === 'vmess') {
    const payload = str.replace(/^vmess:\/\//i, '').trim();
    const obj = JSON.parse(bytesToText(b64ToBytes(payload)));
    const rawSec = firstValue(obj.tls, obj.streamSecurity, obj.netSecurity);
    const security = ['tls', 'reality', 'none'].includes(String(rawSec).toLowerCase()) ? String(rawSec).toLowerCase() : 'none';
    const net = normalizeNetworkId(firstValue(obj.net, 'tcp'));
    return {
      protocol: 'vmess',
      name: cleanRemarkName(obj.ps, 'VMess Node'),
      server: firstValue(obj.add, obj.host),
      serverPort: String(firstValue(obj.port, obj.serverPort, '443')),
      password: firstValue(obj.id, obj.uuid),
      method: firstValue(obj.scy, obj.security, 'auto'),
      alterId: firstValue(obj.aid, obj.alterId, '0'),
      network: net,
      headerType: firstValue(obj.type, 'none'),
      host: firstValue(obj.host, obj.requestHost),
      path: net === 'grpc' ? '' : firstValue(obj.path, ''),
      serviceName: net === 'grpc' ? firstValue(obj.path, obj.serviceName, '') : '',
      security,
      sni: firstValue(obj.sni, obj.peer),
      alpn: firstValue(obj.alpn),
      fingerPrint: firstValue(obj.fp, obj.fingerprint),
      insecure: truthyParam(firstValue(obj.allowInsecure, obj.insecure, obj.tlsAllowInsecure)),
      verifyPeerCertByName: firstValue(obj.vcn, obj.verifyPeerCertByName)
    };
  }

  if (proto === 'ss') {
    let body = str.replace(/^ss:\/\//i, '');
    let hash = '';
    const hashIdx = body.indexOf('#');
    if (hashIdx >= 0) {
      hash = body.slice(hashIdx + 1);
      body = body.slice(0, hashIdx);
    }
    let query = '';
    const qIdx = body.indexOf('?');
    if (qIdx >= 0) {
      query = body.slice(qIdx + 1);
      body = body.slice(0, qIdx);
    }
    body = body.replace(/\/$/, '');
    const ssParams = new URLSearchParams(query);
    const pluginRaw = String(ssParams.get('plugin') || '').trim();
    const pluginParts = pluginRaw.split(';');
    const plugin = pluginParts[0] || '';
    const pluginOpts = pluginParts.slice(1).join(';');
    let userInfo = '', hostPort = '';
    const at = body.lastIndexOf('@');
    if (at >= 0) {
      userInfo = body.slice(0, at);
      hostPort = body.slice(at + 1);
      if (!userInfo.includes(':')) {
        try { userInfo = bytesToText(b64ToBytes(userInfo)); } catch (_) {}
      }
    } else {
      const decoded = bytesToText(b64ToBytes(body));
      const at2 = decoded.lastIndexOf('@');
      if (at2 < 0) throw new Error('Invalid Shadowsocks URI');
      userInfo = decoded.slice(0, at2);
      hostPort = decoded.slice(at2 + 1);
    }
    const sep = userInfo.indexOf(':');
    if (sep < 0) throw new Error('Invalid Shadowsocks credentials');
    const method = decodeUriStrict(userInfo.slice(0, sep));
    const password = decodeUriStrict(userInfo.slice(sep + 1));
    const hp = splitHostPortLoose(hostPort);
    return {
      protocol: 'ss',
      name: cleanRemarkName(hash, 'Shadowsocks'),
      server: hp.host,
      serverPort: String(hp.port || '443'),
      password,
      method: method || 'aes-128-gcm',
      plugin,
      pluginOpts,
      network: 'tcp',
      security: 'none'
    };
  }

  const url = new URL(str);
  const q: Record<string, string> = {};
  for (const [k, v] of url.searchParams.entries()) q[k] = v;
  const name = cleanRemarkName(url.hash ? url.hash.slice(1) : '', proto.toUpperCase());
  const hasSecurity = url.searchParams.has('security') || url.searchParams.has('tls');
  let parsedSecurity = hasSecurity ? firstValue(q.security, q.tls) : '';
  if (!parsedSecurity && proto === 'trojan') parsedSecurity = 'tls';
  const parsedNetwork = firstValue(q.type, q.net, q.network, 'tcp');

  const common: any = {
    protocol: proto,
    name,
    server: url.hostname.replace(/^\[|\]$/g, ''),
    serverPort: String(url.port || q.port || (parsedSecurity === 'tls' || parsedSecurity === 'reality' ? '443' : '80')),
    password: decodeUriStrict(url.username || ''),
    method: firstValue(q.encryption, q.securityCipher, q.method, proto === 'vless' ? 'none' : 'auto'),
    network: parsedNetwork,
    headerType: firstValue(q.headerType, q.header, 'none'),
    host: firstValue(q.host, q.requestHost),
    path: firstValue(q.path, url.pathname && url.pathname !== '/' ? url.pathname : ''),
    serviceName: firstValue(q.serviceName, q.grpcServiceName),
    authority: firstValue(q.authority),
    security: parsedSecurity || 'none',
    sni: firstValue(q.sni, q.peer, q.serverName),
    alpn: firstValue(q.alpn),
    flow: firstValue(q.flow),
    fingerPrint: firstValue(q.fp, q.fingerprint),
    publicKey: firstValue(q.pbk, q.publicKey),
    shortId: firstValue(q.sid, q.shortId, q.shortIds),
    spiderX: firstValue(q.spx, q.spiderX),
    insecure: truthyParam(firstValue(q.allowInsecure, q.insecure, q.tlsAllowInsecure)),
    verifyPeerCertByName: firstValue(q.vcn, q.verifyPeerCertByName),
    pinnedPeerCertSha256: firstValue(q.pcs, q.pinnedPeerCertSha256),
    xhttpMode: firstValue(q.mode),
    xhttpExtra: (() => {
      try {
        return q.extra ? JSON.parse(q.extra) : null;
      } catch {
        return null;
      }
    })()
  };
  if (proto === 'socks') {
    common.username = decodeUriStrict(url.username || '');
    common.password = decodeUriStrict(url.password || '');
  }
  return common;
}

export function buildXrayJsonForProfile(p: any, tlsFixMode: TlsFixMode = 'auto-smart'): any {
  const n = normalizedProfile(p, '', tlsFixMode);
  const protocol = detectProtocol(p);
  const port = Number(n.port) || 443;

  const streamSettings: any = {
    network: n.network || 'tcp',
    security: n.security || 'none'
  };

  if (n.security === 'tls') {
    streamSettings.tlsSettings = {
      allowInsecure: Boolean(n.insecure),
      serverName: n.sni || n.hostHeader || n.host,
      ...(n.verifyPeerCertByName ? { verifyPeerCertByName: n.verifyPeerCertByName } : {}),
      ...(n.pinnedPeerCertSha256 ? { pinnedPeerCertSha256: n.pinnedPeerCertSha256 } : {}),
      ...(n.alpn ? { alpn: n.alpn.split(',').map((x: string) => x.trim()).filter(Boolean) } : {}),
      ...(n.fp ? { fingerprint: n.fp } : {})
    };
  } else if (n.security === 'reality') {
    streamSettings.realitySettings = {
      show: false,
      serverName: n.sni || '',
      fingerprint: n.fp || 'chrome',
      publicKey: n.publicKey || '',
      shortId: n.shortId || '',
      spiderX: n.spiderX || '/'
    };
  }

  if (n.network === 'ws') {
    streamSettings.wsSettings = {
      path: n.path || '/',
      headers: n.hostHeader ? { Host: n.hostHeader } : {}
    };
  } else if (n.network === 'grpc') {
    streamSettings.grpcSettings = {
      serviceName: n.serviceName || '',
      authority: n.authority || '',
      multiMode: false
    };
  } else if (n.network === 'tcp' && n.headerType && n.headerType !== 'none') {
    const header: any = { type: n.headerType };
    if (n.headerType === 'http') {
      header.request = {
        path: [n.path || '/'],
        ...(n.hostHeader ? { headers: { Host: [n.hostHeader] } } : {})
      };
    }
    streamSettings.tcpSettings = { header };
  } else if (n.network === 'httpupgrade') {
    streamSettings.httpupgradeSettings = {
      path: n.path || '/',
      ...(n.hostHeader ? { host: n.hostHeader } : {})
    };
  } else if (n.network === 'xhttp' || n.network === 'splithttp') {
    streamSettings.network = 'xhttp';
    streamSettings.xhttpSettings = {
      path: n.path || '/',
      ...(n.hostHeader ? { host: n.hostHeader } : {}),
      ...(n.xhttpMode ? { mode: n.xhttpMode } : {}),
      ...(n.xhttpExtra ? { extra: n.xhttpExtra } : {})
    };
  } else if (n.network === 'http' || n.network === 'h2') {
    streamSettings.network = 'h2';
    streamSettings.httpSettings = {
      path: n.path || '/',
      ...(n.hostHeader ? { host: [n.hostHeader] } : {})
    };
  }

  let settings: any = {};
  if (protocol === 'vless') {
    settings = {
      vnext: [{
        address: n.host,
        port,
        users: [{
          id: n.id,
          encryption: n.method && n.method !== 'auto' ? n.method : 'none',
          ...(n.flow ? { flow: n.flow } : {}),
          level: 8
        }]
      }]
    };
  } else if (protocol === 'vmess') {
    settings = {
      vnext: [{
        address: n.host,
        port,
        users: [{
          id: n.id,
          alterId: Number(n.alterId) || 0,
          security: n.method && n.method !== 'none' ? n.method : 'auto',
          level: 8
        }]
      }]
    };
  } else if (protocol === 'trojan') {
    settings = {
      servers: [{
        address: n.host,
        port,
        password: n.id,
        level: 8
      }]
    };
  } else if (protocol === 'ss') {
    settings = {
      servers: [{
        address: n.host,
        port,
        method: n.method && n.method !== 'none' ? n.method : 'aes-128-gcm',
        password: n.id,
        level: 8
      }]
    };
  } else if (protocol === 'socks') {
    settings = {
      servers: [{
        address: n.host,
        port,
        ...(n.username ? { users: [{ user: n.username, pass: n.password || '' }] } : {})
      }]
    };
  }

  return {
    remarks: n.name,
    log: { loglevel: 'warning' },
    inbounds: [
      {
        tag: 'socks',
        port: 10808,
        listen: '127.0.0.1',
        protocol: 'socks',
        settings: { auth: 'noauth', udp: true, userLevel: 8 },
        sniffing: { enabled: true, destOverride: ['http', 'tls'] }
      },
      {
        tag: 'http',
        port: 10809,
        listen: '127.0.0.1',
        protocol: 'http',
        settings: { userLevel: 8 }
      }
    ],
    outbounds: [
      {
        tag: 'proxy',
        protocol: protocol === 'ss' ? 'shadowsocks' : protocol,
        settings,
        streamSettings,
        mux: { enabled: false, concurrency: -1 }
      },
      { tag: 'direct', protocol: 'freedom', settings: {} },
      { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'http' } } }
    ]
  };
}

export function buildSingBoxJsonForProfile(p: any, tlsFixMode: TlsFixMode = 'auto-smart'): any {
  const n = normalizedProfile(p, '', tlsFixMode);
  const protocol = detectProtocol(p);
  const port = Number(n.port) || 443;

  const outbound: any = {
    type: protocol === 'ss' ? 'shadowsocks' : protocol,
    tag: n.name || 'proxy',
    server: n.host,
    server_port: port
  };

  if (protocol === 'vless') {
    outbound.uuid = n.id;
    if (n.flow) outbound.flow = n.flow;
  } else if (protocol === 'vmess') {
    outbound.uuid = n.id;
    outbound.security = n.method && n.method !== 'none' ? n.method : 'auto';
    outbound.alter_id = Number(n.alterId) || 0;
  } else if (protocol === 'trojan') {
    outbound.password = n.id;
  } else if (protocol === 'ss') {
    outbound.method = n.method && n.method !== 'none' ? n.method : 'aes-128-gcm';
    outbound.password = n.id;
    if (n.plugin) outbound.plugin = n.plugin;
    if (n.pluginOpts) outbound.plugin_opts = n.pluginOpts;
  } else if (protocol === 'socks') {
    if (n.username) outbound.username = n.username;
    if (n.password) outbound.password = n.password;
  }

  if (n.security === 'tls' || n.security === 'reality') {
    outbound.tls = {
      enabled: true,
      server_name: n.sni || n.hostHeader || n.host,
      insecure: Boolean(n.insecure),
      ...(n.alpn ? { alpn: n.alpn.split(',').map((x: string) => x.trim()).filter(Boolean) } : {}),
      ...(n.fp ? { utls: { enabled: true, fingerprint: n.fp } } : {}),
      ...(n.security === 'reality' ? {
        reality: {
          enabled: true,
          public_key: n.publicKey || '',
          short_id: n.shortId || ''
        }
      } : {})
    };
  }

  if (n.network === 'ws') {
    outbound.transport = {
      type: 'ws',
      path: n.path || '/',
      ...(n.hostHeader ? { headers: { Host: n.hostHeader } } : {})
    };
  } else if (n.network === 'grpc') {
    outbound.transport = {
      type: 'grpc',
      service_name: n.serviceName || ''
    };
  } else if (n.network === 'httpupgrade') {
    outbound.transport = {
      type: 'httpupgrade',
      host: n.hostHeader || n.host,
      path: n.path || '/'
    };
  } else if (n.network === 'http' || n.network === 'h2') {
    outbound.transport = {
      type: 'http',
      host: n.hostHeader ? [n.hostHeader] : [n.host],
      path: n.path || '/'
    };
  } else if ((n.network === 'xhttp' || n.network === 'splithttp') && n.path) {
    outbound.transport = {
      type: 'httpupgrade',
      host: n.hostHeader || n.host,
      path: n.path
    };
  }

  return {
    log: { level: 'warn', timestamp: true },
    inbounds: [
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: 2080,
        sniff: true
      }
    ],
    outbounds: [
      outbound,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' }
    ]
  };
}

export function buildClashYamlForProfile(p: any, tlsFixMode: TlsFixMode = 'auto-smart'): string {
  const n = normalizedProfile(p, '', tlsFixMode);
  const protocol = detectProtocol(p);
  const port = Number(n.port) || 443;

  const lines: string[] = [
    `proxies:`,
    `  - name: ${JSON.stringify(n.name)}`,
    `    type: ${protocol === 'socks' ? 'socks5' : protocol}`,
    `    server: ${JSON.stringify(n.host)}`,
    `    port: ${port}`,
    `    udp: true`
  ];

  if (protocol === 'vless' || protocol === 'vmess') {
    lines.push(`    uuid: ${JSON.stringify(n.id)}`);
    if (protocol === 'vmess') {
      lines.push(`    alterId: ${Number(n.alterId) || 0}`);
      lines.push(`    cipher: ${JSON.stringify(n.method && n.method !== 'none' ? n.method : 'auto')}`);
    }
    if (n.flow) lines.push(`    flow: ${JSON.stringify(n.flow)}`);
  } else if (protocol === 'trojan' || protocol === 'ss') {
    lines.push(`    password: ${JSON.stringify(n.id)}`);
    if (protocol === 'ss') {
      lines.push(`    cipher: ${JSON.stringify(n.method && n.method !== 'none' ? n.method : 'aes-128-gcm')}`);
      if (n.plugin) {
        const pluginName = String(n.plugin).toLowerCase();
        const optMap = new Map<string, string>();
        String(n.pluginOpts || '')
          .split(';')
          .map((x) => x.trim())
          .filter(Boolean)
          .forEach((part) => {
            const eq = part.indexOf('=');
            if (eq >= 0) optMap.set(part.slice(0, eq), part.slice(eq + 1));
            else optMap.set(part, 'true');
          });
        if (pluginName === 'obfs-local' || pluginName === 'obfs') {
          lines.push(`    plugin: obfs`);
          lines.push(`    plugin-opts:`);
          if (optMap.get('obfs')) lines.push(`      mode: ${JSON.stringify(optMap.get('obfs'))}`);
          if (optMap.get('obfs-host')) lines.push(`      host: ${JSON.stringify(optMap.get('obfs-host'))}`);
        } else if (pluginName === 'v2ray-plugin') {
          lines.push(`    plugin: v2ray-plugin`);
          lines.push(`    plugin-opts:`);
          lines.push(`      mode: "websocket"`);
          if (optMap.has('tls')) lines.push(`      tls: true`);
          if (optMap.get('host')) lines.push(`      host: ${JSON.stringify(optMap.get('host'))}`);
          if (optMap.get('path')) lines.push(`      path: ${JSON.stringify(optMap.get('path'))}`);
          if (optMap.has('mux')) lines.push(`      mux: true`);
        }
      }
    }
  } else if (protocol === 'socks') {
    if (n.username) lines.push(`    username: ${JSON.stringify(n.username)}`);
    if (n.password) lines.push(`    password: ${JSON.stringify(n.password)}`);
  }

  if (n.security === 'tls' || n.security === 'reality') {
    lines.push(`    tls: true`);
    if (n.sni) lines.push(`    servername: ${JSON.stringify(n.sni)}`);
    if (n.fp) lines.push(`    client-fingerprint: ${JSON.stringify(n.fp)}`);
    if (n.insecure) lines.push(`    skip-cert-verify: true`);
    if (n.alpn) {
      const alpnList = n.alpn.split(',').map((x: string) => x.trim()).filter(Boolean);
      if (alpnList.length) lines.push(`    alpn: [${alpnList.map((a: string) => JSON.stringify(a)).join(', ')}]`);
    }
    if (n.security === 'reality') {
      lines.push(`    reality-opts:`);
      lines.push(`      public-key: ${JSON.stringify(n.publicKey || '')}`);
      if (n.shortId) lines.push(`      short-id: ${JSON.stringify(n.shortId)}`);
    }
  }

  if (n.network && n.network !== 'tcp') {
    const clashNetwork = n.network === 'xhttp' || n.network === 'splithttp' ? 'httpupgrade' : n.network;
    lines.push(`    network: ${JSON.stringify(clashNetwork)}`);
    if (n.network === 'ws' || n.network === 'httpupgrade') {
      lines.push(`    ${clashNetwork}-opts:`);
      lines.push(`      path: ${JSON.stringify(n.path || '/')}`);
      if (n.hostHeader) {
        lines.push(`      headers:`);
        lines.push(`        Host: ${JSON.stringify(n.hostHeader)}`);
      }
    } else if (n.network === 'grpc') {
      lines.push(`    grpc-opts:`);
      lines.push(`      grpc-service-name: ${JSON.stringify(n.serviceName || '')}`);
    } else if (n.network === 'http' || n.network === 'h2') {
      lines.push(`    h2-opts:`);
      if (n.hostHeader) lines.push(`      host: [${JSON.stringify(n.hostHeader)}]`);
      lines.push(`      path: ${JSON.stringify(n.path || '/')}`);
    }
  }

  return lines.join('\n');
}

function defaultNpvLockConfig() {
  return {
    version: 1,
    isLocked: true,
    password: '',
    onlyMobileNetwork: false,
    blockRootedAndJailbroken: true,
    onlyOfficialStores: false,
    expiryDate: '',
    deviceIds: '',
    message: '',
    customServerMessage: ''
  };
}

function configTypeForProtocol(proto: string): number {
  if (proto === 'vless') return 5;
  if (proto === 'trojan') return 6;
  if (proto === 'ss' || proto === 'shadowsocks') return 3;
  if (proto === 'socks') return 7;
  return 1; // vmess
}

export function encryptNPVTChunk(plain: string, customNonce?: Uint8Array): string {
  const nonce = customNonce || new Uint8Array(16);
  if (!customNonce) {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(nonce);
    } else {
      for (let i = 0; i < 16; i++) nonce[i] = (i * 17 + 43) & 255;
    }
  }
  const pt = textToBytes(String(plain || ''));
  const ct = ctrCrypt(nonce, pt);
  const box = new Uint8Array(16 + ct.length);
  box.set(nonce, 0);
  box.set(ct, 16);
  return bytesToBase64(box);
}

export function buildNPVTContainerFromLinks(links: string[]): string {
  const profiles = links.map((link, index) => {
    const p = parseShareLinkToProfile(link);
    const proto = detectProtocol(p);
    const xrayObj = buildXrayJsonForProfile(p);
    const v2: any = {
      configVersion: 4,
      configType: configTypeForProtocol(proto),
      subscriptionId: '',
      addedTime: Date.now() + index,
      remarks: p.name || `Node ${index + 1}`,
      server: p.server,
      serverPort: String(p.serverPort),
      password: p.password || '',
      method: p.method || (proto === 'vmess' ? 'auto' : 'none'),
      plugin: p.plugin || '',
      pluginOpts: p.pluginOpts || '',
      network: p.network || 'tcp',
      headerType: p.headerType || 'none',
      security: p.security || 'none',
      host: p.host || '',
      path: p.path || '',
      sni: p.sni || '',
      fingerPrint: p.fingerPrint || '',
      insecure: Boolean(p.insecure),
      verifyPeerCertByName: p.verifyPeerCertByName || '',
      pinnedPeerCertSha256: p.pinnedPeerCertSha256 || '',
      alpn: p.alpn || '',
      flow: p.flow || '',
      publicKey: p.publicKey || '',
      shortId: p.shortId || '',
      spiderX: p.spiderX || '',
      serviceName: p.serviceName || '',
      authority: p.authority || '',
      xhttpMode: p.xhttpMode || '',
      xhttpExtra: p.xhttpExtra || null,
      v2rayJson: JSON.stringify(xrayObj),
      persistJson: false
    };
    return {
      name: v2.remarks,
      address: `${v2.server}:${v2.serverPort}`,
      type: 'V2RAY',
      v2rayProfile: v2,
      lockConfig: defaultNpvLockConfig()
    };
  });

  const versionChunk = encryptNPVTChunk('1');
  const profilesChunk = encryptNPVTChunk(JSON.stringify(profiles));
  const lockChunk = encryptNPVTChunk(JSON.stringify(defaultNpvLockConfig()));
  return `NPVT1\n${versionChunk},${profilesChunk},${lockChunk}`;
}

export function inspectNpvsV5(bytes: Uint8Array) {
  if (bytes.length < 160 || String.fromCharCode(...bytes.slice(0, 4)) !== 'NPVS') {
    throw new Error('Not an NPVS binary envelope');
  }
  const version = bytes[4];
  if (version !== 5) throw new Error(`NPVS version ${version} is not supported`);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerLength = view.getUint32(5, false);
  if (headerLength < 135 || 9 + headerLength + 16 + 64 > bytes.length) {
    throw new Error('Malformed NPVS header size');
  }
  const header = bytes.subarray(9, 9 + headerLength);
  const method = header[50];
  const recipients = (header[51] << 8) | header[52];
  const keySectionEnd = 53 + recipients * (32 + 93);
  const iterations = method === 1 ? new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(keySectionEnd, false) : undefined;
  const unlockMethod = method === 0 ? 'Device Hardware ID Lock (Private Key)' : method === 1 ? 'Creator Passphrase (PBKDF2)' : 'App-Bound Key';
  return {
    version,
    unlockMethod,
    recipients,
    iterations,
    bytes: bytes.length
  };
}

function createConvertedNode(
  profileObj: any,
  source: string,
  idx: number,
  tlsFixMode: TlsFixMode = 'auto-smart'
): ConvertedNode {
  const n = normalizedProfile(profileObj, '', tlsFixMode);
  const proto = detectProtocol(profileObj);
  const link = profileToLink(profileObj, n.name, tlsFixMode);
  const fastlyFixedLink = n.hasMismatch ? profileToLink(profileObj, n.name, 'fastly-sni') : undefined;
  const xrayObj = buildXrayJsonForProfile(profileObj, tlsFixMode);
  const singBoxObj = buildSingBoxJsonForProfile(profileObj, tlsFixMode);
  const clashYaml = buildClashYamlForProfile(profileObj, tlsFixMode);

  return {
    id: `${proto}-${idx}-${n.host}-${n.port}`,
    name: n.name,
    protocol: proto.toUpperCase(),
    server: n.host,
    port: n.port,
    network: (n.network || 'tcp').toUpperCase(),
    security: (n.security || 'none').toUpperCase(),
    sni: n.sni || '',
    originalSni: n.originalSni || '',
    hostHeader: n.hostHeader || '',
    path: n.path || n.serviceName || '',
    alpn: n.alpn || '',
    fp: n.fp || '',
    pbk: n.publicKey || '',
    sid: n.shortId || '',
    spx: n.spiderX || '',
    flow: n.flow || '',
    uuidOrPassword: n.id || n.password || '',
    method: n.method || '',
    insecure: Boolean(n.insecure),
    vcn: n.verifyPeerCertByName || '',
    tlsFixed: Boolean(n.tlsFixed),
    tlsFixNote: n.tlsFixNote || '',
    isFastly: Boolean(n.isFastly),
    link,
    fastlyFixedLink,
    xrayJson: JSON.stringify(xrayObj, null, 2),
    singBoxJson: JSON.stringify(singBoxObj, null, 2),
    clashYaml,
    source
  };
}

function extractSshProfilesFromObj(obj: any): Array<any> {
  const sshList: any[] = [];
  const seen = new WeakSet();
  function visit(x: any) {
    if (!x || typeof x !== 'object' || seen.has(x)) return;
    seen.add(x);
    if (Array.isArray(x)) {
      x.forEach(visit);
      return;
    }
    if (x.sshConfig && typeof x.sshConfig === 'object') {
      const sc = x.sshConfig;
      sshList.push({
        name: firstValue(x.name, sc.remarks, 'SSH Tunnel'),
        host: firstValue(sc.sshHost, sc.host, sc.server),
        port: String(firstValue(sc.sshPort, sc.port, '22')),
        username: firstValue(sc.sshUsername, sc.username, sc.user),
        password: firstValue(sc.sshPassword, sc.password),
        payload: firstValue(sc.payload),
        sni: firstValue(sc.sni, sc.sslSni)
      });
    }
    for (const val of Object.values(x)) visit(val);
  }
  visit(obj);
  return sshList;
}

function parseSshLinkToProfile(link: string): any | null {
  try {
    const u = new URL(link);
    if (u.protocol !== 'ssh:') return null;
    return {
      name: cleanRemarkName(u.searchParams.get('remarks') || 'SSH Tunnel', 'SSH Tunnel'),
      host: u.hostname,
      port: String(u.port || '22'),
      username: safeDecodeURIComponent(u.username || ''),
      password: safeDecodeURIComponent(u.password || ''),
      payload: u.hash ? safeDecodeURIComponent(u.hash.slice(1)) : '',
      sni: u.searchParams.get('sni') || ''
    };
  } catch {
    return null;
  }
}

export function convertAnyConfigInput(
  text: string,
  sourceName = 'Input',
  rawBytes?: Uint8Array,
  passphrase = '',
  tlsFixMode: TlsFixMode = 'auto-smart'
): ConversionResult {
  const result: ConversionResult = {
    detectedFormat: 'نامشخص',
    nodes: [],
    sshProfiles: [],
    decryptedChunks: [],
    npvsInspection: null,
    tlsMismatchCount: 0,
    errors: [],
    notes: []
  };

  const trimmed = String(text || '').trim();
  const seenLinks = new Set<string>();
  let nodeCounter = 0;

  const pushNodeFromProfile = (prof: any, src: string) => {
    try {
      const node = createConvertedNode(prof, src, ++nodeCounter, tlsFixMode);
      if (!seenLinks.has(node.link)) {
        seenLinks.add(node.link);
        result.nodes.push(node);
        if (node.tlsFixed || (node.originalSni && node.originalSni !== node.sni)) {
          result.tlsMismatchCount = (result.tlsMismatchCount || 0) + 1;
        }
      }
    } catch (e: any) {
      result.errors.push(`${src}: ${e.message}`);
    }
  };

  const pushNodeFromLink = (link: string, src: string) => {
    const cleanLink = String(link || '').trim();
    if (!cleanLink) return;
    if (/^ssh:\/\//i.test(cleanLink)) {
      const sshProf = parseSshLinkToProfile(cleanLink);
      if (sshProf) result.sshProfiles.push(sshProf);
      return;
    }
    try {
      const prof = parseShareLinkToProfile(cleanLink);
      pushNodeFromProfile(prof, src);
    } catch (e: any) {
      result.errors.push(`Link parse (${src}): ${e.message}`);
    }
  };

  const absorbPlain = (rawPlain: string, label: string) => {
    const plain = decodeNpvSentinels(String(rawPlain || ''));

    // Check for ssh:// links
    const sshMatches = plain.match(/ssh:\/\/[^\s"'<>]+/gi) || [];
    for (const sLink of sshMatches) {
      pushNodeFromLink(sLink, label);
    }

    for (const link of extractRawLinks(plain)) {
      pushNodeFromLink(link, label);
    }
    const sub = tryDecodeBase64Text(plain);
    if (sub) {
      const decodedSub = decodeNpvSentinels(sub);
      result.notes.push(`${label}: اشتراک Base64 رمزگشایی شد`);
      for (const link of extractRawLinks(decodedSub)) pushNodeFromLink(link, `${label} (Base64)`);
      for (const cand of parseJSONCandidates(decodedSub)) {
        const cleanCand = deepDecodeSentinels(cand);
        for (const item of flattenJSONProfiles(cleanCand)) pushNodeFromProfile(item.profile, `${label} (JSON)`);
        result.sshProfiles.push(...extractSshProfilesFromObj(cleanCand));
      }
    }
    for (const cand of parseJSONCandidates(plain)) {
      const cleanCand = deepDecodeSentinels(cand);
      if (cleanCand && Array.isArray(cleanCand.configs)) {
        for (const cfg of cleanCand.configs) {
          for (const item of flattenJSONProfiles(cfg)) pushNodeFromProfile(item.profile, `${label} (NPVO1)`);
          result.sshProfiles.push(...extractSshProfilesFromObj(cfg));
        }
      } else {
        for (const item of flattenJSONProfiles(cleanCand)) pushNodeFromProfile(item.profile, label);
        result.sshProfiles.push(...extractSshProfilesFromObj(cleanCand));
      }
    }
  };

  // Detect binary NPVS either from rawBytes OR from Base64-encoded "TlBWUw..." in text
  let candidateBytes = rawBytes;
  if (!candidateBytes || candidateBytes.length < 4 || candidateBytes[0] !== 78 || candidateBytes[1] !== 80 || candidateBytes[2] !== 86 || candidateBytes[3] !== 83) {
    const compactText = trimmed.replace(/^NPVS[:\s-]*/i, '').replace(/\s+/g, '');
    if (/^TlBWUw/i.test(compactText)) {
      const decodedB64 = b64UrlOrStdToBytes(compactText);
      if (decodedB64 && decodedB64.length >= 16 && decodedB64[0] === 78 && decodedB64[1] === 80 && decodedB64[2] === 86 && decodedB64[3] === 83) {
        candidateBytes = decodedB64;
      }
    }
  }

  // Handle NPVS v5 (Gen-2 Compact Binary Envelope) & NPVS v1 (JSON Header Envelope)
  if (candidateBytes && candidateBytes.length >= 4 && candidateBytes[0] === 78 && candidateBytes[1] === 80 && candidateBytes[2] === 86 && candidateBytes[3] === 83) {
    if (isNpvGen2Bytes(candidateBytes)) {
      try {
        result.npvsInspection = inspectNpvsV5(candidateBytes);
      } catch {
        // Continue to decryptor even if inspection helper warns
      }
      const dec = decryptNpvGen2Envelope(candidateBytes, passphrase);
      result.recoveredKeys = dec.recoveredKeys;
      result.creatorMessage = dec.creatorMessage;
      result.needsPassphrase = dec.needsPassphrase;

      if (dec.ok) {
        if (result.npvsInspection) result.npvsInspection.decrypted = true;
        result.detectedFormat = `NPVS v5 (نسل ۵ — رمزگشایی کامل Gen-2 ${dec.unlockMethod === 'passphrase' ? 'PBKDF2' : 'White-Box AppKey'})`;
        result.notes.push('کانتینر نسل ۵ (NPVS v5 Compact Envelope) با موفقیت بازگشایی و کلیدهای ChaCha20-Poly1305 استخراج شدند.');

        // Prioritize rawConfigObjects so all native fields (tlsAllowInsecure, host, sni, etc.) are preserved accurately
        if (Array.isArray(dec.rawConfigObjects) && dec.rawConfigObjects.length > 0) {
          result.decryptedChunks.push({
            index: 'NPVS-v5-JSON',
            text: JSON.stringify(dec.rawConfigObjects, null, 2)
          });
          for (const cfg of dec.rawConfigObjects) {
            for (const item of flattenJSONProfiles(cfg)) pushNodeFromProfile(item.profile, 'NPVS v5');
            result.sshProfiles.push(...extractSshProfilesFromObj(cfg));
          }
        }
        if (result.nodes.length === 0 && result.sshProfiles.length === 0) {
          if (Array.isArray(dec.links)) {
            for (const link of dec.links) pushNodeFromLink(link, 'NPVS v5');
          }
          if (dec.decryptedText) {
            absorbPlain(dec.decryptedText, 'NPVS v5');
          }
        }
        if (dec.decryptedText && result.decryptedChunks.length === 0) {
          result.decryptedChunks.push({ index: 'NPVS-v5', text: dec.decryptedText });
        }
        return result;
      } else {
        result.detectedFormat = `NPVS v5 (نسل ۵ — ${dec.needsPassphrase ? 'نیازمند رمز عبور' : 'قفل کانتینر'})`;
        if (dec.error) result.errors.push(dec.error);
        return result;
      }
    } else if (isNpvV1Bytes(candidateBytes)) {
      const dec = decryptNpvV1Envelope(candidateBytes, passphrase);
      result.recoveredKeys = dec.recoveredKeys;
      result.creatorMessage = dec.creatorMessage;
      result.needsPassphrase = dec.needsPassphrase;
      if (dec.ok) {
        result.detectedFormat = `NPVS v1 (رمزگشایی کامل ChaCha20-Poly1305)`;
        result.notes.push('کانتینر NPVS v1 با موفقیت رمزگشایی شد.');
        if (Array.isArray(dec.rawConfigObjects) && dec.rawConfigObjects.length > 0) {
          result.decryptedChunks.push({
            index: 'NPVS-v1-JSON',
            text: JSON.stringify(dec.rawConfigObjects, null, 2)
          });
          for (const cfg of dec.rawConfigObjects) {
            for (const item of flattenJSONProfiles(cfg)) pushNodeFromProfile(item.profile, 'NPVS v1');
            result.sshProfiles.push(...extractSshProfilesFromObj(cfg));
          }
        }
        if (result.nodes.length === 0 && result.sshProfiles.length === 0) {
          if (dec.decryptedText) absorbPlain(dec.decryptedText, 'NPVS v1');
          if (Array.isArray(dec.links)) {
            for (const link of dec.links) pushNodeFromLink(link, 'NPVS v1');
          }
        }
        return result;
      } else {
        result.detectedFormat = `NPVS v1 (${dec.needsPassphrase ? 'نیازمند رمز عبور' : 'خطای بازگشایی'})`;
        if (dec.error) result.errors.push(dec.error);
        return result;
      }
    }
  }

  if (!trimmed) {
    result.errors.push('ورودی خالی است. لطفاً محتوای کانفیگ یا فایل .npvt / .npvs خود را وارد کنید.');
    return result;
  }

  // Check NetMod (.nm or nm-*://) encrypted configs
  if (/^nm-[a-z0-9]+:\/\//i.test(trimmed) || sourceName.toLowerCase().endsWith('.nm')) {
    const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    let anyNetMod = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = line.match(/^(nm-[a-z0-9]+):\/\/(.+)$/i);
      const payload = m ? m[2] : line;
      const dec = decryptNetModPayload(payload);
      if (dec) {
        anyNetMod = true;
        result.detectedFormat = `NetMod VPN (رمزگشایی AES-128-ECB با کلید ${dec.key})`;
        result.recoveredKeys = { ...(result.recoveredKeys || {}), 'NetMod AES Key': dec.key };
        result.decryptedChunks.push({ index: `NM#${i + 1}`, text: dec.text });
        absorbPlain(dec.text, `NetMod#${i + 1}`);
      }
    }
    if (anyNetMod) return result;
  }

  // 1. Check NPVO1 open export
  if (/^NPVO1(?:\s|$)/i.test(trimmed)) {
    result.detectedFormat = 'NPVO1 (کانفیگ باز NPV Tunnel + رمزگشایی Sentinel)';
    const jsonBody = trimmed.replace(/^NPVO1\s*/i, '').trim();
    const cleanBody = decodeNpvSentinels(jsonBody);
    result.decryptedChunks.push({ index: 'NPVO1', text: cleanBody });
    absorbPlain(cleanBody, 'NPVO1');
  }

  // 2. Check NPVT1 encrypted tokens
  const forceNPVT = sourceName.toLowerCase().endsWith('.npvt') || sourceName.toLowerCase().endsWith('.npv4') || /(?:NPVT(?:SUB)?1|npvt:\/\/|npv-tunnel:\/\/)/i.test(trimmed);
  const tokens = extractNPVTTokens(trimmed, forceNPVT);
  if (tokens.length > 0) {
    result.detectedFormat = 'NPVT1 Encrypted Container (فایل رمزنگاری شده NPV Tunnel)';
    for (let i = 0; i < tokens.length; i++) {
      try {
        const chunks = decodeNPVTPlainChunks(tokens[i]);
        for (const chunk of chunks) {
          result.decryptedChunks.push({ index: `${i + 1}.${chunk.part}`, text: chunk.text });
          absorbPlain(chunk.text, `NPVT#${i + 1}`);
        }
      } catch (e: any) {
        result.errors.push(`خطا در رمزگشایی قطعه ${i + 1}: ${e.message}`);
      }
    }
  } else if (forceNPVT && rawBytes && rawBytes.length > 16) {
    try {
      const plain = bytesToText(decryptNPVTBytes(rawBytes)).replace(/\0+$/g, '').trim();
      if (plain) {
        result.detectedFormat = 'Binary NPVT Container';
        result.decryptedChunks.push({ index: '1.1', text: plain });
        absorbPlain(plain, 'Binary NPVT');
      }
    } catch (e: any) {
      result.errors.push(`Binary NPVT fallback: ${e.message}`);
    }
  }

  // 3. Also absorb any direct JSON, Share Links, or Base64 subscriptions
  if (!tokens.length && !/^NPVO1/i.test(trimmed)) {
    absorbPlain(trimmed, sourceName);
    if (result.nodes.length > 0 || result.sshProfiles.length > 0) {
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        result.detectedFormat = 'Xray / V2Ray / NPV JSON Profile';
      } else if (extractRawLinks(trimmed).length > 0) {
        result.detectedFormat = 'V2Ray Share URI Links';
      } else {
        result.detectedFormat = 'Base64 Subscription';
      }
    }
  }

  if (result.nodes.length === 0 && result.sshProfiles.length === 0 && !result.npvsInspection && result.errors.length === 0) {
    result.errors.push('هیچ نود V2Ray (VLESS / VMess / Trojan / Shadowsocks) یا کانتینر معتبری در ورودی یافت نشد.');
  }

  return result;
}

export function buildNPVSV5ContainerFromLinks(
  links: string[],
  options?: { passphrase?: string; displayMessage?: string }
): { bytes: Uint8Array; base64: string } | null {
  const configs = links.map((link, index) => {
    const p = parseShareLinkToProfile(link);
    const proto = detectProtocol(p);
    return {
      name: p.name || `NPVS v5 Node ${index + 1}`,
      address: p.server,
      type: 'V2RAY',
      v2rayProfile: {
        configVersion: 5,
        configType: configTypeForProtocol(proto),
        remarks: p.name || `NPVS v5 Node ${index + 1}`,
        server: p.server,
        serverPort: String(p.serverPort || '443'),
      password: p.password || '',
      method: p.method || (proto === 'vmess' ? 'auto' : 'none'),
      plugin: p.plugin || '',
      pluginOpts: p.pluginOpts || '',
      alterId: String(p.alterId || '0'),
      network: p.network || 'tcp',
      headerType: p.headerType || 'none',
      security: p.security || 'none',
      host: p.host || '',
      path: p.path || '',
      sni: p.sni || '',
      fingerPrint: p.fingerPrint || '',
      tlsAllowInsecure: Boolean(p.insecure),
      verifyPeerCertByName: p.verifyPeerCertByName || '',
      pinnedPeerCertSha256: p.pinnedPeerCertSha256 || '',
      alpn: p.alpn || '',
      flow: p.flow || '',
      publicKey: p.publicKey || '',
      shortId: p.shortId || '',
      spiderX: p.spiderX || '',
      serviceName: p.serviceName || '',
      authority: p.authority || '',
      xhttpMode: p.xhttpMode || '',
      xhttpExtra: p.xhttpExtra || null
      }
    };
  });

  const bytes = buildNpvGen2Container(configs, options);
  if (!bytes) return null;
  return {
    bytes,
    base64: bytesToBase64(bytes)
  };
}

// Generate a real sample encrypted NPVT1 config with 3 realistic V2Ray nodes for instant testing
export function getSampleNPVTConfig(): string {
  const sampleLinks = [
    'vless://a3b8d920-41e5-4f88-9a1e-8c7b6f5d4e3a@de-fra-01.cdn-edge.example.com:443?encryption=none&security=tls&sni=de-fra-01.cdn-edge.example.com&fp=chrome&type=ws&host=de-fra-01.cdn-edge.example.com&path=%2Fgraphql-stream#Germany%20Frankfurt%20VLESS%20WS',
    'vless://b4c9e031-52f6-4a99-8b2f-9d8c7a6e5f4b@nl-ams-reality.core-node.example.net:8443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=safari&pbk=mK9xLp3qR7vW2zY5nJ8bH4cF1gT6dS0wA9eU3iO2pL8&sid=4f8a2b1c&spx=%2F&type=tcp#Netherlands%20REALITY%20Direct',
    'vmess://' + base64Utf8(JSON.stringify({
      v: '2',
      ps: 'Finland Helsinki VMess gRPC',
      add: 'fi-hel-02.relay-net.example.org',
      port: '2053',
      id: 'c5d0f142-63a7-4b00-9c3a-0e9d8b7f6a5c',
      aid: '0',
      scy: 'auto',
      net: 'grpc',
      type: 'gun',
      host: '',
      path: 'v2ray-grpc-service',
      tls: 'tls',
      sni: 'fi-hel-02.relay-net.example.org',
      fp: 'chrome',
      alpn: 'h2'
    }))
  ];
  return buildNPVTContainerFromLinks(sampleLinks);
}

// Generate a real sample encrypted NPVS v5 (Gen-2 Compact Binary Envelope) config including Fastly CDN Domain-Fronting node
export function getSampleNPVSV5Config(): { bytes: Uint8Array; base64: string } | null {
  const sampleLinks = [
    'vless://d1e2f3a4-5678-49ab-9cde-f0123456789a@167.82.64.46:443?encryption=none&security=tls&sni=firefox.com&fp=chrome&type=ws&host=npv5-relay.global.ssl.fastly.net&path=%2Fws-fastly#NPVS-v5%20Fastly%20CDN%20WS%20TLS',
    'vless://e2f3a4b5-6789-4abc-8def-0123456789ab@de-v5-reality.npv-edge.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=mK9xLp3qR7vW2zY5nJ8bH4cF1gT6dS0wA9eU3iO2pL8&sid=6ba85179e30d4fc2&type=tcp#NPVS-v5%20Germany%20REALITY%20Vision',
    'trojan://NpvV5SecretPass2026@199.232.78.160:443?security=tls&sni=firefox.com&fp=firefox&type=ws&host=edge-tr01.global.ssl.fastly.net&path=%2Ftrojan-ws#NPVS-v5%20Fastly%20Edge%20Trojan%20WS'
  ];
  return buildNPVSV5ContainerFromLinks(sampleLinks, {
    displayMessage: 'کانفیگ اختصاصی نسل پنجم (NPVS v5 Gen-2 Compact Envelope) — مجهز به سیستم رفع خودکار خطای گواهی x509 فستلی (firefox.com)'
  });
}

