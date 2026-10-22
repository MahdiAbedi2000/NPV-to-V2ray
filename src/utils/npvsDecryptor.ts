// @ts-nocheck
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { tyBoxes, mbl, tboxesLastV1, tboxesLastV2, xorTable, shiftOrder } from './npvCryptoTables.ts';
import { b64ToBytes, bytesToText, textToBytes } from './npvConverter.ts';
import { GEN2_TABLES_B64 } from '../assets/gen2TablesB64.ts';

const NPV_GEN2_BLOCK_SIZE = 57344;
const NPV_GEN2_BLOCK_COUNT = 13;
const NPV_GEN2_PAGE_SIZE = 4096;
const NPV_GEN2_TABLES_SIZE = NPV_GEN2_BLOCK_COUNT * NPV_GEN2_BLOCK_SIZE + NPV_GEN2_PAGE_SIZE; // 749,568 bytes
const NPV_GEN2_APPKEY_LABEL = 'npvtunnel/appkey/v2 ';
const NPV_V4_APPKEY_LABEL = 'npvtunnel/appkey/v1 ';

let cachedGen2Tables: Uint8Array | null = null;

export function setGen2TablesForTest(tables: Uint8Array): void {
  cachedGen2Tables = tables;
}

export async function loadNpvGen2Tables(): Promise<Uint8Array> {
  if (cachedGen2Tables && cachedGen2Tables.length === NPV_GEN2_TABLES_SIZE) {
    return cachedGen2Tables;
  }

  const compressedB64 = GEN2_TABLES_B64.replace(/\s+/g, '');

  // Browser: inflate via DecompressionStream('deflate').
  // Pipe the source through the stream: writing into the writer directly can
  // deadlock because the readable side must be consumed while writes settle.
  if (typeof DecompressionStream !== 'undefined' && typeof atob === 'function') {
    const bin = atob(compressedB64);
    const compressed = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) compressed[i] = bin.charCodeAt(i);
    const source = new Response(compressed.slice().buffer).body;
    if (!source) throw new Error('خطا در رمزگشایی جداول Gen2');
    const inflated = source.pipeThrough(new DecompressionStream('deflate'));
    const outBuffer = await new Response(inflated).arrayBuffer();
    cachedGen2Tables = new Uint8Array(outBuffer);
    if (cachedGen2Tables.length !== NPV_GEN2_TABLES_SIZE) {
      throw new Error(`اندازه جدول Gen2 نامعتبر است: ${cachedGen2Tables.length}`);
    }
    return cachedGen2Tables;
  }

  // Node.js environment fallback for unit tests
  const zlib = await import('node:zlib');
  const compressedNode = Buffer.from(compressedB64, 'base64');
  const inflatedNode = zlib.inflateSync(compressedNode);
  cachedGen2Tables = new Uint8Array(inflatedNode.buffer, inflatedNode.byteOffset, inflatedNode.byteLength);
  return cachedGen2Tables;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

async function pbkdf2HmacSha256(passphrase: string, salt: Uint8Array, iterations: number, dkLen = 32): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    textToBytes(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt,
      iterations
    },
    baseKey,
    dkLen * 8
  );
  return new Uint8Array(bits);
}

async function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length = 32): Promise<Uint8Array> {
  const effectiveSalt = salt.length ? salt : new Uint8Array(32);
  const baseKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: effectiveSalt,
      info
    },
    baseKey,
    length * 8
  );
  return new Uint8Array(bits);
}

export function chachaOpen(key: Uint8Array, nonce: Uint8Array, ctTag: Uint8Array, aad?: Uint8Array): Uint8Array {
  const aead = chacha20poly1305(key, nonce, aad);
  return aead.decrypt(ctTag);
}

// --- NPVS v4 (JSON header) White-Box KDK Derivation ---
function wbBlockWithTlast(block: Uint8Array, tlastTable: number[][]): Uint8Array {
  let buf = new Uint8Array(16);
  for (let i = 0; i < 16; i++) buf[i] = block[shiftOrder[i]];
  for (let grp = 0; grp < 4; grp++) {
    const base = grp * 4;
    const a = tyBoxes[base + 0][buf[base + 0]] >>> 0;
    const b = tyBoxes[base + 1][buf[base + 1]] >>> 0;
    const c = tyBoxes[base + 2][buf[base + 2]] >>> 0;
    const d = tyBoxes[base + 3][buf[base + 3]] >>> 0;
    for (let k = 0; k < 4; k++) {
      const t = grp * 24 + k * 6;
      const hi = 28 - 8 * k;
      const lo = 24 - 8 * k;
      const p1 = xorTable[t][(a >>> hi) & 15][(b >>> hi) & 15];
      const p2 = xorTable[t + 1][(c >>> hi) & 15][(d >>> hi) & 15];
      const p3 = xorTable[t + 2][(a >>> lo) & 15][(b >>> lo) & 15];
      const p4 = xorTable[t + 3][(c >>> lo) & 15][(d >>> lo) & 15];
      buf[base + k] = (xorTable[t + 4][p1][p2] << 4) | xorTable[t + 5][p3][p4];
    }
    const a2 = mbl[base + 0][buf[base + 0]] >>> 0;
    const b2 = mbl[base + 1][buf[base + 1]] >>> 0;
    const c2 = mbl[base + 2][buf[base + 2]] >>> 0;
    const d2 = mbl[base + 3][buf[base + 3]] >>> 0;
    for (let k = 0; k < 4; k++) {
      const t = grp * 24 + k * 6;
      const hi = 28 - 8 * k;
      const lo = 24 - 8 * k;
      const p1 = xorTable[t][(a2 >>> hi) & 15][(b2 >>> hi) & 15];
      const p2 = xorTable[t + 1][(c2 >>> hi) & 15][(d2 >>> hi) & 15];
      const p3 = xorTable[t + 2][(a2 >>> lo) & 15][(b2 >>> lo) & 15];
      const p4 = xorTable[t + 3][(c2 >>> lo) & 15][(d2 >>> lo) & 15];
      buf[base + k] = (xorTable[t + 4][p1][p2] << 4) | xorTable[t + 5][p3][p4];
    }
  }
  const shifted = new Uint8Array(16);
  for (let i = 0; i < 16; i++) shifted[i] = buf[shiftOrder[i]];
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = tlastTable[i][shifted[i]];
  return out;
}

export async function custodianKDKs(salt: Uint8Array): Promise<Uint8Array[]> {
  const material = new Uint8Array(32);
  material.set(salt.subarray(0, 16), 0);
  const prefix = textToBytes(NPV_V4_APPKEY_LABEL);
  const kdks: Uint8Array[] = [];

  for (const tlast of [tboxesLastV1, tboxesLastV2]) {
    const counter = new Uint8Array(material.subarray(0, 16));
    const ct = material.subarray(16);
    const stream = new Uint8Array(ct.length);
    for (let i = 0; i < ct.length; i += 16) {
      const ks = wbBlockWithTlast(counter, tlast);
      const n = Math.min(ct.length - i, 16);
      for (let j = 0; j < n; j++) stream[i + j] = ct[i + j] ^ ks[j];
      for (let p = 15; p >= 0; p--) {
        counter[p] = (counter[p] + 1) & 255;
        if (counter[p] !== 0) break;
      }
    }
    const sum = await sha256Bytes(concatBytes(prefix, stream));
    kdks.push(sum);
  }
  return kdks;
}

// --- NPVS v5 Gen-2 White-Box A16 & KDK Derivation ---
function npvGen2BE32(block: Uint8Array, off: number): number {
  return (
    ((block[off] << 24) |
      (block[off + 1] << 16) |
      (block[off + 2] << 8) |
      block[off + 3]) >>>
    0
  );
}

function npvGen2GroupArgs(block: Uint8Array, half: number, j: number, s: Uint8Array): [number, number, number, number] {
  const base = half + 0x1000 * j;
  return [
    npvGen2BE32(block, base + 4 * s[0]),
    npvGen2BE32(block, base + 0x400 + 4 * s[1]),
    npvGen2BE32(block, base + 0x800 + 4 * s[2]),
    npvGen2BE32(block, base + 0xc00 + 4 * s[3])
  ];
}

function npvGen2Sub7DC0(
  block: Uint8Array,
  i: number,
  in3: number,
  in4: number,
  in5: number,
  in6: number
): Uint8Array {
  const m32 = (v: number) => v >>> 0;
  const at = (addr: number) => block[addr >>> 0];
  const out = new Uint8Array(4);

  let x0 = 0, x8 = 0, x9 = 0, x10 = 0, x11 = 0, x12 = 0, x13 = 0, x14 = 0, x15 = 0, x16 = 0, x17 = 0;
  const x2 = i >>> 0;
  const x3 = m32(in3);
  const x4 = m32(in4);
  const x5 = m32(in5);
  const x6 = m32(in6);

  x8 = m32(x2 + m32(x2 << 1));
  x12 = m32(x3 >>> 0x14);
  x11 = m32(x3 >>> 0x18);
  x13 = (x4 >>> 0x18) & 0xf;
  x14 = m32(x5 >>> 0x18);
  x10 = x6;
  x9 = m32(x8 << 3);
  x8 = x4;
  x12 &= 0xf0;
  x12 = m32(x12 + x13);
  x13 = m32(x5 >>> 0x14);
  x16 = x8 >>> 0x1c;
  x9 = m32(x9);
  x11 &= 0xf0;
  x14 &= 0xf0;
  x15 = m32(x6 >>> 0x18) & 0xf;
  x13 &= 0xf0;
  x17 = m32(x3 >>> 0x10);
  x9 = m32(x9 << 8);
  x8 &= 0xf;
  x13 = m32(x13 + x15);
  x17 &= 0xf0;
  x11 = m32(x9 + x11);
  x14 = m32(x9 + x14);
  x12 = m32(x9 + x12);
  x16 = at(x11 + x16);
  x14 = m32(x14 + (x10 >>> 28));
  x12 = at(x12 + 0x200);
  x13 = m32(x9 + x13);
  x0 = m32(x6 >>> 0x14) & 0xf;
  x14 = at(x14 + 0x100);
  x15 = m32(x9 + (x16 << 4));
  x13 = at(x13 + 0x300);
  x12 = m32(x9 + (x12 << 4));
  x16 = m32(x4 >>> 0x14) & 0xf;
  x10 &= 0xf;
  x14 = m32(x15 + x14);
  x15 = m32(x5 >>> 0x10);
  x12 = m32(x12 + x13);
  x13 = m32(x3 >>> 0xc);
  x14 = at(x14 + 0x400);
  x12 = at(x12 + 0x500);
  x15 &= 0xf0;
  x16 = m32(x17 + x16);
  x15 = m32(x15 + x0);
  x0 = m32(x4 >>> 0x10) & 0xf;
  x17 = m32(x5 >>> 0xc);
  x12 = (x12 | (x14 << 4)) >>> 0;
  x13 &= 0xf0;
  x14 = m32(x6 >>> 0x10) & 0xf;
  x13 = m32(x13 + x0);
  x17 &= 0xf0;
  x16 = m32(x9 + x16);
  out[0] = x12 & 0xff;
  x13 = m32(x9 + x13);
  x12 = m32(x17 + x14);
  x14 = at(x16 + 0x600);
  x13 = at(x13 + 0x800);
  x15 = m32(x9 + x15);
  x12 = m32(x9 + x12);
  x15 = at(x15 + 0x700);
  x16 = m32(x5 >>> 8);
  x12 = at(x12 + 0x900);
  x14 = m32(x9 + (x14 << 4));
  x13 = m32(x9 + (x13 << 4));
  x0 = m32(x6 >>> 0xc) & 0xf;
  x17 = m32(x3 >>> 8);
  x14 = m32(x14 + x15);
  x12 = m32(x13 + x12);
  x13 = x16 & 0xf0;
  x14 = at(x14 + 0xa00);
  x12 = at(x12 + 0xb00);
  x15 = m32(x3 >>> 4);
  x13 = m32(x13 + x0);
  x0 = m32(x4 >>> 8) & 0xf;
  x16 = m32(x4 >>> 0xc) & 0xf;
  x12 = (x12 | (x14 << 4)) >>> 0;
  x14 = x15 & 0xf0;
  x17 &= 0xf0;
  x14 = m32(x14 + x0);
  x15 = m32(x9 + 0xc00);
  x0 = m32(x5 >>> 4);
  x17 = m32(x15 + x17);
  out[1] = x12 & 0xff;
  x12 = m32(x6 >>> 8) & 0xf;
  x16 = at(x17 + x16);
  x14 = m32(x9 + x14);
  x17 = x0 & 0xf0;
  x14 = at(x14 + 0xe00);
  x12 = m32(x17 + x12);
  x13 = m32(x15 + x13);
  x12 = m32(x9 + x12);
  x13 = at(x13 + 0x100);
  x15 = m32(x9 + (x16 << 4));
  x12 = at(x12 + 0xf00);
  x14 = m32(x9 + (x14 << 4));
  x16 = 0x1000;
  x13 = m32(x15 + x13);
  x17 = m32(x6 >>> 4) & 0xf;
  x0 = x5 & 0xf0;
  x12 = m32(x14 + x12);
  x14 = 0x1100;
  x13 = at(x13 + x16);
  x12 = at(x12 + x14);
  x14 = 0x1200;
  x15 = m32(x4 >>> 4) & 0xf;
  x16 = x3 & 0xf0;
  x17 = m32(x0 + x17);
  x14 = m32(x9 + x14);
  x12 = (x12 | (x13 << 4)) >>> 0;
  x13 = ((x3 & 0xf) << 4) >>> 0;
  x16 = m32(x14 + x16);
  out[2] = x12 & 0xff;
  x8 = m32(x13 + x8);
  x12 = m32(x14 + x17);
  x14 = ((x5 & 0xf) << 4) >>> 0;
  x13 = at(x16 + x15);
  x8 = m32(x9 + x8);
  x15 = 0x1400;
  x12 = at(x12 + 0x100);
  x8 = at(x8 + x15);
  x10 = m32(x14 + x10);
  x14 = 0x1500;
  x10 = m32(x9 + x10);
  x13 = m32(x9 + (x13 << 4));
  x10 = at(x10 + x14);
  x8 = m32(x9 + (x8 << 4));
  x9 = m32(x13 + x12);
  x12 = 0x1600;
  x8 = m32(x8 + x10);
  x10 = 0x1700;
  x9 = at(x9 + x12);
  x8 = at(x8 + x10);
  x8 = (x8 | (x9 << 4)) >>> 0;
  out[3] = x8 & 0xff;
  return out;
}

export async function npvGen2A16(salt: Uint8Array): Promise<Uint8Array> {
  if (salt.length !== 16) throw new Error(`طول Salt در Gen2 باید ۱۶ بایت باشد`);
  const tables = await loadNpvGen2Tables();
  let state = new Uint8Array(salt);

  for (let b = 0; b < NPV_GEN2_BLOCK_COUNT; b++) {
    const block = tables.subarray(b * NPV_GEN2_BLOCK_SIZE, (b + 1) * NPV_GEN2_BLOCK_SIZE);
    const shifted = new Uint8Array(16);
    for (let i = 0; i < 16; i++) shifted[i] = state[shiftOrder[i]];
    state = shifted;

    for (let j = 0; j < 4; j++) {
      const slice = state.subarray(4 * j, 4 * j + 4);
      let args = npvGen2GroupArgs(block, 0x6000, j, slice);
      let written = npvGen2Sub7DC0(block, j, args[0], args[1], args[2], args[3]);
      state.set(written, 4 * j);

      const slice2 = state.subarray(4 * j, 4 * j + 4);
      args = npvGen2GroupArgs(block, 0xa000, j, slice2);
      written = npvGen2Sub7DC0(block, j, args[0], args[1], args[2], args[3]);
      state.set(written, 4 * j);
    }
  }

  const page = tables.subarray(NPV_GEN2_BLOCK_COUNT * NPV_GEN2_BLOCK_SIZE);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = page[0x100 * i + state[shiftOrder[i]]];
  }
  return out;
}

export async function npvGen2KDK(a16: Uint8Array, configID: Uint8Array): Promise<Uint8Array> {
  return sha256Bytes(concatBytes(textToBytes(NPV_GEN2_APPKEY_LABEL), a16, configID));
}

const SENTINEL_PREFIX = 'npvs1:';
const SENTINEL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-';

export function decodeNpvSentinels(s: string): string {
  let out = '';
  let rest = String(s || '');
  while (true) {
    const idx = rest.indexOf(SENTINEL_PREFIX);
    if (idx < 0) {
      out += rest;
      return out;
    }
    out += rest.slice(0, idx);
    rest = rest.slice(idx + SENTINEL_PREFIX.length);
    let j = 0;
    while (j < rest.length && SENTINEL_ALPHABET.includes(rest[j])) j++;
    const tok = rest.slice(0, j);
    rest = rest.slice(j);
    try {
      const dec = bytesToText(b64ToBytes(tok));
      out += dec;
    } catch (_) {
      out += SENTINEL_PREFIX + tok;
    }
  }
}

function readBE16(b: Uint8Array, off: number): number {
  return (b[off] << 8) | b[off + 1];
}

function readBE32(b: Uint8Array, off: number): number {
  return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}

function writeBE16(v: number): Uint8Array {
  return new Uint8Array([(v >>> 8) & 0xff, v & 0xff]);
}

function writeBE32(v: number): Uint8Array {
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
}

function npvGen2FieldText(raw: Uint8Array): string {
  if (!raw) return '';
  const s = bytesToText(raw).trim();
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    try {
      const parsed = JSON.parse(s);
      if (typeof parsed === 'string') return parsed;
    } catch (_) {}
    return s.slice(1, -1);
  }
  return s;
}

function npvGen2Substitute(v: any, fields: Map<number, Uint8Array>): any {
  if (typeof v === 'number' && Number.isInteger(v)) {
    const raw = fields.get(v);
    if (!raw) return '';
    return decodeNpvSentinels(npvGen2FieldText(raw));
  }
  if (Array.isArray(v)) {
    return v.map((item) => npvGen2Substitute(item, fields));
  }
  if (v && typeof v === 'object') {
    const out: Record<string, any> = {};
    for (const [k, val] of Object.entries(v)) {
      out[k] = npvGen2Substitute(val, fields);
    }
    return out;
  }
  if (typeof v === 'string') {
    return decodeNpvSentinels(v);
  }
  return v;
}

export interface NpvsDecryptResult {
  version: number;
  unlockMethod: 'app-key' | 'passphrase' | 'recipient-key';
  needsPassphrase: boolean;
  decryptedJsonText?: string;
  configs?: any[];
  creatorMessage?: string;
  metadata?: any;
  keyMaterial: Array<{ label: string; value: string }>;
}

export async function decryptNPVSContainer(bytes: Uint8Array, password = ''): Promise<NpvsDecryptResult> {
  if (bytes.length < 89 || String.fromCharCode(...bytes.subarray(0, 4)) !== 'NPVS') {
    throw new Error('این فایل یک کانتینر باینری NPVS نیست.');
  }

  const version = bytes[4];
  const hdrLen = readBE32(bytes, 5);
  if (hdrLen < 20 || 9 + hdrLen > bytes.length) {
    throw new Error(`طول هدر NPVS نامعتبر است: ${hdrLen}`);
  }

  const header = bytes.subarray(9, 9 + hdrLen);

  // Branch 1: NPVS v5 Compact Binary Header (Gen-2)
  if (version === 5) {
    if (header[0] !== 1) {
      throw new Error(`نسخه هدر فشرده NPVS v5 (${header[0]}) پشتیبانی نمی‌شود.`);
    }
    const configID = header.subarray(1, 17);
    const creator = header.subarray(17, 50);
    const method = header[50]; // 0 = Recipient, 1 = Passphrase, 2 = AppKey
    const recipients = readBE16(header, 51);
    let off = 53 + recipients * (32 + 0x5d);

    let iters = 0;
    let salt = new Uint8Array(0);
    let wrap = new Uint8Array(0);

    if (method === 1) {
      if (off + 80 + 4 > header.length) throw new Error('بلوک رمز عبور در NPVS v5 ناقص است.');
      iters = readBE32(header, off);
      salt = header.subarray(off + 4, off + 20);
      wrap = header.subarray(off + 20, off + 80);
      off += 80;
    } else if (method === 2) {
      if (off + 78 + 4 > header.length) throw new Error('بلوک AppKey در NPVS v5 ناقص است.');
      salt = header.subarray(off + 2, off + 18);
      wrap = header.subarray(off + 18, off + 78);
      off += 78;
    }

    const metaLen = readBE32(header, off);
    const prefix = header.subarray(0, off);
    const metaBlob = header.subarray(off + 4, off + 4 + metaLen);

    let bodyOff = 9 + hdrLen;
    const nonce = bytes.subarray(bodyOff, bodyOff + 12);
    const bodyLen = readBE32(bytes, bodyOff + 12);
    bodyOff += 16;
    const body = bytes.subarray(bodyOff, bodyOff + bodyLen);

    const keyMaterial: Array<{ label: string; value: string }> = [
      { label: 'configId', value: bytesToHex(configID) },
      { label: 'creator.pk', value: bytesToHex(creator) }
    ];

    if (method === 0) {
      throw new Error(
        `این کانفیگ NPVS v5 با قفل سخت‌افزاری دستگاه (Method 0 - ECDH برای ${recipients} گیرنده) بسته شده و فقط روی گوشی ثبت‌شده که کلید خصوصی را دارد باز می‌شود.`
      );
    }

    let kdk: Uint8Array;
    if (method === 2) {
      const a16 = await npvGen2A16(salt);
      kdk = await npvGen2KDK(a16, configID);
      keyMaterial.push({ label: 'appKey A16 (Gen-2 White-Box)', value: bytesToHex(a16) });
    } else if (method === 1) {
      if (!password) {
        const err: any = new Error('این کانفیگ NPVS v5 دارای رمز عبور (Passphrase) است. لطفاً رمز عبور کانفیگ را در کادر رمز وارد کنید تا بازگشایی شود.');
        err.needsPassphrase = true;
        throw err;
      }
      kdk = await pbkdf2HmacSha256(password, salt, iters, 32);
      keyMaterial.push({ label: 'KDF', value: `PBKDF2-HMAC-SHA256 (${iters} iterations)` });
    } else {
      throw new Error(`روش قفل ناشناخته در NPVS v5: ${method}`);
    }

    let dek: Uint8Array;
    try {
      dek = chachaOpen(kdk, wrap.subarray(0, 12), wrap.subarray(12), salt);
    } catch (_) {
      if (method === 1) {
        const err: any = new Error('رمز عبور (Passphrase) وارد شده برای این فایل NPVS v5 نادرست است.');
        err.needsPassphrase = true;
        throw err;
      }
      throw new Error('خطا در بازگشایی کلید DEK با کلید AppKey نسل پنجم.');
    }

    const metaKey = await hkdfSha256(dek, nonce, textToBytes('NPVS-v5/metadata'));
    const metadataBytes = chachaOpen(metaKey, nonce, metaBlob, prefix);
    let metadataObj: any = {};
    try {
      metadataObj = JSON.parse(bytesToText(metadataBytes));
    } catch (_) {}

    // Parse NPF\x01 body
    if (body.length < 38 || String.fromCharCode(...body.subarray(0, 4)) !== 'NPF\x01') {
      throw new Error('ساختار بدنه NPF در فایل NPVS v5 نامعتبر است.');
    }
    const contentID = body.subarray(4, 36);
    const count = readBE16(body, 36);
    let fOff = 38;
    const fields = new Map<number, Uint8Array>();

    for (let idx = 0; idx < count; idx++) {
      if (fOff + 6 > body.length) break;
      const seq = readBE16(body, fOff);
      const blobLen = readBE16(body, fOff + 4);
      const blob = body.subarray(fOff + 6, fOff + 6 + blobLen);
      fOff += 6 + blobLen;

      const ptLen = blob.length - 16;
      if (ptLen < 0) continue;

      const fieldInfo = concatBytes(textToBytes('NPV-fields-v1/field/'), writeBE16(seq));
      const fieldKey = await hkdfSha256(dek, contentID, fieldInfo);
      const aad = concatBytes(
        textToBytes('NPV-fields-v1/record/'),
        contentID,
        writeBE16(seq),
        writeBE32(ptLen)
      );
      try {
        const pt = chachaOpen(fieldKey, new Uint8Array(12), blob, aad);
        fields.set(seq, pt);
      } catch (_) {}
    }

    keyMaterial.push(
      { label: 'contentId', value: bytesToHex(contentID) },
      { label: 'KDK', value: bytesToHex(kdk) },
      { label: 'DEK/CEK', value: bytesToHex(dek) }
    );

    const sentinelTableBytes = fields.get(0xffff);
    let substitutedConfigs: any[] = [];
    if (sentinelTableBytes) {
      const spec = JSON.parse(bytesToText(sentinelTableBytes));
      if (Array.isArray(spec.configs)) {
        substitutedConfigs = spec.configs.map((cfg: any) => npvGen2Substitute(cfg, fields));
      }
    }

    const msgParts = [
      metadataObj?.policy?.displayMessage,
      metadataObj?.policy?.customServerMessage
    ]
      .map((m) => String(m || '').trim())
      .filter(Boolean);

    return {
      version: 5,
      unlockMethod: method === 2 ? 'app-key' : 'passphrase',
      needsPassphrase: method === 1,
      decryptedJsonText: JSON.stringify(substitutedConfigs, null, 2),
      configs: substitutedConfigs,
      creatorMessage: msgParts.join('\n'),
      metadata: metadataObj,
      keyMaterial
    };
  }

  // Branch 2: NPVS v1 / v4 JSON Header Envelope
  const hdrJson = JSON.parse(bytesToText(header));
  let bodyOff = 9 + hdrLen;
  const nonce = bytes.subarray(bodyOff, bodyOff + 12);
  const bodyLen = readBE32(bytes, bodyOff + 12);
  bodyOff += 16;
  const body = bytes.subarray(bodyOff, bodyOff + bodyLen);

  const keyMaterial: Array<{ label: string; value: string }> = [
    { label: 'configId', value: String(hdrJson.configId || '') },
    { label: 'creator.fp', value: String(hdrJson?.creator?.fp || '') }
  ];

  let dek: Uint8Array | null = null;
  if (hdrJson.appKey) {
    const salt = b64ToBytes(hdrJson.appKey.salt);
    const wrap = b64ToBytes(hdrJson.appKey.wrap);
    const kdks = await custodianKDKs(salt);
    for (const kdk of kdks) {
      try {
        dek = chachaOpen(kdk, wrap.subarray(0, 12), wrap.subarray(12), salt);
        break;
      } catch (_) {}
    }
    if (!dek) throw new Error('کلید AppKey با هیچ‌یک از جداول White-Box نسل ۴ مطابقت نداشت.');
  } else if (hdrJson.passphrase) {
    if (!password) {
      const err: any = new Error('این کانفیگ NPVS دارای رمز عبور است. لطفاً رمز عبور را وارد نمایید.');
      err.needsPassphrase = true;
      throw err;
    }
    const salt = b64ToBytes(hdrJson.passphrase.salt);
    const wrap = b64ToBytes(hdrJson.passphrase.wrap);
    const derived = await pbkdf2HmacSha256(password, salt, hdrJson.passphrase.iters, 32);
    try {
      dek = chachaOpen(derived, wrap.subarray(0, 12), wrap.subarray(12), salt);
    } catch (_) {
      const err: any = new Error('رمز عبور وارد شده نادرست است.');
      err.needsPassphrase = true;
      throw err;
    }
  } else {
    throw new Error('این فایل NPVS نیازمند کلید خصوصی گیرنده (Hardware ID Lock) است.');
  }

  keyMaterial.push({ label: 'DEK/CEK', value: bytesToHex(dek) });
  const plainBytes = chachaOpen(dek, nonce, body, header);
  const decodedText = decodeNpvSentinels(bytesToText(plainBytes));

  let parsedConfigs: any[] = [];
  try {
    const parsed = JSON.parse(decodedText);
    parsedConfigs = Array.isArray(parsed) ? parsed : Array.isArray(parsed.configs) ? parsed.configs : [parsed];
  } catch (_) {}

  const msgParts = [
    hdrJson?.policy?.displayMessage,
    hdrJson?.policy?.customServerMessage
  ]
    .map((m) => String(m || '').trim())
    .filter(Boolean);

  return {
    version: hdrJson.v || version,
    unlockMethod: hdrJson.appKey ? 'app-key' : 'passphrase',
    needsPassphrase: Boolean(hdrJson.passphrase && !hdrJson.appKey),
    decryptedJsonText: decodedText,
    configs: parsedConfigs,
    creatorMessage: msgParts.join('\n'),
    metadata: hdrJson.policy,
    keyMaterial
  };
}
