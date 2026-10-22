// @ts-nocheck
import { tyBoxes, mbl, tboxesLast, tboxesLastV1, tboxesLastV2, xorTable, shiftOrder } from './npvCryptoTables.ts';
import { GEN2_TABLES_B64 } from '../assets/gen2TablesB64.ts';

// ============================================================================
// Pure TypeScript SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, HKDF-SHA256
// ============================================================================

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr32(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

export function sha256(data: Uint8Array): Uint8Array {
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const bitLenHi = Math.floor(data.length / 0x20000000);
  const bitLenLo = (data.length << 3) >>> 0;
  const padLen = ((data.length + 9 + 63) & ~63);
  const padded = new Uint8Array(padLen);
  padded.set(data);
  padded[data.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padLen - 8, bitLenHi, false);
  view.setUint32(padLen - 4, bitLenLo, false);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  outView.setUint32(20, h5, false);
  outView.setUint32(24, h6, false);
  outView.setUint32(28, h7, false);
  return out;
}

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  const blockSize = 64;
  let k = key;
  if (k.length > blockSize) {
    k = sha256(k);
  }
  const keyBlock = new Uint8Array(blockSize);
  keyBlock.set(k);

  const ipad = new Uint8Array(blockSize + message.length);
  const opad = new Uint8Array(blockSize + 32);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = keyBlock[i] ^ 0x36;
    opad[i] = keyBlock[i] ^ 0x5c;
  }
  ipad.set(message, blockSize);
  const innerHash = sha256(ipad);
  opad.set(innerHash, blockSize);
  return sha256(opad);
}

export function customPBKDF2HmacSha256(
  passphraseBytes: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number
): Uint8Array {
  const blocks = Math.floor((dkLen + 31) / 32);
  const out = new Uint8Array(dkLen);
  const saltCounter = new Uint8Array(salt.length + 4);
  saltCounter.set(salt);
  const view = new DataView(saltCounter.buffer);

  let written = 0;
  for (let i = 1; i <= blocks; i++) {
    view.setUint32(salt.length, i, false);
    let digest = hmacSha256(passphraseBytes, saltCounter);
    const blockXor = new Uint8Array(digest);
    for (let j = 2; j <= iterations; j++) {
      digest = hmacSha256(passphraseBytes, digest);
      for (let idx = 0; idx < 32; idx++) {
        blockXor[idx] ^= digest[idx];
      }
    }
    const n = Math.min(32, dkLen - written);
    out.set(blockXor.subarray(0, n), written);
    written += n;
  }
  return out;
}

export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length = 32): Uint8Array {
  const actualSalt = salt && salt.length > 0 ? salt : new Uint8Array(32);
  const prk = hmacSha256(actualSalt, ikm);
  const out = new Uint8Array(length);
  let t = new Uint8Array(0);
  let written = 0;
  let counter = 1;
  while (written < length) {
    const input = new Uint8Array(t.length + info.length + 1);
    input.set(t, 0);
    input.set(info, t.length);
    input[t.length + info.length] = counter++;
    t = hmacSha256(prk, input);
    const n = Math.min(32, length - written);
    out.set(t.subarray(0, n), written);
    written += n;
  }
  return out;
}

// ============================================================================
// Pure TypeScript ChaCha20-Poly1305 (RFC 8439)
// ============================================================================

function rotl32(v: number, c: number): number {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}

function chacha20QuarterRound(x: Uint32Array, a: number, b: number, c: number, d: number) {
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 7);
}

function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  const kv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) {
    state[4 + i] = kv.getUint32(i * 4, true);
  }
  state[12] = counter >>> 0;
  const nv = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  state[13] = nv.getUint32(0, true);
  state[14] = nv.getUint32(4, true);
  state[15] = nv.getUint32(8, true);

  const working = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    chacha20QuarterRound(working, 0, 4, 8, 12);
    chacha20QuarterRound(working, 1, 5, 9, 13);
    chacha20QuarterRound(working, 2, 6, 10, 14);
    chacha20QuarterRound(working, 3, 7, 11, 15);
    chacha20QuarterRound(working, 0, 5, 10, 15);
    chacha20QuarterRound(working, 1, 6, 11, 12);
    chacha20QuarterRound(working, 2, 7, 8, 13);
    chacha20QuarterRound(working, 3, 4, 9, 14);
  }

  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) {
    ov.setUint32(i * 4, (working[i] + state[i]) >>> 0, true);
  }
  return out;
}

function chacha20Crypt(key: Uint8Array, counter: number, nonce: Uint8Array, input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.length);
  let blockCount = counter;
  for (let i = 0; i < input.length; i += 64) {
    const ks = chacha20Block(key, blockCount++, nonce);
    const n = Math.min(64, input.length - i);
    for (let j = 0; j < n; j++) {
      out[i + j] = input[i + j] ^ ks[j];
    }
  }
  return out;
}

function poly1305Mac(msg: Uint8Array, key: Uint8Array): Uint8Array {
  const P = (1n << 130n) - 5n;
  const rBytes = new Uint8Array(key.subarray(0, 16));
  rBytes[3] &= 15;
  rBytes[7] &= 15;
  rBytes[11] &= 15;
  rBytes[15] &= 15;
  rBytes[4] &= 252;
  rBytes[8] &= 252;
  rBytes[12] &= 252;

  let r = 0n;
  for (let i = 15; i >= 0; i--) {
    r = (r << 8n) | BigInt(rBytes[i]);
  }

  let s = 0n;
  for (let i = 31; i >= 16; i--) {
    s = (s << 8n) | BigInt(key[i]);
  }

  let a = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const n = Math.min(16, msg.length - i);
    let chunk = 1n;
    for (let j = n - 1; j >= 0; j--) {
      chunk = (chunk << 8n) | BigInt(msg[i + j]);
    }
    a = ((a + chunk) * r) % P;
  }

  a = (a + s) & ((1n << 128n) - 1n);
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = Number(a & 0xffn);
    a >>= 8n;
  }
  return tag;
}

export function chachaOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ctTag: Uint8Array,
  aad: Uint8Array
): Uint8Array | null {
  if (key.length !== 32 || nonce.length !== 12 || ctTag.length < 16) {
    return null;
  }
  const ct = ctTag.subarray(0, ctTag.length - 16);
  const tag = ctTag.subarray(ctTag.length - 16);

  const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
  const pad1 = (16 - (aad.length % 16)) % 16;
  const pad2 = (16 - (ct.length % 16)) % 16;
  const macData = new Uint8Array(aad.length + pad1 + ct.length + pad2 + 16);
  macData.set(aad, 0);
  macData.set(ct, aad.length + pad1);
  const dv = new DataView(macData.buffer);
  dv.setUint32(macData.length - 16, aad.length >>> 0, true);
  dv.setUint32(macData.length - 12, Math.floor(aad.length / 0x100000000), true);
  dv.setUint32(macData.length - 8, ct.length >>> 0, true);
  dv.setUint32(macData.length - 4, Math.floor(ct.length / 0x100000000), true);

  const expectedTag = poly1305Mac(macData, otk);
  let diff = 0;
  for (let i = 0; i < 16; i++) {
    diff |= expectedTag[i] ^ tag[i];
  }
  if (diff !== 0) {
    return null;
  }
  return chacha20Crypt(key, 1, nonce, ct);
}

export function chachaSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  const ct = chacha20Crypt(key, 1, nonce, plaintext);
  const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
  const pad1 = (16 - (aad.length % 16)) % 16;
  const pad2 = (16 - (ct.length % 16)) % 16;
  const macData = new Uint8Array(aad.length + pad1 + ct.length + pad2 + 16);
  macData.set(aad, 0);
  macData.set(ct, aad.length + pad1);
  const dv = new DataView(macData.buffer);
  dv.setUint32(macData.length - 16, aad.length >>> 0, true);
  dv.setUint32(macData.length - 12, Math.floor(aad.length / 0x100000000), true);
  dv.setUint32(macData.length - 8, ct.length >>> 0, true);
  dv.setUint32(macData.length - 4, Math.floor(ct.length / 0x100000000), true);

  const tag = poly1305Mac(macData, otk);
  const out = new Uint8Array(ct.length + 16);
  out.set(ct, 0);
  out.set(tag, ct.length);
  return out;
}

// ============================================================================
// White-Box AES-CTR for NPVS v1 (Custodian KDKs v1 & v2)
// ============================================================================

function wbXorLookup(t: number, a: number, b: number): number {
  return xorTable[t][a][b] & 0x0f;
}

function wbMixWord(groupIndex: number, k: number, a: number, b: number, c: number, d: number): number {
  const t = groupIndex * 24 + k * 6;
  const hiShift = 28 - 8 * k;
  const loShift = 24 - 8 * k;
  const p1 = wbXorLookup(t, (a >>> hiShift) & 0x0f, (b >>> hiShift) & 0x0f);
  const p2 = wbXorLookup(t + 1, (c >>> hiShift) & 0x0f, (d >>> hiShift) & 0x0f);
  const p3 = wbXorLookup(t + 2, (a >>> loShift) & 0x0f, (b >>> loShift) & 0x0f);
  const p4 = wbXorLookup(t + 3, (c >>> loShift) & 0x0f, (d >>> loShift) & 0x0f);
  return ((wbXorLookup(t + 4, p1, p2) << 4) | wbXorLookup(t + 5, p3, p4)) & 0xff;
}

function wbBlockWithTlast(input16: Uint8Array, tlastTable: number[][]): Uint8Array {
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = input16[shiftOrder[i]];

  for (let grp = 0; grp < 4; grp++) {
    const base = grp * 4;
    let a = tyBoxes[base + 0][s[base + 0]] >>> 0;
    let b = tyBoxes[base + 1][s[base + 1]] >>> 0;
    let c = tyBoxes[base + 2][s[base + 2]] >>> 0;
    let d = tyBoxes[base + 3][s[base + 3]] >>> 0;
    for (let k = 0; k < 4; k++) {
      s[base + k] = wbMixWord(grp, k, a, b, c, d);
    }

    a = mbl[base + 0][s[base + 0]] >>> 0;
    b = mbl[base + 1][s[base + 1]] >>> 0;
    c = mbl[base + 2][s[base + 2]] >>> 0;
    d = mbl[base + 3][s[base + 3]] >>> 0;
    for (let k = 0; k < 4; k++) {
      s[base + k] = wbMixWord(grp, k, a, b, c, d);
    }
  }

  const shifted = new Uint8Array(16);
  for (let i = 0; i < 16; i++) shifted[i] = s[shiftOrder[i]];

  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = tlastTable[i][shifted[i]] & 0xff;
  }
  return out;
}

function wbCTRWithTlast(nonce16: Uint8Array, ct: Uint8Array, tlastTable: number[][]): Uint8Array {
  const counter = new Uint8Array(16);
  counter.set(nonce16.subarray(0, 16));
  const out = new Uint8Array(ct.length);
  for (let i = 0; i < ct.length; i += 16) {
    const ks = wbBlockWithTlast(counter, tlastTable);
    const n = Math.min(ct.length - i, 16);
    for (let j = 0; j < n; j++) {
      out[i + j] = ct[i + j] ^ ks[j];
    }
    for (let p = 15; p >= 0; p--) {
      counter[p] = (counter[p] + 1) & 0xff;
      if (counter[p] !== 0) break;
    }
  }
  return out;
}

const WB_KDF_PREFIX = new TextEncoder().encode('npvtunnel/appkey/v1 ');

export function custodianKDKs(salt: Uint8Array): Uint8Array[] {
  const material = new Uint8Array(32);
  material.set(salt.subarray(0, 16), 0);
  const variants = [tboxesLastV1 || tboxesLast, tboxesLastV2 || tboxesLast];
  const kdks: Uint8Array[] = [];
  for (const tbl of variants) {
    if (!tbl || tbl.length !== 16) continue;
    const stream = wbCTRWithTlast(material.subarray(0, 16), material.subarray(16, 32), tbl);
    const combined = new Uint8Array(WB_KDF_PREFIX.length + stream.length);
    combined.set(WB_KDF_PREFIX, 0);
    combined.set(stream, WB_KDF_PREFIX.length);
    kdks.push(sha256(combined));
  }
  return kdks;
}

// ============================================================================
// White-Box Generation 2 (NPVS v5 Compact Binary Envelope)
// ============================================================================

const NPV_GEN2_BLOCK_SIZE = 57344;
const NPV_GEN2_BLOCK_COUNT = 13;
const NPV_GEN2_PAGE_SIZE = 4096;
const NPV_GEN2_TABLES_SIZE = NPV_GEN2_BLOCK_COUNT * NPV_GEN2_BLOCK_SIZE + NPV_GEN2_PAGE_SIZE; // 749568
const NPV_GEN2_APPKEY_LABEL = new TextEncoder().encode('npvtunnel/appkey/v2 ');

let cachedGen2Tables: Uint8Array | null = null;

export function setGen2Tables(tables: Uint8Array) {
  if (tables && tables.length === NPV_GEN2_TABLES_SIZE) {
    cachedGen2Tables = tables;
  }
}

export function isGen2TablesLoaded(): boolean {
  return cachedGen2Tables !== null && cachedGen2Tables.length === NPV_GEN2_TABLES_SIZE;
}

function decodeGen2TablesB64(): Uint8Array {
  const bin = atob(GEN2_TABLES_B64.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function preloadGen2TablesBrowser(): Promise<boolean> {
  if (cachedGen2Tables) return true;
  try {
    const compressedBuf = decodeGen2TablesB64().slice().buffer;
    if (typeof DecompressionStream !== 'undefined') {
      // pipe the payload through the stream — writing into the writer directly
      // deadlocks, because nothing consumes the readable side while we write
      const source = new Response(compressedBuf).body;
      if (!source) return false;
      const inflated = source.pipeThrough(new DecompressionStream('deflate'));
      const ab = await new Response(inflated).arrayBuffer();
      const bytes = new Uint8Array(ab);
      if (bytes.length === NPV_GEN2_TABLES_SIZE) {
        cachedGen2Tables = bytes;
        return true;
      }
    }
  } catch {
    // Ignore decode error
  }
  return false;
}

function getGen2TablesSync(): Uint8Array | null {
  if (cachedGen2Tables) return cachedGen2Tables;
  try {
    const req = typeof require !== 'undefined' ? require : null;
    if (req) {
      const zlib = req('zlib');
      const compressed = Buffer.from(GEN2_TABLES_B64.replace(/\s+/g, ''), 'base64');
      const inflated = new Uint8Array(zlib.inflateSync(compressed));
      if (inflated.length === NPV_GEN2_TABLES_SIZE) {
        cachedGen2Tables = inflated;
        return cachedGen2Tables;
      }
    }
  } catch {
    // Handled via ESM preload
  }
  return cachedGen2Tables;
}

if (typeof process !== 'undefined' && process.versions?.node) {
  import('node:zlib').then((zlib) => {
    const compressed = Buffer.from(GEN2_TABLES_B64.replace(/\s+/g, ''), 'base64');
    const inflated = new Uint8Array(zlib.inflateSync(compressed));
    if (inflated.length === NPV_GEN2_TABLES_SIZE) {
      cachedGen2Tables = inflated;
    }
  }).catch(() => {});
}

function npvGen2BE32(block: Uint8Array, off: number): number {
  return (
    ((block[off] << 24) |
      (block[off + 1] << 16) |
      (block[off + 2] << 8) |
      block[off + 3]) >>> 0
  );
}

function npvGen2GroupArgs(block: Uint8Array, half: number, j: number, s: Uint8Array): [number, number, number, number] {
  const base = half + 0x1000 * j;
  return [
    npvGen2BE32(block, base + 4 * s[0]),
    npvGen2BE32(block, base + 0x400 + 4 * s[1]),
    npvGen2BE32(block, base + 0x800 + 4 * s[2]),
    npvGen2BE32(block, base + 0xc00 + 4 * s[3]),
  ];
}

export function npvGen2Sub7DC0(
  block: Uint8Array,
  i: number,
  in3: number,
  in4: number,
  in5: number,
  in6: number
): Uint8Array {
  const m32 = (v: number) => v >>> 0;
  const at = (addr: number) => block[addr >>> 0] >>> 0;

  const out = new Uint8Array(4);
  const x2 = i >>> 0;
  const x3 = m32(in3);
  const x4 = m32(in4);
  const x5 = m32(in5);
  const x6 = m32(in6);

  let x0 = 0, x8 = 0, x9 = 0, x10 = 0, x11 = 0, x12 = 0, x13 = 0, x14 = 0, x15 = 0, x16 = 0, x17 = 0;

  x8 = m32(x2 + m32(x2 << 1));
  x12 = m32(x3 >>> 0x14);
  x11 = m32(x3 >>> 0x18);
  x13 = (x4 >>> 0x18) & 0xf;
  x14 = m32(x5 >>> 0x18);
  x10 = x6;
  x9 = m32(x8 << 3);
  x8 = x4;
  x12 &= 0xf0;
  x12 = (x12 + x13) >>> 0;
  x13 = m32(x5 >>> 0x14);
  x16 = x8 >>> 0x1c;
  x9 &= 0xffffffff;
  x11 &= 0xf0;
  x14 &= 0xf0;
  x15 = m32(x6 >>> 0x18) & 0xf;
  x13 &= 0xf0;
  x17 = m32(x3 >>> 0x10);
  x9 = (x9 << 8) >>> 0;
  x8 &= 0xf;
  x13 = (x13 + x15) >>> 0;
  x17 &= 0xf0;
  x11 = (x9 + x11) >>> 0;
  x14 = (x9 + x14) >>> 0;
  x12 = (x9 + x12) >>> 0;
  x16 = at(x11 + x16);
  x14 = (x14 + (x10 >>> 28)) >>> 0;
  x12 = at(x12 + 0x200);
  x13 = (x9 + x13) >>> 0;
  x0 = m32(x6 >>> 0x14) & 0xf;
  x14 = at(x14 + 0x100);
  x15 = (x9 + (x16 << 4)) >>> 0;
  x13 = at(x13 + 0x300);
  x12 = (x9 + (x12 << 4)) >>> 0;
  x16 = m32(x4 >>> 0x14) & 0xf;
  x10 &= 0xf;
  x14 = (x15 + x14) >>> 0;
  x15 = m32(x5 >>> 0x10);
  x12 = (x12 + x13) >>> 0;
  x13 = m32(x3 >>> 0xc);
  x14 = at(x14 + 0x400);
  x12 = at(x12 + 0x500);
  x15 &= 0xf0;
  x16 = (x17 + x16) >>> 0;
  x15 = (x15 + x0) >>> 0;
  x0 = m32(x4 >>> 0x10) & 0xf;
  x17 = m32(x5 >>> 0xc);
  x12 = (x12 | (x14 << 4)) >>> 0;
  x13 &= 0xf0;
  x14 = m32(x6 >>> 0x10) & 0xf;
  x13 = (x13 + x0) >>> 0;
  x17 &= 0xf0;
  x16 = (x9 + x16) >>> 0;
  out[0] = x12 & 0xff;
  x13 = (x9 + x13) >>> 0;
  x12 = (x17 + x14) >>> 0;
  x14 = at(x16 + 0x600);
  x13 = at(x13 + 0x800);
  x15 = (x9 + x15) >>> 0;
  x12 = (x9 + x12) >>> 0;
  x15 = at(x15 + 0x700);
  x16 = m32(x5 >>> 8);
  x12 = at(x12 + 0x900);
  x14 = (x9 + (x14 << 4)) >>> 0;
  x13 = (x9 + (x13 << 4)) >>> 0;
  x0 = m32(x6 >>> 0xc) & 0xf;
  x17 = m32(x3 >>> 8);
  x14 = (x14 + x15) >>> 0;
  x12 = (x13 + x12) >>> 0;
  x13 = x16 & 0xf0;
  x14 = at(x14 + 0xa00);
  x12 = at(x12 + 0xb00);
  x15 = m32(x3 >>> 4);
  x13 = (x13 + x0) >>> 0;
  x0 = m32(x4 >>> 8) & 0xf;
  x16 = m32(x4 >>> 0xc) & 0xf;
  x12 = (x12 | (x14 << 4)) >>> 0;
  x14 = x15 & 0xf0;
  x17 &= 0xf0;
  x14 = (x14 + x0) >>> 0;
  x15 = (x9 + 0xc00) >>> 0;
  x0 = m32(x5 >>> 4);
  x17 = (x15 + x17) >>> 0;
  out[1] = x12 & 0xff;
  x12 = m32(x6 >>> 8) & 0xf;
  x16 = at(x17 + x16);
  x14 = (x9 + x14) >>> 0;
  x17 = x0 & 0xf0;
  x14 = at(x14 + 0xe00);
  x12 = (x17 + x12) >>> 0;
  x13 = (x15 + x13) >>> 0;
  x12 = (x9 + x12) >>> 0;
  x13 = at(x13 + 0x100);
  x15 = (x9 + (x16 << 4)) >>> 0;
  x12 = at(x12 + 0xf00);
  x14 = (x9 + (x14 << 4)) >>> 0;
  x16 = 0x1000;
  x13 = (x15 + x13) >>> 0;
  x17 = m32(x6 >>> 4) & 0xf;
  x0 = x5 & 0xf0;
  x12 = (x14 + x12) >>> 0;
  x14 = 0x1100;
  x13 = at(x13 + x16);
  x12 = at(x12 + x14);
  x14 = 0x1200;
  x15 = m32(x4 >>> 4) & 0xf;
  x16 = x3 & 0xf0;
  x17 = (x0 + x17) >>> 0;
  x14 = (x9 + x14) >>> 0;
  x12 = (x12 | (x13 << 4)) >>> 0;
  x13 = (x3 & 0xf) << 4;
  x16 = (x14 + x16) >>> 0;
  out[2] = x12 & 0xff;
  x8 = (x13 + x8) >>> 0;
  x12 = (x14 + x17) >>> 0;
  x14 = (x5 & 0xf) << 4;
  x13 = at(x16 + x15);
  x8 = (x9 + x8) >>> 0;
  x15 = 0x1400;
  x12 = at(x12 + 0x100);
  x8 = at(x8 + x15);
  x10 = (x14 + x10) >>> 0;
  x14 = 0x1500;
  x10 = (x9 + x10) >>> 0;
  x13 = (x9 + (x13 << 4)) >>> 0;
  x10 = at(x10 + x14);
  x8 = (x9 + (x8 << 4)) >>> 0;
  x9 = (x13 + x12) >>> 0;
  x12 = 0x1600;
  x8 = (x8 + x10) >>> 0;
  x10 = 0x1700;
  x9 = at(x9 + x12);
  x8 = at(x8 + x10);
  x8 = (x8 | (x9 << 4)) >>> 0;
  out[3] = x8 & 0xff;
  return out;
}

export function npvGen2A16(salt: Uint8Array): Uint8Array | null {
  if (salt.length !== 16) return null;
  const tables = getGen2TablesSync();
  if (!tables) return null;

  const state = new Uint8Array(16);
  state.set(salt);

  for (let b = 0; b < NPV_GEN2_BLOCK_COUNT; b++) {
    const block = tables.subarray(b * NPV_GEN2_BLOCK_SIZE, (b + 1) * NPV_GEN2_BLOCK_SIZE);
    const shifted = new Uint8Array(16);
    for (let i = 0; i < 16; i++) shifted[i] = state[shiftOrder[i]];
    state.set(shifted);

    for (let j = 0; j < 4; j++) {
      const s = state.subarray(4 * j, 4 * j + 4);
      let args = npvGen2GroupArgs(block, 0x6000, j, s);
      let written = npvGen2Sub7DC0(block, j, args[0], args[1], args[2], args[3]);
      s.set(written);

      args = npvGen2GroupArgs(block, 0xa000, j, s);
      written = npvGen2Sub7DC0(block, j, args[0], args[1], args[2], args[3]);
      s.set(written);
    }
  }

  const page = tables.subarray(NPV_GEN2_BLOCK_COUNT * NPV_GEN2_BLOCK_SIZE);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = page[0x100 * i + state[shiftOrder[i]]];
  }
  return out;
}

export function npvGen2KDK(a16: Uint8Array, configID: Uint8Array): Uint8Array {
  const buf = new Uint8Array(NPV_GEN2_APPKEY_LABEL.length + a16.length + configID.length);
  buf.set(NPV_GEN2_APPKEY_LABEL, 0);
  buf.set(a16, NPV_GEN2_APPKEY_LABEL.length);
  buf.set(configID, NPV_GEN2_APPKEY_LABEL.length + a16.length);
  return sha256(buf);
}

// ============================================================================
// Sentinel Decoding (npvs1:<base64>)
// ============================================================================

const NPV_SENTINEL_PREFIX = 'npvs1:';
const NPV_SENTINEL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-';

export function b64UrlOrStdToBytes(str: string): Uint8Array | null {
  try {
    let normalized = str.trim().replace(/-/g, '+').replace(/_/g, '/');
    const mod = normalized.length % 4;
    if (mod === 1) return null;
    if (mod > 0) normalized += '='.repeat(4 - mod);
    const bin = atob(normalized);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function decodeNpvSentinels(s: string): string {
  if (!s || !s.includes(NPV_SENTINEL_PREFIX)) return s;
  let result = '';
  let rest = s;
  while (true) {
    const idx = rest.indexOf(NPV_SENTINEL_PREFIX);
    if (idx === -1) {
      result += rest;
      break;
    }
    result += rest.slice(0, idx);
    rest = rest.slice(idx + NPV_SENTINEL_PREFIX.length);
    let j = 0;
    while (j < rest.length && NPV_SENTINEL_ALPHABET.includes(rest[j])) {
      j++;
    }
    const tok = rest.slice(0, j);
    rest = rest.slice(j);
    const decoded = b64UrlOrStdToBytes(tok);
    if (!decoded) {
      result += NPV_SENTINEL_PREFIX + tok;
    } else {
      result += new TextDecoder('utf-8', { fatal: false }).decode(decoded);
    }
  }
  return result;
}

export function deepDecodeSentinels(v: any): any {
  if (typeof v === 'string') return decodeNpvSentinels(v);
  if (Array.isArray(v)) return v.map(deepDecodeSentinels);
  if (v && typeof v === 'object') {
    const out: Record<string, any> = {};
    for (const [k, val] of Object.entries(v)) {
      out[k] = deepDecodeSentinels(val);
    }
    return out;
  }
  return v;
}

// ============================================================================
// NPVS v1 (JSON Header) & NPVS v5 (Gen-2 Compact Binary Envelope) Decryption
// ============================================================================

export interface NpvsDecryptResult {
  ok: boolean;
  version: 'v1' | 'v5-gen2';
  needsPassphrase?: boolean;
  unlockMethod?: 'appKey' | 'passphrase' | 'recipient';
  creatorMessage?: string;
  decryptedText?: string;
  links?: string[];
  rawConfigObjects?: any[];
  metadata?: Record<string, any>;
  recoveredKeys?: Record<string, string>;
  error?: string;
}

function readBE32(b: Uint8Array, off: number): number {
  return (
    ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0
  );
}

function readBE16(b: Uint8Array, off: number): number {
  return ((b[off] << 8) | b[off + 1]) & 0xffff;
}

function writeBE16(v: number): Uint8Array {
  return new Uint8Array([(v >>> 8) & 0xff, v & 0xff]);
}

function writeBE32(v: number): Uint8Array {
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
}

export function isNpvGen2Bytes(b: Uint8Array): boolean {
  return (
    b.length >= 9 &&
    b[0] === 0x4e && // 'N'
    b[1] === 0x50 && // 'P'
    b[2] === 0x56 && // 'V'
    b[3] === 0x53 && // 'S'
    b[4] === 5
  );
}

export function isNpvV1Bytes(b: Uint8Array): boolean {
  return (
    b.length >= 89 &&
    b[0] === 0x4e &&
    b[1] === 0x50 &&
    b[2] === 0x56 &&
    b[3] === 0x53 &&
    b[4] <= 4
  );
}

function npvGen2FlatMap(obj: Record<string, any>): Record<string, string> {
  const flat: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj || {})) {
    if (v === null || v === undefined) flat[k] = '';
    else if (typeof v === 'string') flat[k] = v;
    else if (typeof v === 'number' || typeof v === 'boolean') flat[k] = String(v);
    else flat[k] = JSON.stringify(v);
  }
  return flat;
}

function npvGen2Or(...vals: (string | undefined)[]): string {
  for (const v of vals) {
    if (v && v.trim() !== '') return v;
  }
  return '';
}

function npvGen2AllowInsecure(p: Record<string, string>): boolean {
  for (const key of ['tlsAllowInsecure', 'insecure']) {
    const val = (p[key] || '').trim().toLowerCase();
    if (val === 'true' || val === '1' || val === 'yes') return true;
    if (val === 'false' || val === '0' || val === 'no') return false;
  }
  return false;
}

function npvGen2StreamQuery(p: Record<string, string>): URLSearchParams {
  const network = npvGen2Or(p.network, 'tcp');
  const security = npvGen2Or(p.security, 'none');
  const q = new URLSearchParams();
  q.set('type', network);
  q.set('security', security);

  const setIf = (k: string, v?: string) => {
    if (v && v !== '') q.set(k, v);
  };

  switch (network) {
    case 'ws':
      setIf('path', p.path);
      setIf('host', p.host);
      break;
    case 'grpc':
      setIf('serviceName', p.serviceName);
      setIf('mode', npvGen2Or(p.mode, p.xhttpMode, 'gun'));
      setIf('authority', p.authority);
      break;
    case 'kcp':
      setIf('headerType', p.headerType);
      setIf('seed', p.seed);
      break;
    case 'quic':
      setIf('key', p.key);
      setIf('headerType', p.headerType);
      break;
    case 'xhttp':
    case 'httpupgrade':
      setIf('path', p.path);
      setIf('host', p.host);
      setIf('mode', npvGen2Or(p.xhttpMode, p.mode));
      setIf('extra', p.xhttpExtra);
      break;
    case 'tcp':
    case 'raw':
      if (p.headerType && p.headerType !== 'none') {
        q.set('headerType', p.headerType);
        setIf('host', p.host);
        setIf('path', p.path);
      }
      break;
  }

  if (security === 'tls') {
    setIf('sni', p.sni);
    setIf('fp', p.fingerPrint);
    setIf('alpn', p.alpn);
    if (npvGen2AllowInsecure(p)) q.set('allowInsecure', '1');
  } else if (security === 'reality') {
    setIf('sni', p.sni);
    setIf('fp', p.fingerPrint);
    setIf('pbk', p.publicKey);
    setIf('sid', p.shortId);
    setIf('spx', p.spiderX);
  }
  return q;
}

export function npvConfigObjToShareLink(cfg: any): string {
  if (!cfg || typeof cfg !== 'object') return String(cfg || '');
  const remarks = String(cfg.name || 'NPVS Node');
  const address = String(cfg.address || '');

  if (cfg.v2rayProfile && typeof cfg.v2rayProfile === 'object') {
    const p = npvGen2FlatMap(cfg.v2rayProfile);
    if (p.v2rayJson && p.v2rayJson.trim().startsWith('{')) {
      return p.v2rayJson;
    }
    const host = npvGen2Or(p.server, address);
    const port = parseInt(p.serverPort || p.port || '443', 10) || 443;
    const configType = parseInt(p.configType || '0', 10);

    if (configType === 1) {
      let headerType = npvGen2Or(p.headerType, 'none');
      let hostHeader = p.host || '';
      let path = p.path || '';
      const net = npvGen2Or(p.network, 'tcp').toLowerCase();
      if (net === 'kcp') path = npvGen2Or(path, p.seed);
      else if (net === 'grpc') {
        headerType = p.mode || '';
        path = npvGen2Or(path, p.serviceName);
        hostHeader = npvGen2Or(hostHeader, p.authority);
      }
      const vmessObj = {
        v: '2',
        ps: remarks,
        add: host,
        port: String(port),
        id: p.password || '',
        aid: String(parseInt(p.alterId || '0', 10) || 0),
        scy: npvGen2Or(p.method, 'auto'),
        net,
        type: headerType,
        host: hostHeader,
        path,
        tls: p.security === 'tls' || p.security === 'reality' ? 'tls' : '',
        sni: p.sni || '',
        fp: p.fingerPrint || '',
        alpn: p.alpn || '',
        insecure: p.security === 'tls' ? (npvGen2AllowInsecure(p) ? '1' : '0') : '',
      };
      const jsonBytes = new TextEncoder().encode(JSON.stringify(vmessObj));
      let bin = '';
      for (let i = 0; i < jsonBytes.length; i++) bin += String.fromCharCode(jsonBytes[i]);
      return 'vmess://' + btoa(bin);
    } else if (configType === 5) {
      const q = npvGen2StreamQuery(p);
      q.set('encryption', p.method && p.method.trim() ? p.method.trim() : 'none');
      if (p.flow) q.set('flow', p.flow);
      return `vless://${p.password || ''}@${host}:${port}?${q.toString()}#${encodeURIComponent(remarks)}`;
    } else if (configType === 6) {
      const q = npvGen2StreamQuery(p);
      if (p.flow) q.set('flow', p.flow);
      return `trojan://${encodeURIComponent(p.password || '')}@${host}:${port}?${q.toString()}#${encodeURIComponent(remarks)}`;
    } else if (configType === 3) {
      const rawUser = `${p.method || 'aes-256-gcm'}:${p.password || ''}`;
      const uBytes = new TextEncoder().encode(rawUser);
      let bin = '';
      for (let i = 0; i < uBytes.length; i++) bin += String.fromCharCode(uBytes[i]);
      return `ss://${btoa(bin)}@${host}:${port}#${encodeURIComponent(remarks)}`;
    }
  }

  if (cfg.sshConfig && typeof cfg.sshConfig === 'object') {
    const s = npvGen2FlatMap(cfg.sshConfig);
    const target = s.sshPort ? `${s.sshHost}:${s.sshPort}` : s.sshHost;
    const q = new URLSearchParams();
    if (remarks) q.set('remarks', remarks);
    if (s.sshConfigType) q.set('sshConfigType', s.sshConfigType);
    if (s.httpProxy) q.set('httpProxy', s.httpProxy);
    const userPart = `${encodeURIComponent(s.sshUsername || '')}:${encodeURIComponent(s.sshPassword || '')}`;
    return `ssh://${userPart}@${target}?${q.toString()}#${s.payload || ''}`;
  }

  for (const kind of ['socksConfig', 'socksProfile', 'httpConfig', 'httpProfile', 'proxyConfig']) {
    if (cfg[kind] && typeof cfg[kind] === 'object') {
      const p = npvGen2FlatMap(cfg[kind]);
      const scheme = kind.replace(/Config$|Profile$/, '');
      const host = npvGen2Or(p.server, p.host, address);
      const port = npvGen2Or(p.serverPort, p.port, p.localPort, '1080');
      const q = new URLSearchParams();
      if (remarks) q.set('remarks', remarks);
      const userPart = p.username
        ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password || '')}@`
        : '';
      return `${scheme}://${userPart}${host}:${port}?${q.toString()}#${encodeURIComponent(remarks)}`;
    }
  }

  return '';
}

function npvGen2FieldText(raw: Uint8Array | undefined): string {
  if (!raw) return '';
  const s = new TextDecoder('utf-8', { fatal: false }).decode(raw).trim();
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    try {
      return JSON.parse(s);
    } catch {
      return s.slice(1, -1);
    }
  }
  return s;
}

function npvGen2Substitute(v: any, fields: Map<number, Uint8Array>): any {
  if (typeof v === 'number' && Number.isInteger(v) && fields.has(v)) {
    return decodeNpvSentinels(npvGen2FieldText(fields.get(v)));
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
  return v;
}

export function decryptNpvGen2Envelope(b: Uint8Array, password = ''): NpvsDecryptResult {
  if (!isNpvGen2Bytes(b)) {
    return { ok: false, version: 'v5-gen2', error: 'فرمت باینری NPVS نسخه ۵ (Gen-2) معتبر نیست.' };
  }
  const hdrLen = readBE32(b, 5);
  if (hdrLen < 135 || 9 + hdrLen > b.length) {
    return { ok: false, version: 'v5-gen2', error: `طول هدر NPVS v5 نامعتبر است (${hdrLen} بایت).` };
  }
  const h = b.subarray(9, 9 + hdrLen);
  if (h[0] !== 1) {
    return { ok: false, version: 'v5-gen2', error: `نسخه هدر فشرده (${h[0]}) پشتیبانی نمی‌شود.` };
  }
  const configID = h.subarray(1, 17);
  const creator = h.subarray(17, 50);
  const method = h[50];
  const recipients = readBE16(h, 51);

  const unlockMethod =
    method === 2 ? 'appKey' : method === 1 ? 'passphrase' : method === 0 ? 'recipient' : undefined;

  let off = 53 + recipients * (32 + 0x5d);
  let iters = 0;
  let salt = new Uint8Array(0);
  let wrap = new Uint8Array(0);

  if (method === 1) {
    if (off + 80 + 4 > h.length) {
      return { ok: false, version: 'v5-gen2', error: 'بلوک رمز عبور در هدر NPVS v5 ناقص است.' };
    }
    iters = readBE32(h, off);
    salt = h.subarray(off + 4, off + 20);
    wrap = h.subarray(off + 20, off + 80);
    off += 80;
  } else if (method === 2) {
    if (off + 78 + 4 > h.length) {
      return { ok: false, version: 'v5-gen2', error: 'بلوک AppKey در هدر NPVS v5 ناقص است.' };
    }
    if (readBE16(h, off) !== 2) {
      return { ok: false, version: 'v5-gen2', error: 'بلوک AppKey در هدر NPVS v5 یافت نشد.' };
    }
    salt = h.subarray(off + 2, off + 18);
    wrap = h.subarray(off + 18, off + 78);
    off += 78;
  } else {
    return {
      ok: false,
      version: 'v5-gen2',
      unlockMethod: 'recipient',
      error: `این فایل نسل ۵ با کلید خصوصی گیرنده (ECDH Recipient Wrap) قفل شده است (${recipients} گیرنده).`,
    };
  }

  if (off + 4 > h.length) {
    return { ok: false, version: 'v5-gen2', error: 'طول متادیتای NPVS v5 ناقص است.' };
  }
  const metaLen = readBE32(h, off);
  if (metaLen < 16 || off + 4 + metaLen > h.length) {
    return { ok: false, version: 'v5-gen2', error: 'متادیتای NPVS v5 آسیب دیده است.' };
  }
  const prefix = h.subarray(0, off);
  const metaBlob = h.subarray(off + 4, off + 4 + metaLen);

  let bodyOff = 9 + hdrLen;
  if (bodyOff + 16 > b.length) {
    return { ok: false, version: 'v5-gen2', error: 'هدر بدنه NPVS v5 ناقص است.' };
  }
  const nonce = b.subarray(bodyOff, bodyOff + 12);
  const bodyLen = readBE32(b, bodyOff + 12);
  bodyOff += 16;
  if (bodyLen < 32 || bodyOff + bodyLen + 64 > b.length) {
    return { ok: false, version: 'v5-gen2', error: 'بدنه رمزنگاری‌شده NPVS v5 ناقص است.' };
  }
  const body = b.subarray(bodyOff, bodyOff + bodyLen);

  const recoveredKeys: Record<string, string> = {
    configId: bytesToHex(configID),
    'creator.pk': bytesToHex(creator),
  };

  let kdk: Uint8Array | null = null;
  if (method === 2) {
    const a16 = npvGen2A16(salt);
    if (!a16) {
      return {
        ok: false,
        version: 'v5-gen2',
        unlockMethod: 'appKey',
        error: 'جداول رمزگشایی White-Box نسل ۵ هنوز بارگذاری نشده‌اند. لطفاً یک لحظه صبر کنید.',
      };
    }
    recoveredKeys['appKey A16 (Gen-2 Whitebox)'] = bytesToHex(a16);
    kdk = npvGen2KDK(a16, configID);
  } else if (method === 1) {
    if (iters !== undefined && (iters < 1 || iters > 2000000)) {
      return {
        ok: false,
        version: 'v5-gen2',
        unlockMethod: 'passphrase',
        error: 'تعداد دورهای PBKDF2 در این فایل خارج از محدوده مجاز است.',
      };
    }
    const cleanPassword = password.trim();
    const candidatePasswords = cleanPassword
      ? [cleanPassword]
      : ['1234', '123456', '12345678', 'admin', 'npv', 'npvt'];
    let unwrappedDek: Uint8Array | null = null;
    let matchedPass = '';
    for (const cand of candidatePasswords) {
      if (!cand) continue;
      const derived = customPBKDF2HmacSha256(new TextEncoder().encode(cand), salt, iters || 310000, 32);
      const tryDek = chachaOpen(derived, wrap.subarray(0, 12), wrap.subarray(12), salt);
      if (tryDek) {
        kdk = derived;
        unwrappedDek = tryDek;
        matchedPass = cand;
        break;
      }
      // If user didn't enter a password and iters > 50,000, don't brute-force multiple slow PBKDF2 rounds
      if (!cleanPassword && (iters || 0) > 20000) break;
    }
    if (!unwrappedDek || !kdk) {
      return {
        ok: false,
        version: 'v5-gen2',
        needsPassphrase: true,
        unlockMethod: 'passphrase',
        recoveredKeys,
        error: cleanPassword
          ? 'رمز عبور (Passphrase) واردشده برای این کانفیگ نسل ۵ اشتباه است.'
          : `این کانفیگ نسل ۵ (NPVS v5) با رمز عبور قفل شده است (PBKDF2 با ${(iters || 0).toLocaleString()} دور). لطفاً رمز عبور فایل را در کادر رمز وارد کنید.`,
      };
    }
    recoveredKeys['passphrase'] = matchedPass;
    recoveredKeys['kdf'] = `pbkdf2-hmac-sha256 (iters=${iters})`;
  }

  const dek = chachaOpen(kdk!, wrap.subarray(0, 12), wrap.subarray(12), salt);
  if (!dek) {
    return {
      ok: false,
      version: 'v5-gen2',
      unlockMethod,
      recoveredKeys,
      error: 'بازگشایی کلید DEK در کانتینر نسل ۵ با شکست مواجه شد (ChaCha20-Poly1305 Auth Failed).',
    };
  }

  recoveredKeys['KDK'] = bytesToHex(kdk!);
  recoveredKeys['DEK/CEK (hex)'] = bytesToHex(dek);

  const metaKey = hkdfSha256(dek, nonce, new TextEncoder().encode('NPVS-v5/metadata'), 32);
  const metaBytes = chachaOpen(metaKey, nonce, metaBlob, prefix);
  if (!metaBytes) {
    return {
      ok: false,
      version: 'v5-gen2',
      unlockMethod,
      recoveredKeys,
      error: 'متادیتای مهروموم‌شده (Sealed Metadata) در NPVS v5 بازگشایی نشد.',
    };
  }

  let metadataObj: any = {};
  let creatorMessage = '';
  try {
    metadataObj = JSON.parse(new TextDecoder().decode(metaBytes));
    const msgs = [
      metadataObj?.policy?.displayMessage,
      metadataObj?.policy?.customServerMessage,
    ]
      .map((m) => (typeof m === 'string' ? m.replace(/\r\n/g, '\n').trim() : ''))
      .filter(Boolean);
    creatorMessage = msgs.join('\n');
  } catch {
    // Ignore metadata JSON parse error
  }

  if (
    body.length < 38 ||
    body[0] !== 0x4e ||
    body[1] !== 0x50 ||
    body[2] !== 0x46 ||
    body[3] !== 0x01
  ) {
    return {
      ok: false,
      version: 'v5-gen2',
      unlockMethod,
      recoveredKeys,
      error: 'ساختار بدنه NPF\\x01 در کانتینر نسل ۵ معتبر نیست.',
    };
  }

  const contentID = body.subarray(4, 36);
  recoveredKeys['contentId'] = bytesToHex(contentID);
  const count = readBE16(body, 36);
  let bPos = 38;
  const fields = new Map<number, Uint8Array>();
  const fieldKeyPrefix = new TextEncoder().encode('NPV-fields-v1/field/');
  const recordAADPrefix = new TextEncoder().encode('NPV-fields-v1/record/');
  const zeroNonce = new Uint8Array(12);

  for (let idx = 0; idx < count; idx++) {
    if (bPos + 6 > body.length) break;
    const seq = readBE16(body, bPos);
    const blobLen = readBE16(body, bPos + 4);
    bPos += 6;
    if (bPos + blobLen > body.length) break;
    const blob = body.subarray(bPos, bPos + blobLen);
    bPos += blobLen;

    const ptLen = blob.length - 16;
    if (ptLen < 0) continue;

    const seqBE = writeBE16(seq);
    const info = new Uint8Array(fieldKeyPrefix.length + 2);
    info.set(fieldKeyPrefix, 0);
    info.set(seqBE, fieldKeyPrefix.length);
    const fieldKey = hkdfSha256(dek, contentID, info, 32);

    const aad = new Uint8Array(recordAADPrefix.length + contentID.length + 2 + 4);
    aad.set(recordAADPrefix, 0);
    aad.set(contentID, recordAADPrefix.length);
    aad.set(seqBE, recordAADPrefix.length + contentID.length);
    aad.set(writeBE32(ptLen), recordAADPrefix.length + contentID.length + 2);

    const pt = chachaOpen(fieldKey, zeroNonce, blob, aad);
    if (pt) {
      fields.set(seq, pt);
    }
  }

  const sentinelTableBytes = fields.get(0xffff);
  const links: string[] = [];
  const rawConfigObjects: any[] = [];

  if (sentinelTableBytes) {
    try {
      const tableText = new TextDecoder().decode(sentinelTableBytes);
      const spec = JSON.parse(tableText);
      if (Array.isArray(spec.configs)) {
        for (const cfg of spec.configs) {
          const substituted = npvGen2Substitute(cfg, fields);
          rawConfigObjects.push(substituted);
          const link = npvConfigObjToShareLink(substituted);
          if (link) links.push(link);
        }
      }
    } catch {
      // Fallback to raw fields
    }
  }

  const rawLines: string[] = [];
  if (links.length > 0) {
    rawLines.push(...links);
  } else {
    for (const [seq, val] of fields.entries()) {
      if (seq === 0xffff) continue;
      rawLines.push(decodeNpvSentinels(npvGen2FieldText(val)));
    }
  }

  return {
    ok: true,
    version: 'v5-gen2',
    unlockMethod,
    creatorMessage,
    decryptedText: rawLines.join('\n'),
    links,
    rawConfigObjects,
    metadata: metadataObj,
    recoveredKeys,
  };
}

// ============================================================================
// NPVS v5 (Gen-2 Compact Binary Envelope) Builder (Encoder)
// ============================================================================

export function buildNpvGen2Container(
  configObjects: any[],
  options?: { passphrase?: string; displayMessage?: string }
): Uint8Array | null {
  const passphrase = options?.passphrase?.trim() || '';
  const method = passphrase ? 1 : 2;

  const randomBytes = (length: number): Uint8Array => {
    const out = new Uint8Array(length);
    crypto.getRandomValues(out);
    return out;
  };

  const configID = randomBytes(16);
  const creator = randomBytes(33);
  creator[0] = 0x03;
  const salt = randomBytes(16);
  const dek = randomBytes(32);
  const wrapNonce = randomBytes(12);

  let kdk: Uint8Array;
  let keyBlock: Uint8Array;

  if (method === 2) {
    const a16 = npvGen2A16(salt);
    if (!a16) return null;
    kdk = npvGen2KDK(a16, configID);
    const wrappedDek = chachaSeal(kdk, wrapNonce, dek, salt); // 48 bytes
    keyBlock = new Uint8Array(78);
    keyBlock[0] = 0;
    keyBlock[1] = 2; // uint16(2)
    keyBlock.set(salt, 2);
    keyBlock.set(wrapNonce, 18);
    keyBlock.set(wrappedDek, 30);
  } else {
    const iters = 310000;
    kdk = customPBKDF2HmacSha256(new TextEncoder().encode(passphrase), salt, iters, 32);
    const wrappedDek = chachaSeal(kdk, wrapNonce, dek, salt);
    keyBlock = new Uint8Array(80);
    keyBlock.set(writeBE32(iters), 0);
    keyBlock.set(salt, 4);
    keyBlock.set(wrapNonce, 20);
    keyBlock.set(wrappedDek, 32);
  }

  const prefix = new Uint8Array(53 + keyBlock.length);
  prefix[0] = 1; // header version 1
  prefix.set(configID, 1);
  prefix.set(creator, 17);
  prefix[50] = method;
  prefix[51] = 0; // recipients = 0
  prefix[52] = 0;
  prefix.set(keyBlock, 53);

  const bodyNonce = randomBytes(12);

  const metaJson = JSON.stringify({
    issuedAt: new Date().toISOString(),
    policy: {
      attestationLevel: 'NONE',
      configVersion: 5,
      customServerMessage: '',
      displayMessage: options?.displayMessage || 'NPVS v5 (Gen-2 Compact Envelope) — Built with NPVT Studio',
      onlyMobileNetwork: false,
    },
  });
  const metaKey = hkdfSha256(dek, bodyNonce, new TextEncoder().encode('NPVS-v5/metadata'), 32);
  const metaBlob = chachaSeal(metaKey, bodyNonce, new TextEncoder().encode(metaJson), prefix);

  const header = new Uint8Array(prefix.length + 4 + metaBlob.length);
  header.set(prefix, 0);
  header.set(writeBE32(metaBlob.length), prefix.length);
  header.set(metaBlob, prefix.length + 4);

  // Build NPF\x01 fields
  const contentID = sha256(header);
  const fieldEntries: { seq: number; pt: Uint8Array }[] = [];
  let nextSeq = 1;

  function tokenizeScalars(val: any): any {
    if (
      (typeof val === 'string' && val.length > 0) ||
      typeof val === 'number' ||
      typeof val === 'boolean'
    ) {
      const seq = nextSeq++;
      fieldEntries.push({ seq, pt: new TextEncoder().encode(JSON.stringify(String(val))) });
      return seq;
    }
    if (Array.isArray(val)) return val.map(tokenizeScalars);
    if (val && typeof val === 'object') {
      const out: Record<string, any> = {};
      for (const [k, v] of Object.entries(val)) {
        out[k] = tokenizeScalars(v);
      }
      return out;
    }
    return val;
  }

  const substitutedConfigs = configObjects.map(tokenizeScalars);
  const sentinelTablePt = new TextEncoder().encode(JSON.stringify({ configs: substitutedConfigs }));
  fieldEntries.push({ seq: 0xffff, pt: sentinelTablePt });

  const fieldKeyPrefix = new TextEncoder().encode('NPV-fields-v1/field/');
  const recordAADPrefix = new TextEncoder().encode('NPV-fields-v1/record/');
  const zeroNonce = new Uint8Array(12);

  const encryptedRows: Uint8Array[] = [];
  let totalRowsBytes = 0;

  for (const row of fieldEntries) {
    const seqBE = writeBE16(row.seq);
    const info = new Uint8Array(fieldKeyPrefix.length + 2);
    info.set(fieldKeyPrefix, 0);
    info.set(seqBE, fieldKeyPrefix.length);
    const fieldKey = hkdfSha256(dek, contentID, info, 32);

    const aad = new Uint8Array(recordAADPrefix.length + contentID.length + 2 + 4);
    aad.set(recordAADPrefix, 0);
    aad.set(contentID, recordAADPrefix.length);
    aad.set(seqBE, recordAADPrefix.length + contentID.length);
    aad.set(writeBE32(row.pt.length), recordAADPrefix.length + contentID.length + 2);

    const blob = chachaSeal(fieldKey, zeroNonce, row.pt, aad);
    const rowBuf = new Uint8Array(6 + blob.length);
    rowBuf.set(seqBE, 0);
    rowBuf.set(writeBE16(0), 2);
    rowBuf.set(writeBE16(blob.length), 4);
    rowBuf.set(blob, 6);
    encryptedRows.push(rowBuf);
    totalRowsBytes += rowBuf.length;
  }

  const body = new Uint8Array(38 + totalRowsBytes);
  body.set([0x4e, 0x50, 0x46, 0x01], 0); // "NPF\x01"
  body.set(contentID, 4);
  body.set(writeBE16(encryptedRows.length), 36);
  let bOff = 38;
  for (const r of encryptedRows) {
    body.set(r, bOff);
    bOff += r.length;
  }

  const sig = new Uint8Array(64);
  const full = new Uint8Array(9 + header.length + 16 + body.length + 64);
  full.set([0x4e, 0x50, 0x56, 0x53, 5], 0); // "NPVS\x05"
  full.set(writeBE32(header.length), 5);
  full.set(header, 9);
  let fOff = 9 + header.length;
  full.set(bodyNonce, fOff);
  full.set(writeBE32(body.length), fOff + 12);
  fOff += 16;
  full.set(body, fOff);
  full.set(sig, fOff + body.length);

  return full;
}

export function decryptNpvV1Envelope(b: Uint8Array, password = ''): NpvsDecryptResult {
  if (!isNpvV1Bytes(b)) {
    return { ok: false, version: 'v1', error: 'فرمت هدر NPVS v1 معتبر نیست.' };
  }
  const hdrLen = readBE32(b, 5);
  if (hdrLen <= 0 || 9 + hdrLen > b.length) {
    return { ok: false, version: 'v1', error: 'طول هدر JSON در کانتینر NPVS نامعتبر است.' };
  }
  const headerRaw = b.subarray(9, 9 + hdrLen);
  let hdr: any;
  try {
    hdr = JSON.parse(new TextDecoder().decode(headerRaw));
  } catch {
    return { ok: false, version: 'v1', error: 'ساختار هدر JSON در کانتینر NPVS آسیب دیده است.' };
  }

  let off = 9 + hdrLen;
  if (off + 16 > b.length) {
    return { ok: false, version: 'v1', error: 'بخش Nonce/Length در بدنه NPVS ناقص است.' };
  }
  const nonce = b.subarray(off, off + 12);
  const bodyLen = readBE32(b, off + 12);
  off += 16;
  if (bodyLen < 16 || off + bodyLen > b.length) {
    return { ok: false, version: 'v1', error: 'طول بدنه رمزنگاری‌شده NPVS نامعتبر است.' };
  }
  const body = b.subarray(off, off + bodyLen);

  const msgs = [hdr?.policy?.displayMessage, hdr?.policy?.customServerMessage]
    .map((m) => (typeof m === 'string' ? m.replace(/\r\n/g, '\n').trim() : ''))
    .filter(Boolean);
  const creatorMessage = msgs.join('\n');

  const recoveredKeys: Record<string, string> = {};
  if (hdr.configId) recoveredKeys.configId = String(hdr.configId);
  if (hdr.creator?.fp) recoveredKeys['creator.fp'] = String(hdr.creator.fp);
  if (hdr.creator?.pk) recoveredKeys['creator.pk'] = String(hdr.creator.pk);

  let dek: Uint8Array | null = null;
  let unlockMethod: 'appKey' | 'passphrase' | 'recipient' = 'appKey';

  if (hdr.appKey) {
    unlockMethod = 'appKey';
    const salt = b64UrlOrStdToBytes(String(hdr.appKey.salt || ''));
    const wrap = b64UrlOrStdToBytes(String(hdr.appKey.wrap || ''));
    if (!salt || salt.length !== 16 || !wrap || wrap.length !== 60) {
      return { ok: false, version: 'v1', creatorMessage, error: 'مقادیر Salt/Wrap در AppKey نامعتبر است.' };
    }
    const kdks = custodianKDKs(salt);
    for (const kdk of kdks) {
      const opened = chachaOpen(kdk, wrap.subarray(0, 12), wrap.subarray(12), salt);
      if (opened) {
        dek = opened;
        recoveredKeys['KDK'] = bytesToHex(kdk);
        break;
      }
    }
    if (!dek) {
      return { ok: false, version: 'v1', creatorMessage, error: 'هیچ‌یک از کلیدهای White-Box با این کانتینر NPVS مطابقت نداشت.' };
    }
  } else if (hdr.passphrase) {
    unlockMethod = 'passphrase';
    const salt = b64UrlOrStdToBytes(String(hdr.passphrase.salt || ''));
    const wrap = b64UrlOrStdToBytes(String(hdr.passphrase.wrap || ''));
    const iters = Number(hdr.passphrase.iters || 600000);
    if (!salt || !wrap || wrap.length !== 60) {
      return { ok: false, version: 'v1', creatorMessage, error: 'ساختار Passphrase Wrap نامعتبر است.' };
    }
    if (!Number.isFinite(iters) || iters < 1 || iters > 2000000) {
      return { ok: false, version: 'v1', creatorMessage, error: 'تعداد دورهای PBKDF2 در این فایل خارج از محدوده مجاز است.' };
    }
    if (!password) {
      return {
        ok: false,
        version: 'v1',
        needsPassphrase: true,
        unlockMethod: 'passphrase',
        creatorMessage,
        recoveredKeys,
        error: `این فایل NPVS با رمز عبور محافظت شده است${creatorMessage ? ` (پیام سازنده: ${creatorMessage})` : ''}. لطفاً رمز عبور را وارد کنید.`,
      };
    }
    const derived = customPBKDF2HmacSha256(new TextEncoder().encode(password.trim()), salt, iters, 32);
    dek = chachaOpen(derived, wrap.subarray(0, 12), wrap.subarray(12), salt);
    if (!dek) {
      return {
        ok: false,
        version: 'v1',
        needsPassphrase: true,
        unlockMethod: 'passphrase',
        creatorMessage,
        recoveredKeys,
        error: 'رمز عبور واردشده برای بازگشایی این فایل NPVS اشتباه است.',
      };
    }
    recoveredKeys['KDK'] = bytesToHex(derived);
  } else {
    return {
      ok: false,
      version: 'v1',
      unlockMethod: 'recipient',
      creatorMessage,
      error: 'این کانتینر NPVS نیازمند کلید خصوصی گیرنده (ECDH Recipient Key) است.',
    };
  }

  recoveredKeys['DEK/CEK (hex)'] = bytesToHex(dek);
  const ptBytes = chachaOpen(dek, nonce, body, headerRaw);
  if (!ptBytes) {
    return {
      ok: false,
      version: 'v1',
      unlockMethod,
      creatorMessage,
      recoveredKeys,
      error: 'رمزگشایی بدنه اصلی NPVS با شکست مواجه شد.',
    };
  }

  const rawPt = new TextDecoder('utf-8', { fatal: false }).decode(ptBytes);
  const decodedText = decodeNpvSentinels(rawPt);
  const links: string[] = [];
  const rawConfigObjects: any[] = [];

  try {
    const parsed = JSON.parse(decodedText);
    const configs = Array.isArray(parsed?.configs) ? parsed.configs : Array.isArray(parsed) ? parsed : [parsed];
    for (const cfg of configs) {
      const cleanCfg = deepDecodeSentinels(cfg);
      rawConfigObjects.push(cleanCfg);
      const link = npvConfigObjToShareLink(cleanCfg);
      if (link) links.push(link);
    }
  } catch {
    // Plaintext may already be share links
  }

  return {
    ok: true,
    version: 'v1',
    unlockMethod,
    creatorMessage,
    decryptedText: links.length > 0 ? links.join('\n') : decodedText,
    links,
    rawConfigObjects,
    metadata: hdr,
    recoveredKeys,
  };
}

// ============================================================================
// Pure TypeScript AES-128-ECB Decryptor for NetMod (.nm / nm-*://)
// ============================================================================

const AES_SBOX_INV = new Uint8Array([
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]);

const AES_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) AES_SBOX[AES_SBOX_INV[i]] = i;

const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

function gmul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function expandKey128(key: Uint8Array): Uint8Array {
  const rk = new Uint8Array(176);
  rk.set(key.subarray(0, 16));
  const temp = new Uint8Array(4);
  for (let i = 16; i < 176; i += 4) {
    temp.set(rk.subarray(i - 4, i));
    if (i % 16 === 0) {
      const t = temp[0];
      temp[0] = AES_SBOX[temp[1]] ^ RCON[i / 16];
      temp[1] = AES_SBOX[temp[2]];
      temp[2] = AES_SBOX[temp[3]];
      temp[3] = AES_SBOX[t];
    }
    for (let j = 0; j < 4; j++) {
      rk[i + j] = rk[i - 16 + j] ^ temp[j];
    }
  }
  return rk;
}

function aes128DecryptBlock(ct: Uint8Array, rk: Uint8Array): Uint8Array {
  let s = new Uint8Array(ct);
  for (let i = 0; i < 16; i++) s[i] ^= rk[160 + i];

  for (let round = 9; round >= 1; round--) {
    const sr = new Uint8Array(16);
    sr[0] = s[0]; sr[4] = s[4]; sr[8] = s[8]; sr[12] = s[12];
    sr[1] = s[13]; sr[5] = s[1]; sr[9] = s[5]; sr[13] = s[9];
    sr[2] = s[10]; sr[6] = s[14]; sr[10] = s[2]; sr[14] = s[6];
    sr[3] = s[7]; sr[7] = s[11]; sr[11] = s[15]; sr[15] = s[3];
    for (let i = 0; i < 16; i++) {
      s[i] = AES_SBOX_INV[sr[i]] ^ rk[round * 16 + i];
    }
    const mc = new Uint8Array(16);
    for (let c = 0; c < 4; c++) {
      const idx = c * 4;
      const a0 = s[idx], a1 = s[idx + 1], a2 = s[idx + 2], a3 = s[idx + 3];
      mc[idx] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
      mc[idx + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
      mc[idx + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
      mc[idx + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
    s = mc;
  }

  const sr = new Uint8Array(16);
  sr[0] = s[0]; sr[4] = s[4]; sr[8] = s[8]; sr[12] = s[12];
  sr[1] = s[13]; sr[5] = s[1]; sr[9] = s[5]; sr[13] = s[9];
  sr[2] = s[10]; sr[6] = s[14]; sr[10] = s[2]; sr[14] = s[6];
  sr[3] = s[7]; sr[7] = s[11]; sr[11] = s[15]; sr[15] = s[3];
  for (let i = 0; i < 16; i++) {
    s[i] = AES_SBOX_INV[sr[i]] ^ rk[i];
  }
  return s;
}

const NETMOD_KEYS = ['<n3t5yn4^n3tm0d>', '_netsyna_netmod_', 'nicetrybuddygoon'];

export function decryptNetModPayload(base64Payload: string): { text: string; key: string } | null {
  const cleaned = base64Payload.replace(/\s+/g, '');
  const ct = b64UrlOrStdToBytes(cleaned);
  if (!ct || ct.length === 0 || ct.length % 16 !== 0) return null;

  for (const keyStr of NETMOD_KEYS) {
    const keyBytes = new TextEncoder().encode(keyStr);
    const rk = expandKey128(keyBytes);
    const pt = new Uint8Array(ct.length);
    for (let off = 0; off < ct.length; off += 16) {
      pt.set(aes128DecryptBlock(ct.subarray(off, off + 16), rk), off);
    }
    const padLen = pt[pt.length - 1];
    if (padLen < 1 || padLen > 16) continue;
    let validPad = true;
    for (let i = pt.length - padLen; i < pt.length; i++) {
      if (pt[i] !== padLen) {
        validPad = false;
        break;
      }
    }
    if (!validPad) continue;
    const unpadded = pt.subarray(0, pt.length - padLen);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(unpadded);
    return { text, key: keyStr };
  }
  return null;
}
