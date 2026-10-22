import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import {
  encryptNPVTChunk,
  decryptNPVTBytes,
  b64ToBytes,
  bytesToText,
  buildNPVTContainerFromLinks,
  buildNPVSV5ContainerFromLinks,
  convertAnyConfigInput,
  parseShareLinkToProfile,
  profileToLink,
  buildSingBoxJsonForProfile,
  buildClashYamlForProfile,
  getSampleNPVTConfig,
  getSampleNPVSV5Config
} from './npvConverter.ts';
import {
  setGen2Tables,
  npvGen2A16,
  npvGen2KDK,
  custodianKDKs,
  decodeNpvSentinels,
  bytesToHex,
  buildNpvGen2Container
} from './npvCryptV5.ts';
import { GEN2_TABLES_B64 } from '../assets/gen2TablesB64.ts';

// Load Gen-2 whitebox tables for tests (tables are inlined as base64, nothing is fetched)
const inflated = new Uint8Array(zlib.inflateSync(Buffer.from(GEN2_TABLES_B64.replace(/\s+/g, ''), 'base64')));
setGen2Tables(inflated);

test('White-box AES-CTR round-trip encrypts and decrypts NPVT1 chunks accurately', () => {
  const originalJson = JSON.stringify({
    name: 'Test VLESS Reality',
    server: 'edge.example.com',
    port: '443',
    protocol: 'vless'
  });

  const encryptedB64 = encryptNPVTChunk(originalJson);
  const rawBytes = b64ToBytes(encryptedB64);
  const decryptedBytes = decryptNPVTBytes(rawBytes);
  const decryptedText = bytesToText(decryptedBytes);

  assert.equal(decryptedText, originalJson);
});

test('buildNPVTContainerFromLinks and convertAnyConfigInput round-trip VLESS, VMess, and Trojan links', () => {
  const sampleNPVT = getSampleNPVTConfig();
  assert.ok(sampleNPVT.startsWith('NPVT1\n'));

  const result = convertAnyConfigInput(sampleNPVT, 'sample.npvt');
  assert.equal(result.errors.length, 0);
  assert.equal(result.nodes.length, 3);

  const [node1, node2, node3] = result.nodes;
  assert.equal(node1.protocol, 'VLESS');
  assert.equal(node1.server, 'de-fra-01.cdn-edge.example.com');
  assert.equal(node1.network, 'WS');
  assert.equal(node1.security, 'TLS');

  assert.equal(node2.protocol, 'VLESS');
  assert.equal(node2.security, 'REALITY');
  assert.equal(node2.pbk, 'mK9xLp3qR7vW2zY5nJ8bH4cF1gT6dS0wA9eU3iO2pL8');

  assert.equal(node3.protocol, 'VMESS');
  assert.equal(node3.network, 'GRPC');
  assert.equal(node3.port, '2053');
});

test('NPVS v5 (Gen-2 White-Box A16 and KDK) matches official cryptographic test vectors', () => {
  const salt = Uint8Array.from(Buffer.from('b3e16e38809576cbf6aaafd638b6b070', 'hex'));
  const cfgId = Uint8Array.from(Buffer.from('96b7d923079c7bc36d1310bd4d111a79', 'hex'));
  const a16 = npvGen2A16(salt);
  assert.ok(a16);
  assert.equal(bytesToHex(a16), 'ffd6b86349231c14b37f6c929e24cd42');

  const kdk = npvGen2KDK(a16, cfgId);
  assert.equal(bytesToHex(kdk), '52043647a29853e765f8efe370fac47155616bfaf653d61b0075a2f183fb6b6b');
});

test('NPVS v1 Custodian KDKs match both v1 and v2 white-box tables', () => {
  const salt = new Uint8Array([0x84, 0x3c, 0xc2, 0xc9, 0x01, 0xce, 0x91, 0x51, 0x6c, 0x38, 0xcc, 0x66, 0x05, 0xb9, 0x2e, 0x47]);
  const kdks = custodianKDKs(salt);
  assert.equal(kdks.length, 2);
  assert.equal(bytesToHex(kdks[0]), 'a9c9058dca50d178b64e0318ad5362be8f8d4103dc83ce2bd0ccd7e404584e3d');
  assert.equal(bytesToHex(kdks[1]), '438a04b521a5952156441a76bee5d8377a67257ff7e8291b220023614d7933d5');
});

test('NPVS v5 (Gen-2 Compact Binary Envelope) sample config encrypts and decrypts all 3 V2Ray nodes and auto-fixes Fastly TLS', () => {
  const sampleV5 = getSampleNPVSV5Config();
  assert.ok(sampleV5);
  assert.ok(sampleV5.base64.startsWith('TlBWUwU'));

  // Test decoding from Base64 text in default auto-smart mode
  const resFromB64 = convertAnyConfigInput(sampleV5.base64, 'sample_v5.npvs');
  assert.equal(resFromB64.errors.length, 0);
  assert.equal(resFromB64.nodes.length, 3);
  assert.ok(resFromB64.recoveredKeys?.['DEK/CEK (hex)']);

  // Node 0 is Fastly 167.82.64.46:443 with sni=firefox.com -> should have allowInsecure=1 & vcn=default.ssl.fastly.net
  const fastlyNode = resFromB64.nodes[0];
  assert.equal(fastlyNode.protocol, 'VLESS');
  assert.equal(fastlyNode.server, '167.82.64.46');
  assert.equal(fastlyNode.sni, 'firefox.com');
  assert.equal(fastlyNode.insecure, true);
  assert.equal(fastlyNode.vcn, 'default.ssl.fastly.net');
  assert.ok(fastlyNode.link.includes('allowInsecure=1'));
  assert.ok(fastlyNode.link.includes('vcn=default.ssl.fastly.net'));
  assert.ok(fastlyNode.fastlyFixedLink?.includes('sni=default.ssl.fastly.net'));

  // Test decoding in fastly-sni mode -> replaces fake firefox.com SNI with default.ssl.fastly.net
  const resFastlySni = convertAnyConfigInput(sampleV5.base64, 'sample_v5.npvs', undefined, '', 'fastly-sni');
  assert.equal(resFastlySni.nodes[0].sni, 'default.ssl.fastly.net');
  assert.equal(resFastlySni.nodes[0].originalSni, 'firefox.com');

  assert.equal(resFromB64.nodes[1].security, 'REALITY');
  assert.equal(resFromB64.nodes[2].protocol, 'TROJAN');
});

test('NPVS v5 with object-form v2rayJson (NapsternetV v2rayProfile) keeps the Trojan password', () => {
  const built = buildNpvGen2Container([
    {
      name: 'Object JSON Trojan',
      address: 'edge.example.com:443',
      v2rayProfile: {
        server: 'edge.example.com',
        serverPort: '443',
        v2rayJson: {
          outbounds: [
            {
              protocol: 'trojan',
              settings: {
                servers: [{ address: 'edge.example.com', port: '443', password: 'obj-secret' }]
              },
              streamSettings: {
                network: 'ws',
                security: 'tls',
                wsSettings: { host: 'cdn.example.com', path: '/ws' },
                tlsSettings: { serverName: 'edge.example.com', allowInsecure: false }
              }
            }
          ]
        }
      }
    }
  ]);
  assert.ok(built);

  const result = convertAnyConfigInput('', 'object-json.npvs', built, '');
  assert.equal(result.errors.length, 0);
  assert.equal(result.nodes.length, 1);
  assert.equal(result.nodes[0].protocol, 'TROJAN');
  assert.equal(result.nodes[0].server, 'edge.example.com');
  assert.ok(result.nodes[0].link.includes('obj-secret'));
});

test('NPVS v5 Passphrase-protected container requires passphrase and unlocks with correct password', () => {
  const built = buildNPVSV5ContainerFromLinks(
    ['vless://d1e2f3a4-5678-49ab-9cde-f0123456789a@locked-v5.example.com:443?security=tls&type=ws#LockedNode'],
    { passphrase: 'mySecretPassword2026' }
  );
  assert.ok(built);

  // Without password -> needsPassphrase
  const lockedRes = convertAnyConfigInput('', 'locked.npvs', built.bytes, '');
  assert.equal(lockedRes.needsPassphrase, true);
  assert.equal(lockedRes.nodes.length, 0);

  // With password -> unlocks
  const unlockedRes = convertAnyConfigInput('', 'locked.npvs', built.bytes, 'mySecretPassword2026');
  assert.equal(unlockedRes.errors.length, 0);
  assert.equal(unlockedRes.nodes.length, 1);
  assert.equal(unlockedRes.nodes[0].server, 'locked-v5.example.com');
});

test('decodeNpvSentinels decodes npvs1: base64 tokens inside NPVO1 configs', () => {
  const raw = 'NPVO1\n{"configs":[{"name":"npvs1:VGVzdCBOb2Rl","v2rayProfile":{"configType":5,"server":"npvs1:c2VydmVyLmV4YW1wbGUuY29t","serverPort":443,"password":"11111111-2222-3333-4444-555555555555","network":"tcp","security":"tls"}}]}';
  const res = convertAnyConfigInput(raw, 'open.npvs');
  assert.equal(res.nodes.length, 1);
  assert.equal(res.nodes[0].name, 'Test Node');
  assert.equal(res.nodes[0].server, 'server.example.com');
});

test('Shadowsocks SIP002 / legacy / 2022 links parse correctly and keep plugins', () => {
  const userinfo = Buffer.from('aes-256-gcm:p@ss:word').toString('base64').replace(/=+$/, '');
  const link = `ss://${userinfo}@1.2.3.4:8388?plugin=${encodeURIComponent('v2ray-plugin;tls;host=cdn.example.com;path=/ws')}#SS%20Node`;
  const p = parseShareLinkToProfile(link);
  assert.equal(p.protocol, 'ss');
  assert.equal(p.server, '1.2.3.4');
  assert.equal(p.serverPort, '8388');
  assert.equal(p.method, 'aes-256-gcm');
  assert.equal(p.password, 'p@ss:word');
  assert.equal(p.plugin, 'v2ray-plugin');
  assert.equal(p.pluginOpts, 'tls;host=cdn.example.com;path=/ws');
  assert.equal(p.name, 'SS Node');

  const rebuilt = profileToLink(p);
  assert.ok(rebuilt.startsWith('ss://'));
  assert.ok(rebuilt.includes('plugin='));
  assert.ok(rebuilt.includes('#SS%20Node') || rebuilt.includes('#SS Node'));

  const sing = buildSingBoxJsonForProfile(p);
  assert.equal(sing.outbounds[0].type, 'shadowsocks');
  assert.equal(sing.outbounds[0].method, 'aes-256-gcm');
  assert.equal(sing.outbounds[0].plugin, 'v2ray-plugin');
  assert.equal(sing.outbounds[0].plugin_opts, 'tls;host=cdn.example.com;path=/ws');

  const clash = buildClashYamlForProfile(p);
  assert.ok(clash.includes('plugin: v2ray-plugin'));
  assert.ok(clash.includes('mode: "websocket"'));
  assert.ok(clash.includes('tls: true'));
  assert.ok(clash.includes('host: "cdn.example.com"'));
  assert.ok(clash.includes('path: "/ws"'));

  // Legacy fully-base64 encoded URI: ss://base64(method:password@host:port)
  const legacy = `ss://${Buffer.from('chacha20-ietf-poly1305:legacyPass@5.6.7.8:443').toString('base64')}#Legacy`;
  const legacyProfile = parseShareLinkToProfile(legacy);
  assert.equal(legacyProfile.method, 'chacha20-ietf-poly1305');
  assert.equal(legacyProfile.password, 'legacyPass');
  assert.equal(legacyProfile.server, '5.6.7.8');

  // SIP002 with a 2022 method (percent-encoded userinfo, password may contain + / =)
  const pass2022 = 'YctPZ6U7xPPcU+gp3u+0pw==';
  const link2022 = `ss://2022-blake3-aes-128-gcm:${encodeURIComponent(pass2022)}@example.com:443#2022`;
  const p2022 = parseShareLinkToProfile(link2022);
  assert.equal(p2022.method, '2022-blake3-aes-128-gcm');
  assert.equal(p2022.password, pass2022);
  assert.ok(profileToLink(p2022).includes(encodeURIComponent(pass2022)));
});

test('TLS fix mode propagates into Sing-box and Clash outputs', () => {
  const sampleV5 = getSampleNPVSV5Config();
  assert.ok(sampleV5);
  const res = convertAnyConfigInput(sampleV5.base64, 'sample_v5.npvs');
  const fastly = res.nodes[0];
  const profile = parseShareLinkToProfile(fastly.link);

  const sing = buildSingBoxJsonForProfile(profile, 'auto-smart');
  assert.equal(sing.outbounds[0].tls.enabled, true);
  assert.equal(sing.outbounds[0].tls.server_name, 'firefox.com');
  assert.equal(sing.outbounds[0].tls.insecure, true);

  const clash = buildClashYamlForProfile(profile, 'auto-smart');
  assert.ok(clash.includes('tls: true'));
  assert.ok(clash.includes('skip-cert-verify: true'));
  assert.ok(clash.includes('servername: "firefox.com"'));

  const singFastly = buildSingBoxJsonForProfile(profile, 'fastly-sni');
  assert.equal(singFastly.outbounds[0].tls.server_name, 'default.ssl.fastly.net');
});
