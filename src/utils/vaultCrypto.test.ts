import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isDefaultPassHash,
  resolvePassHash,
  sha256Hex,
  timingSafeEqual,
  verifyPassword,
} from './vaultCrypto.ts';

test('sha256Hex matches known digests', async () => {
  assert.equal(
    await sha256Hex('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
  assert.equal(
    await sha256Hex(''),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
  assert.equal(await sha256Hex('Forge@Studio2026'), resolvePassHash());
});

test('the studio password is accepted and nothing else is', async () => {
  assert.equal(await verifyPassword('Forge@Studio2026'), true);
  assert.equal(await verifyPassword('Forge@Studio2027'), false);
  assert.equal(await verifyPassword(''), false);
  assert.equal(await verifyPassword('   '), false);
});

test('surrounding whitespace is trimmed before hashing', async () => {
  assert.equal(await verifyPassword('  Forge@Studio2026  '), true);
});

test('the build falls back to the default password hash', () => {
  assert.equal(isDefaultPassHash(), true);
  assert.equal(resolvePassHash().length, 64);
});

test('timingSafeEqual compares strings without length leaks', () => {
  assert.equal(timingSafeEqual('abc', 'abc'), true);
  assert.equal(timingSafeEqual('abc', 'abd'), false);
  assert.equal(timingSafeEqual('abc', 'abcd'), false);
  assert.equal(timingSafeEqual('', ''), true);
});
