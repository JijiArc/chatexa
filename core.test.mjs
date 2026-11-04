// Run with: node test/core.test.mjs   (Node 20+)
// Extracts the pure core from index.html and checks crypto, replay defence and static-hosting rules.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const m = html.match(/\/\* CORE-BEGIN \*\/([\s\S]*?)\/\* CORE-END \*\//);
assert.ok(m, 'CORE block not found in index.html');
const api = new Function(m[1] + '\nreturn { deriveKeys, seal, open, acceptIncoming, getState, assessPassword };')();

let n = 0;
const ok = (name, fn) => Promise.resolve().then(fn).then(() => { n++; console.log('ok  ' + name); });

const a = await api.deriveKeys('alpha bravo charlie delta');
const a2 = await api.deriveKeys('  alpha bravo charlie delta ');
const b = await api.deriveKeys('echo foxtrot golf hotel');

await ok('same password gives the same room, different password a different one', () => {
  assert.equal(a.roomId, a2.roomId);
  assert.notEqual(a.roomId, b.roomId);
  assert.match(a.roomId, /^[0-9a-f]{32}$/);
});
await ok('seal/open round trip', async () => {
  const e = await api.seal(a.key, { t: 'm', text: 'hi' });
  assert.deepEqual(await api.open(a2.key, e.iv, e.ct), { t: 'm', text: 'hi' });
});
await ok('wrong key and tampering are rejected', async () => {
  const e = await api.seal(a.key, { x: 1 });
  assert.equal(await api.open(b.key, e.iv, e.ct), null);
  const bad = e.ct.slice(0, -4) + (e.ct.endsWith('AAAA') ? 'BBBB' : 'AAAA');
  assert.equal(await api.open(a.key, e.iv, bad), null);
  assert.equal(await api.open(a.key, 'short', e.ct), null);
});
await ok('every message uses a fresh IV', async () => {
  const ivs = new Set();
  for (let i = 0; i < 50; i++) ivs.add((await api.seal(a.key, { i })).iv);
  assert.equal(ivs.size, 50);
});

const now = 1_000_000_000_000;
const msg = (o = {}) => ({ t: 'm', id: 'id-1', from: 'peer', text: 'hello', sentAt: now - 1000, ttl: 60, ...o });
await ok('fresh message accepted, duplicate rejected', () => {
  const seen = new Map();
  assert.ok(api.acceptIncoming(msg(), now, seen));
  assert.equal(api.acceptIncoming(msg(), now, seen), null);
});
await ok('stale, far-future and malformed payloads rejected', () => {
  const seen = new Map();
  assert.equal(api.acceptIncoming(msg({ id: 'a', sentAt: now - 76_000 }), now, seen), null);
  assert.equal(api.acceptIncoming(msg({ id: 'b', sentAt: now + 16_000 }), now, seen), null);
  assert.equal(api.acceptIncoming(msg({ id: 'c', text: '' }), now, seen), null);
  assert.equal(api.acceptIncoming(msg({ id: 'd', from: '' }), now, seen), null);
  assert.equal(api.acceptIncoming({ t: 'x' }, now, seen), null);
  assert.equal(api.acceptIncoming(null, now, seen), null);
});
await ok('ttl is clamped and a fast clock cannot extend life', () => {
  const seen = new Map();
  assert.equal(api.acceptIncoming(msg({ id: 'e', ttl: 9999 }), now, seen).ttl, 75);
  assert.equal(api.acceptIncoming(msg({ id: 'f', ttl: 1 }), now, seen).ttl, 5);
  assert.equal(api.acceptIncoming(msg({ id: 'g', sentAt: now + 10_000 }), now, seen).sentAt, now);
});
await ok('heartbeats expire after 30 seconds', () => {
  const seen = new Map();
  assert.ok(api.acceptIncoming({ t: 'h', from: 'p', sentAt: now - 10_000 }, now, seen));
  assert.equal(api.acceptIncoming({ t: 'h', from: 'p', sentAt: now - 31_000 }, now, seen), null);
});
await ok('expiry and fade maths', () => {
  const s = { ttl: 60, sentAt: now };
  assert.equal(api.getState(s, now + 30_000).fading, false);
  assert.equal(api.getState(s, now + 57_000).fading, true);
  assert.equal(api.getState(s, now + 60_000).expired, true);
});
await ok('password guidance', () => {
  assert.equal(api.assessPassword('password1').ok, false);
  assert.equal(api.assessPassword('correct horse battery staple').ok, true);
  assert.equal(api.assessPassword('').empty, true);
});
await ok('static-hosting rules: no external scripts, CSP present, only ntfy allowed', () => {
  assert.ok(!/<script[^>]+src=/i.test(html), 'external script found');
  assert.ok(!/<link[^>]+href=["']https?:/i.test(html), 'external stylesheet found');
  const csp = html.match(/Content-Security-Policy" content="([^"]+)"/);
  assert.ok(csp, 'CSP meta missing');
  assert.match(csp[1], /default-src 'none'/);
  assert.match(csp[1], /connect-src https:\/\/ntfy\.sh/);
});

console.log(`\n${n} checks passed`);
