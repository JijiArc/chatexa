// Run with: node test/core.test.mjs (Node 20+; also works from the repo root)
// Extracts the pure core, the relay channels and the vault format from the pages and checks them.
import { readFileSync, existsSync } from 'node:fs';
import assert from 'node:assert/strict';

const root = existsSync(new URL('./index.html', import.meta.url)) ? './' : '../';
const html = readFileSync(new URL(root + 'index.html', import.meta.url), 'utf8');
const vaultHtml = readFileSync(new URL(root + 'sharing.html', import.meta.url), 'utf8');
const searchHtml = readFileSync(new URL(root + 'search.html', import.meta.url), 'utf8');
const groupHtml = readFileSync(new URL(root + 'group.html', import.meta.url), 'utf8');
const block = (src, name) => {
  const r = src.match(new RegExp('/\\* ' + name + '-BEGIN \\*/([\\s\\S]*?)/\\* ' + name + '-END \\*/'));
  assert.ok(r, name + ' block not found');
  return r[1];
};
const coreSrc = block(html, 'CORE');
const api = new Function(coreSrc + '\nreturn { deriveKeys, seal, open, acceptIncoming, getState, assessPassword, parseIceServers, parseXirsys };')();

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

/* ---------- hosting rules ---------- */
const cspOf = src => {
  const m = src.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/);
  assert.ok(m, 'CSP meta tag missing or misspelled');
  return m[1];
};
const connectOf = src => cspOf(src).match(/connect-src ([^;]+)/)[1].split(/\s+/);

await ok('static-hosting rules: no external scripts, CSP present, no wildcards', () => {
  for (const [name, src] of [['index', html], ['vault', vaultHtml], ['search', searchHtml], ['group', groupHtml]]) {
    assert.ok(!/<script[^>]+src=/i.test(src), name + ': external script found');
    assert.ok(!/<link[^>]+href=["']https?:/i.test(src), name + ': external stylesheet found');
    assert.match(cspOf(src), /default-src 'none'/);
    if (/connect-src/.test(cspOf(src))) assert.ok(!/\*/.test(connectOf(src).join(' ')), name + ': connect-src must not use wildcards');
  }
  assert.ok(connectOf(html).includes('https://ntfy.sh'));
});
await ok('every MQTT broker is wss and allowed by the CSP', () => {
  const list = html.match(/const MQTT_BROKERS = \[([^\]]*)\]/);
  assert.ok(list, 'MQTT_BROKERS constant missing');
  const urls = [...list[1].matchAll(/'([^']+)'/g)].map(x => x[1]);
  assert.ok(urls.length > 0, 'no MQTT broker configured');
  const connect = connectOf(html);
  for (const u of urls) {
    const url = new URL(u);
    assert.equal(url.protocol, 'wss:', u + ' must be wss');
    assert.ok(connect.includes('wss://' + url.host), 'CSP connect-src lacks wss://' + url.host);
  }
});
await ok('the search page CSP allows the archive API and each proxy it falls back to', () => {
  const connect = connectOf(searchHtml);
  const urls = [...searchHtml.matchAll(/(?:apiBase: *"|"|')(https:\/\/api\.[a-z.]+)/g)].map(m => new URL(m[1]).origin);
  assert.ok(urls.length >= 3, 'expected the API and two proxies');
  for (const o of new Set(urls)) assert.ok(connect.includes(o), 'search CSP connect-src lacks ' + o);
});
await ok('Turnix: the API origin is allowed by the CSP and no token is stored in the page', () => {
  const url = html.match(/const TURN_API = '([^']+)'/);
  assert.ok(url, 'TURN_API missing');
  assert.ok(connectOf(html).includes(new URL(url[1]).origin), 'CSP connect-src lacks the Turnix origin');
  assert.ok(!/Bearer [A-Za-z0-9]{16,}/.test(html), 'a bearer token appears to be hard-coded');
});
await ok('Turnix: only well-formed TURN entries are kept, STUN only when asked, junk is dropped', () => {
  const payload = { iceServers: [
    { urls: ['stun:stun.turnix.io:3478'] },
    { username: 'u', credential: 'c', urls: ['turn:eu.turnix.io:3478?transport=udp', 'turns:eu.turnix.io:443?transport=tcp', 'javascript:alert(1)'] },
    { urls: ['turn:no-credentials.example:3478'] },
    null, { urls: 'http://evil.example' }
  ] };
  const turnOnly = api.parseIceServers(payload, false);
  assert.equal(turnOnly.length, 1);
  assert.deepEqual(turnOnly[0].urls, ['turn:eu.turnix.io:3478?transport=udp', 'turns:eu.turnix.io:443?transport=tcp']);
  assert.equal(api.parseIceServers(payload, true).length, 2);
  assert.deepEqual(api.parseIceServers(null, true), []);
  assert.deepEqual(api.parseIceServers({ iceServers: 'x' }, true), []);
});
await ok('Xirsys: the host is allowed by the CSP and the answer is parsed in both known shapes', () => {
  const host = html.match(/const XIRSYS_HOST = '([^']+)'/);
  assert.ok(host && connectOf(html).includes(new URL(host[1]).origin), 'CSP connect-src lacks the Xirsys origin');
  const entry = { username: 'u', credential: 'c', urls: ['stun:s.example:3478', 'turn:t.example:80?transport=tcp', 'turns:t.example:443?transport=tcp'] };
  for (const shape of [[entry], entry]) {
    const out = api.parseXirsys({ s: 'ok', v: { iceServers: shape } }, false);
    assert.equal(out.length, 1);
    assert.deepEqual(out[0].urls, ['turn:t.example:80?transport=tcp', 'turns:t.example:443?transport=tcp']);
  }
  assert.deepEqual(api.parseXirsys({ s: 'error', v: {} }, false), []);
  assert.deepEqual(api.parseXirsys(null, false), []);
});
await ok('every vault upload host is allowed by the vault CSP', () => {
  const urls = [...vaultHtml.matchAll(/url:"(https:\/\/[^\"]+)"/g)].map(x => x[1]);
  assert.ok(urls.length > 0, 'no upload host configured');
  const connect = connectOf(vaultHtml);
  for (const u of urls) assert.ok(connect.includes(new URL(u).origin), 'vault CSP connect-src lacks ' + new URL(u).origin);
});
await ok('no Cloudflare Worker or account-bound storage is referenced any more', () => {
  const re = /workers\.dev|wrangler|RELAY_URL|cloudflarestorage|backblaze|proxyBase/i;
  assert.ok(!re.test(html), 'index.html still references a Worker relay');
  assert.ok(!re.test(vaultHtml), 'sharing.html still references account-bound storage');
  assert.ok(!re.test(searchHtml), 'search.html still references a Worker proxy');
});
await ok('search CORS fallbacks are https and carry the target as an encoded parameter', () => {
  const wraps = [...searchHtml.matchAll(/wrap: url => "(https:\/\/[^\"]+)" \+ encodeURIComponent\(url\)/g)];
  assert.ok(wraps.length >= 1, 'no open CORS proxy configured');
});

/* ---------- MQTT client and relay fan-out ---------- */
const mqttSrc = block(html, 'MQTT');
const multiSrc = block(html, 'MULTI');
const offlineErr = () => Object.assign(new Error('offline'), { code: 'offline' });

const sockets = [];
class FakeWS {
  constructor(url, proto) { this.url = url; this.proto = proto; this.readyState = 0; this.sent = []; sockets.push(this); }
  send(d) { this.sent.push(d); }
  close() { if (this.readyState === 3) return; this.readyState = 3; if (this.onclose) this.onclose(); }
  open() { this.readyState = 1; this.onopen(); }
  recv(bytes) { this.onmessage({ data: Uint8Array.from(bytes).buffer }); }
}
const mq = new Function('WebSocket', 'offline',
  coreSrc + '\n' + mqttSrc + '\nreturn { mqttLen, mqttStr, mqttPacket, mqttReader, makeMqttChannel };')(FakeWS, offlineErr);
const text = u8 => new TextDecoder().decode(u8);
const bytesOf = s => [...new TextEncoder().encode(s)];

await ok('MQTT remaining-length encoding matches the spec examples', () => {
  const v = [[0, [0]], [127, [127]], [128, [0x80, 1]], [16383, [0xFF, 0x7F]], [16384, [0x80, 0x80, 1]],
    [2097151, [0xFF, 0xFF, 0x7F]], [2097152, [0x80, 0x80, 0x80, 1]]];
  for (const [num, want] of v) assert.deepEqual(mq.mqttLen(num), want, String(num));
});
await ok('MQTT reader handles split packets, several packets in one message, and bad lengths', () => {
  const got = [];
  const feed = mq.mqttReader((first, body) => got.push([first, [...body]]));
  const p1 = [0x30, 3, 0xAA, 0xBB, 0xCC], p2 = [0xD0, 0];
  feed(Uint8Array.from([...p1, ...p2]));
  assert.deepEqual(got, [[0x30, [0xAA, 0xBB, 0xCC]], [0xD0, []]]);
  got.length = 0;
  feed(Uint8Array.from(p1.slice(0, 3)));
  assert.equal(got.length, 0);
  feed(Uint8Array.from(p1.slice(3)));
  assert.deepEqual(got, [[0x30, [0xAA, 0xBB, 0xCC]]]);
  assert.throws(() => mq.mqttReader(() => {})(Uint8Array.from([0x30, 0x80, 0x80, 0x80, 0x80, 0x01])), /mqtt_malformed/);
});

const room = 'a'.repeat(32);
const topic = 'chatexa/v2/' + room;
const inbound = (t, obj) => {
  const payload = bytesOf(JSON.stringify(obj)), tb = bytesOf(t);
  const body = [tb.length >> 8, tb.length & 255, ...tb, ...payload];
  assert.ok(body.length < 128);
  return [0x30, body.length, ...body];
};
await ok('MQTT channel: handshake, subscribe, publish, receive, reconnect, stop', async () => {
  const states = [], got = [], fails = [];
  const ch = mq.makeMqttChannel('wss://broker.example:8084/mqtt', room,
    { onEnv: e => got.push(e), onState: up => states.push(up), onFail: c => fails.push(c) });
  assert.equal(ch.up(), false);
  await assert.rejects(ch.post({ x: 1 }), { code: 'offline' });
  ch.start();
  assert.equal(sockets.length, 1);
  assert.equal(sockets[0].url, 'wss://broker.example:8084/mqtt');
  assert.equal(sockets[0].proto, 'mqtt');
  sockets[0].open();

  const connect = sockets[0].sent[0];
  assert.equal(connect[0], 0x10);
  assert.deepEqual([...connect.subarray(2, 14)], [0, 4, 0x4d, 0x51, 0x54, 0x54, 4, 2, 0, 30, 0, 18]);
  assert.equal(connect[1], connect.length - 2);
  assert.match(text(connect.subarray(14)), /^cx[0-9a-f]{16}$/);

  sockets[0].recv([0x20, 2, 0, 0]);
  const sub = sockets[0].sent[1];
  assert.equal(sub[0], 0x82);
  assert.equal(sub[1], sub.length - 2);
  assert.deepEqual([sub[2], sub[3]], [0, 1]);
  assert.equal(sub[5], topic.length);
  assert.equal(text(sub.subarray(6, 6 + topic.length)), topic);
  assert.equal(sub[sub.length - 1], 0);
  assert.equal(ch.up(), false, 'not up before SUBACK');
  sockets[0].recv([0x90, 3, 0, 1, 0]);
  assert.equal(ch.up(), true);
  assert.deepEqual(states, [true]);

  await ch.post({ iv: 'i', ct: 'c' });
  const pub = sockets[0].sent[2];
  assert.equal(pub[0], 0x30);
  assert.equal(text(pub.subarray(4, 4 + topic.length)), topic);
  assert.deepEqual(JSON.parse(text(pub.subarray(4 + topic.length))), { iv: 'i', ct: 'c' });

  sockets[0].recv(inbound(topic, { iv: 'x', ct: 'y' }));
  sockets[0].recv(inbound('someone/else', { iv: 'no', ct: 'no' }));
  const split = inbound(topic, { iv: 'p', ct: 'q' });
  sockets[0].recv(split.slice(0, 7)); sockets[0].recv(split.slice(7));
  assert.deepEqual(got, [{ iv: 'x', ct: 'y' }, { iv: 'p', ct: 'q' }]);

  sockets[0].close();
  assert.equal(ch.up(), false);
  assert.deepEqual(states, [true, false]);
  await new Promise(r => setTimeout(r, 1000));
  assert.equal(sockets.length, 2, 'did not reconnect');
  sockets[1].open(); sockets[1].recv([0x20, 2, 0, 0]); sockets[1].recv([0x90, 3, 0, 1, 0]);
  assert.deepEqual(states, [true, false, true]);
  ch.stop();
  assert.equal(ch.up(), false);
  assert.deepEqual([...sockets[1].sent.at(-1)], [0xE0, 0], 'DISCONNECT not sent');
  await new Promise(r => setTimeout(r, 1200));
  assert.equal(sockets.length, 2, 'reconnected after stop()');
  assert.deepEqual(fails, []);
});
await ok('MQTT channel: a refused connection is closed and retried, not treated as up', async () => {
  const before = sockets.length, states = [];
  const ch = mq.makeMqttChannel('wss://broker.example:8084/mqtt', room, { onEnv() {}, onState: u => states.push(u), onFail() {} });
  ch.start();
  sockets[before].open();
  sockets[before].recv([0x20, 2, 0, 5]);
  assert.equal(sockets[before].readyState, 3);
  assert.equal(ch.up(), false);
  assert.deepEqual(states, []);
  ch.stop();
});

const mkSub = () => {
  const s = { isUp: false, fail: null, started: 0, stopped: 0, posts: [], cb: null,
    up: () => s.isUp, start() { s.started++; }, stop() { s.stopped++; },
    post: async env => { if (s.fail) throw s.fail; s.posts.push(env); } };
  return s;
};
const makeMulti = (sa, sb) => new Function('makeNtfyChannel', 'makeMqttChannel', 'MQTT_BROKERS', 'offline',
  multiSrc + '\nreturn makeMultiChannel;')(
  (id, cb) => { sa.cb = cb; return sa; }, (url, id, cb) => { sb.cb = cb; return sb; }, ['wss://x.example:8084/mqtt'], offlineErr);

await ok('fan-out channel: duplicates across relays are delivered once, malformed ones never', () => {
  const sa = mkSub(), sb = mkSub(), got = [];
  makeMulti(sa, sb)('r', { onEnv: e => got.push(e), onState() {}, onFail() {} });
  sa.cb.onEnv({ iv: '1', ct: 'x' });
  sb.cb.onEnv({ iv: '1', ct: 'x' });
  assert.equal(got.length, 1);
  sb.cb.onEnv({ iv: '1', ct: 'tampered' });
  assert.equal(got.length, 2);
  sa.cb.onEnv({}); sa.cb.onEnv(null); sa.cb.onEnv({ iv: 5, ct: 'x' });
  assert.equal(got.length, 2);
});
await ok('fan-out channel: up while any relay is up; start and stop are idempotent', () => {
  const sa = mkSub(), sb = mkSub(), states = [];
  const ch = makeMulti(sa, sb)('r', { onEnv() {}, onState: u => states.push(u), onFail() {} });
  assert.equal(ch.up(), false);
  sa.isUp = true; sa.cb.onState(true);
  sb.isUp = true; sb.cb.onState(true);
  assert.deepEqual(states, [true]);
  sa.isUp = false; sa.cb.onState(false);
  assert.deepEqual(states, [true], 'one relay left, still up');
  sb.isUp = false; sb.cb.onState(false);
  assert.deepEqual(states, [true, false]);
  ch.start(); ch.start();
  assert.deepEqual([sa.started, sb.started], [1, 1]);
  ch.stop(); ch.stop();
  assert.deepEqual([sa.stopped, sb.stopped], [2, 2]);
  ch.start();
  assert.deepEqual([sa.started, sb.started], [2, 2]);
});
await ok('fan-out channel: a post succeeds if any relay takes it, and surfaces a real refusal over "offline"', async () => {
  const sa = mkSub(), sb = mkSub();
  const ch = makeMulti(sa, sb)('r', { onEnv() {}, onState() {}, onFail() {} });
  sa.fail = offlineErr();
  await ch.post({ iv: 'i', ct: 'c' });
  assert.deepEqual(sb.posts, [{ iv: 'i', ct: 'c' }]);
  sb.fail = Object.assign(new Error('rate'), { code: 'relay_429' });
  await assert.rejects(ch.post({ iv: 'j', ct: 'd' }), { code: 'relay_429' });
  sb.fail = offlineErr();
  await assert.rejects(ch.post({ iv: 'k', ct: 'e' }), { code: 'offline' });
});
await ok('fan-out channel: failure is reported only when every relay has failed, and again after a recovery', () => {
  const sa = mkSub(), sb = mkSub(), fails = [];
  makeMulti(sa, sb)('r', { onEnv() {}, onState() {}, onFail: c => fails.push(c) });
  sa.cb.onFail('relay_closed');
  assert.deepEqual(fails, []);
  sb.cb.onFail('relay_unreachable');
  assert.deepEqual(fails, ['relay_unreachable']);
  sa.cb.onFail('relay_closed');
  assert.equal(fails.length, 1, 'no repeat');
  sa.cb.onState(true);
  sa.cb.onFail('relay_closed');
  assert.equal(fails.length, 2);
});

/* ---------- file vault format ---------- */
const vault = new Function(block(vaultHtml, 'VAULT') + '\nreturn { packFile, unpackFile };')();
await ok('vault: round trip keeps name and bytes, and the host-visible file leaks neither', async () => {
  const data = new Uint8Array(70000).map((_, i) => (i * 31) & 255);
  const packed = await vault.packFile('résumé 📄.pdf', data, 'correct horse battery staple');
  assert.ok(!Buffer.from(packed).includes(Buffer.from('pdf')), 'file name must not appear in the stored file');
  const out = await vault.unpackFile(packed, 'correct horse battery staple');
  assert.equal(out.name, 'résumé 📄.pdf');
  assert.ok(Buffer.from(out.data).equals(Buffer.from(data)));
});
await ok('vault: wrong password, any changed byte, and non-vault files are rejected', async () => {
  const packed = await vault.packFile('a.txt', new TextEncoder().encode('hello'), 'one two three four');
  await assert.rejects(vault.unpackFile(packed, 'five six seven eight'), /Wrong password/);
  for (const at of [10, 25, 40, packed.length - 1]) {
    const bad = Uint8Array.from(packed); bad[at] ^= 1;
    await assert.rejects(vault.unpackFile(bad, 'one two three four'), /Wrong password/, 'byte ' + at);
  }
  await assert.rejects(vault.unpackFile(new Uint8Array(100), 'x'), /not a vault file/);
});

await ok('every page links to every other page, and no local link is broken', () => {
  const pages = ['index.html', 'group.html', 'sharing.html', 'search.html'];
  for (const page of pages) {
    assert.ok(existsSync(new URL(root + page, import.meta.url)), page + ' is missing');
    const src = readFileSync(new URL(root + page, import.meta.url), 'utf8');
    const navHtml = (src.match(/<nav[\s\S]*?<\/nav>/) || [''])[0];
    const hrefs = [...src.matchAll(/\shref="([^"#]+)"/g)].map(m => m[1])
      .filter(h => !/^(https?:|data:|mailto:|\$\{)/.test(h));
    for (const h of hrefs) {
      assert.ok(existsSync(new URL(root + h, import.meta.url)), page + ' links to missing ' + h);
    }
    for (const other of pages) {
      assert.ok(navHtml.includes('href="' + other + '"'), page + ' nav does not link to ' + other);
    }
  }
});

console.log(`\n${n} checks passed`);
