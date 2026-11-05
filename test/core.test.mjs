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
await ok('static-hosting rules: no external scripts, CSP present, only the relay hosts allowed', () => {
  assert.ok(!/<script[^>]+src=/i.test(html), 'external script found');
  assert.ok(!/<link[^>]+href=["']https?:/i.test(html), 'external stylesheet found');
  const csp = html.match(/Content-Security-Policy" content="([^"]+)"/);
  assert.ok(csp, 'CSP meta missing');
  assert.match(csp[1], /default-src 'none'/);
  assert.match(csp[1], /connect-src[^;]*https:\/\/ntfy\.sh/);
  const connect = csp[1].match(/connect-src ([^;]+)/)[1];
  assert.ok(!/\*/.test(connect), 'connect-src must not use wildcards');
});
await ok('RELAY_URL, when set, is allowed by the CSP over https and wss', () => {
  const relay = html.match(/const RELAY_URL = '([^']*)'/);
  assert.ok(relay, 'RELAY_URL constant missing');
  if (!relay[1]) return;                                   // empty: the page uses ntfy.sh only
  const u = new URL(relay[1]);
  assert.equal(u.protocol, 'https:', 'RELAY_URL must be https');
  const connect = html.match(/Content-Security-Policy" content="[^"]*connect-src ([^;"]+)/)[1].split(/\s+/);
  assert.ok(connect.includes('https://' + u.host), 'CSP connect-src lacks https://' + u.host);
  assert.ok(connect.includes('wss://' + u.host), 'CSP connect-src lacks wss://' + u.host);
});

/* The WebSocket relay channel: reconnects after a drop, never reconnects after stop(), and does not queue sends while down. */
const chanSrc = html.match(/function makeWsChannel[\s\S]*?\n}\n/)[0];
await ok('ws channel reconnects with backoff, stops cleanly, refuses to send while down', async () => {
  const sockets = [];
  class FakeWS {
    constructor(url) { this.url = url; this.readyState = 0; this.sent = []; sockets.push(this); }
    send(d) { this.sent.push(d); }
    close() { if (this.readyState === 3) return; this.readyState = 3; if (this.onclose) this.onclose(); }
    open() { this.readyState = 1; this.onopen(); }
  }
  const states = [], got = [];
  const make = new Function('RELAY_URL', 'WebSocket', 'offline', chanSrc + '\nreturn makeWsChannel;')(
    'https://relay.example.workers.dev', FakeWS, () => Object.assign(new Error('offline'), { code: 'offline' }));
  const ch = make('a'.repeat(32), { onEnv: e => got.push(e), onState: up => states.push(up), onFail: () => {} });
  assert.equal(ch.up(), false);
  await assert.rejects(ch.post({ x: 1 }), { code: 'offline' });
  ch.start();
  assert.equal(sockets.length, 1);
  assert.equal(sockets[0].url, 'wss://relay.example.workers.dev/ws?room=' + 'a'.repeat(32));
  sockets[0].open();
  assert.equal(ch.up(), true);
  await ch.post({ iv: 'i', ct: 'c' });
  assert.deepEqual(JSON.parse(sockets[0].sent[0]), { iv: 'i', ct: 'c' });
  sockets[0].onmessage({ data: 'pong' });
  sockets[0].onmessage({ data: JSON.stringify({ iv: 'x', ct: 'y' }) });
  assert.deepEqual(got, [{ iv: 'x', ct: 'y' }]);
  sockets[0].close();                                      // network drop
  assert.equal(ch.up(), false);
  assert.deepEqual(states, [true, false]);
  await new Promise(r => setTimeout(r, 1000));             // first retry is due within ~0.85s at most
  assert.equal(sockets.length, 2, 'did not reconnect');
  sockets[1].open();
  assert.deepEqual(states, [true, false, true]);
  ch.stop();
  assert.equal(ch.up(), false);
  await new Promise(r => setTimeout(r, 1200));
  assert.equal(sockets.length, 2, 'reconnected after stop()');
});

await ok('ws channel kick reconnects immediately and replaces a socket that does not answer', async () => {
  const sockets = [];
  class FakeWS {
    constructor() { this.readyState = 0; this.sent = []; sockets.push(this); }
    send(d) { this.sent.push(d); }
    close() { if (this.readyState === 3) return; this.readyState = 3; if (this.onclose) this.onclose(); }
    open() { this.readyState = 1; this.onopen(); }
  }
  const make = new Function('RELAY_URL', 'WebSocket', 'offline', chanSrc + '\nreturn makeWsChannel;')('https://r.example.workers.dev', FakeWS, () => new Error('offline'));
  const ch = make('b'.repeat(32), { onEnv() {}, onState() {}, onFail() {} });
  ch.start(); sockets[0].open();
  ch.kick();
  assert.deepEqual(sockets[0].sent, ['ping']);
  await new Promise(r => setTimeout(r, 4300));              // no pong: the socket is dropped and replaced
  assert.equal(sockets[0].readyState, 3);
  await new Promise(r => setTimeout(r, 1100));
  assert.equal(sockets.length, 2, 'did not reconnect after a dead socket');
  ch.stop();
});

/* Standby rail: send on the primary when it is up, on the standby when it is not, on both when asked. */
const dualSrc = html.match(/function makeDualChannel[\s\S]*?\n}\n/)[0];
await ok('dual channel routes to primary, standby, or both', async () => {
  const mkCh = up => ({ up: () => up.v, posted: [], async post(e) { if (up.fail) throw new Error('x'); this.posted.push(e); }, start() {}, stop() {}, kick() {} });
  const A = mkCh({ v: true }), B = mkCh({ v: true });
  const make = new Function('makeWsChannel', 'makeNtfyChannel', 'offline', dualSrc + '\nreturn makeDualChannel;')(() => A, () => B, () => new Error('offline'));
  const d = make('c'.repeat(32), { onEnv() {} });
  await d.post('e1');                                       // primary up: only the primary
  assert.deepEqual([A.posted, B.posted], [['e1'], []]);
  await d.post('e2', true);                                 // both rails
  assert.deepEqual([A.posted, B.posted], [['e1', 'e2'], ['e2']]);
  const A2 = mkCh({ v: false }), B2 = mkCh({ v: true });
  const d2 = new Function('makeWsChannel', 'makeNtfyChannel', 'offline', dualSrc + '\nreturn makeDualChannel;')(() => A2, () => B2, () => new Error('offline'))('c'.repeat(32), { onEnv() {} });
  await d2.post('e3');                                      // primary down: standby
  assert.deepEqual([A2.posted, B2.posted], [[], ['e3']]);
  A2.up = () => true; A2.post = async () => { throw new Error('boom'); };
  await d2.post('e4');                                      // primary claims up but fails: standby takes over
  assert.deepEqual(B2.posted, ['e3', 'e4']);
});

/* The transport state machine, with fake WebRTC and a fake relay channel. */
const tpSrc = html.match(/\/\* --- Transport B:[\s\S]*?(?=\/\* --- Transport C:)/)[0];
async function harness(opts) {
  const keys = await api.deriveKeys('alpha bravo charlie delta');
  const links = [], posted = [], events = [], errors = [];
  let chanCb = null, chanUp = true, started = 0, stopped = 0;
  const factory = (roomId, cb) => { chanCb = cb; return { start() { started++; }, stop() { stopped++; }, kick() {}, up: () => chanUp, async post(e, both) { posted.push({ e, both }); } }; };
  const fakeLink = cb => {
    let isOpen = false;
    const pc = { signalingState: 'stable', localDescription: { sdp: 'S' }, async createOffer() { return {}; }, async createAnswer() { return {}; },
      async setLocalDescription() { this.signalingState = this.signalingState === 'stable' ? 'have-local-offer' : 'stable'; }, async setRemoteDescription() { this.signalingState = 'stable'; } };
    const L = { pc, dc: { send() {} }, makeChannel() {}, isOpen: () => isOpen, close() { L.closed = true; } };
    links.push({ L, cb, up() { isOpen = true; cb.onUp(L); }, down() { isOpen = false; cb.onDown(L); } });
    return L;
  };
  const make = new Function('RELAY_URL', 'makeDualChannel', 'makeNtfyChannel', 'seal', 'open', 'newLink', 'gathered', 'offline', 'DRIFT_SEC', 'SIGNAL_MAX_AGE_SEC', 'HELLO_STEPS', 'CONNECT_TIMEOUT_MS',
    tpSrc + '\nreturn makeP2PTransport;');
  const tp = make('', factory, factory, api.seal, api.open, fakeLink, async () => {}, () => new Error('offline'), 15, 30, [100000], 100000)(
    keys.roomId, () => keys.key, () => 'aaa', opts);
  await tp.open({ onEnv: e => events.push(e), onUp: up => events.push({ up }), onError: e => errors.push(e.code) });
  const deliver = async obj => { await chanCb.onEnv(await api.seal(keys.key, obj)); await new Promise(r => setTimeout(r, 20)); };
  const opened = async () => Promise.all(posted.map(p => api.open(keys.key, p.e.iv, p.e.ct)));
  const inject = async env => { await chanCb.onEnv(env); await new Promise(r => setTimeout(r, 20)); };
  return { tp, links, posted, events, errors, deliver, inject, opened, keys, counts: () => ({ started, stopped }) };
}
await ok('automatic mode: a direct link that drops moves the chat onto the relay at once', async () => {
  const x = await harness({ relayOnly: false, fallback: true });
  await x.deliver({ t: 'hello', from: 'zzz', sentAt: Date.now(), r: 1 });          // we have the smaller id, so we offer
  assert.ok((await x.opened()).some(p => p.t === 'offer' && p.to === 'zzz'), 'no offer sent');
  assert.ok(x.posted.every(p => p.both === true), 'setup messages must go on every rail');
  await x.deliver({ t: 'answer', from: 'zzz', to: 'aaa', sdp: 'A', sentAt: Date.now() });
  x.links[0].up();
  assert.equal(x.tp.connected(), true);
  const stoppedBefore = x.counts().stopped;
  assert.ok(stoppedBefore >= 1, 'relay connection should close once the direct link is up');
  x.links[0].down();
  assert.equal(x.tp.relay, true, 'did not fall back to the relay');
  assert.ok(x.errors.includes('relay_fallback'));
  assert.equal(x.tp.connected(), true, 'relay should be usable immediately');
  x.tp.close();
});
await ok('direct-only mode does not silently use the relay', async () => {
  const x = await harness({ relayOnly: false, fallback: false });
  await x.deliver({ t: 'hello', from: 'zzz', sentAt: Date.now(), r: 1 });
  await x.deliver({ t: 'answer', from: 'zzz', to: 'aaa', sdp: 'A', sentAt: Date.now() });
  x.links[0].up(); x.links[0].down();
  assert.equal(x.tp.relay, false);
  x.tp.close();
});
await ok('on the relay: a rejoining peer gets a heartbeat, and the same envelope is handled once', async () => {
  const x = await harness({ relayOnly: true, fallback: false });
  assert.equal(x.tp.relay, true);
  const ups = () => x.events.filter(e => e && e.up === true).length;
  const before = ups();
  await x.deliver({ t: 'hello', from: 'zzz', sentAt: Date.now(), r: 1 });           // peer reloaded and is looking for us
  assert.equal(ups(), before + 1, 'should answer so the peer switches to the relay too');
  const env = await api.seal(x.keys.key, { t: 'm', id: 'm1', from: 'zzz', text: 'hi', sentAt: Date.now(), ttl: 60 });
  const chatEvents = () => x.events.filter(e => e && e.iv).length;
  await x.inject(env); await x.inject(env);                                        // same envelope on two rails, or replayed
  assert.equal(chatEvents(), 1, 'a repeated envelope must be handled once');
  await x.inject(await api.seal(x.keys.key, { t: 'm', id: 'm1', from: 'zzz', text: 'hi', sentAt: Date.now(), ttl: 60 }));
  assert.equal(chatEvents(), 2, 'a resend (new iv, same id) must still reach the app, which re-confirms it');
  x.tp.close();
});

/* App-level delivery: unconfirmed messages are retried, repeats are re-confirmed. */
const retrySrc = html.match(/const RETRY_FIRST_MS[\s\S]*?\nfunction retryUnconfirmed[\s\S]*?\n}\n/)[0];
await ok('unconfirmed messages are retried, escalate to every rail, and stop once delivered', () => {
  const calls = [];
  const state = { connected: true, fail: null };
  const run = new Function('messages', 'tp', 'transmit', 'paint', retrySrc + '\nreturn retryUnconfirmed;');
  const msgs = [
    { mine: true, status: 'sending', payload: { id: 'a' }, tries: 0, lastTry: 0 },
    { mine: true, status: 'delivered', payload: { id: 'd' }, tries: 0, lastTry: 0 },
    { mine: false, status: 'sending', payload: { id: 'x' }, tries: 0, lastTry: 0 }
  ];
  const retry = run(msgs, { connected: () => state.connected }, (p, both) => { calls.push([p.id, !!both]); return state.fail ? Promise.reject(state.fail) : Promise.resolve(); }, () => {});
  retry(1000); assert.equal(calls.length, 0, 'retried before the first wait was over');
  retry(3000); assert.deepEqual(calls, [['a', false]]);
  retry(3500); assert.equal(calls.length, 1, 'retried too early');
  retry(8000); assert.deepEqual(calls[1], ['a', true], 'second retry should use every rail');
  state.connected = false; retry(60000); assert.equal(calls.length, 2, 'must not send while disconnected');
  state.connected = true; msgs[0].status = 'delivered'; retry(120000); assert.equal(calls.length, 2, 'delivered messages are not resent');
});
await ok('a repeated message is confirmed again on every rail instead of being ignored', async () => {
  const onChatSrc = html.match(/async function onChat\(d\) \{[\s\S]*?\n}\n/)[0];
  const sent = [], shown = [];
  const seen = new Map();
  const make = new Function('key', 'open', 'sessionId', 'acceptIncoming', 'seen', 'peerSeen', 'transmit', 'sendHeartbeat', 'updatePresence', 'messages', 'paint', 'getState',
    'let lastReplyAt = 0;\n' + onChatSrc + '\nreturn onChat;');
  const onChat = make(a.key, api.open, 'me', api.acceptIncoming, seen, new Map(), (o, both) => { sent.push([o.t, o.id, !!both]); return Promise.resolve(); }, () => {}, () => {}, shown, () => {}, api.getState);
  const env = await api.seal(a.key, { t: 'm', id: 'm9', from: 'peer', text: 'hello', sentAt: Date.now(), ttl: 60 });
  await onChat(env);
  assert.equal(shown.length, 1);
  assert.deepEqual(sent, [['a', 'm9', false]]);
  await onChat(await api.seal(a.key, { t: 'm', id: 'm9', from: 'peer', text: 'hello', sentAt: Date.now(), ttl: 60 }));
  assert.equal(shown.length, 1, 'a repeat must not be shown twice');
  assert.deepEqual(sent[1], ['a', 'm9', true], 'the repeat must be confirmed again on every rail');
});

console.log(`\n${n} checks passed`);
