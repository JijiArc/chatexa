// Run with: node test/relay.test.mjs   (Node 20+)
// Exercises relay/worker.js with stubs: routing, origin allowlist, TURN credentials, and the Room durable object.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const src = readFileSync(new URL('../relay/worker.js', import.meta.url), 'utf8')
  .replace(/^import \{ DurableObject \} from "cloudflare:workers";/m, 'class DurableObject { constructor(c, e) { this.ctx = c; this.env = e; } }');
assert.ok(!src.includes('cloudflare:workers'), 'worker import was not stubbed');
globalThis.WebSocketRequestResponsePair = class { constructor(a, b) { this.a = a; this.b = b; } };
const { default: worker, Room } = await import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'));

let n = 0;
const ok = async (name, fn) => { await fn(); n++; console.log('ok  ' + name); };

const room = 'a'.repeat(32);
const good = { Origin: 'https://jijiarc.github.io' };
const rooms = [];
const env = { ALLOWED_ORIGINS: 'https://jijiarc.github.io', ROOM: { getByName: name => ({ fetch: async () => { rooms.push(name); return new Response('do'); } }) } };
const req = (path, headers = {}, method = 'GET') => new Request('https://x.workers.dev' + path, { method, headers });
const realFetch = globalThis.fetch;

await ok('health, routing and room validation', async () => {
  assert.equal((await worker.fetch(req('/health'), env)).status, 200);
  assert.equal((await worker.fetch(req('/ws?room=' + room, { ...good, Upgrade: 'websocket' }), env)).status, 200);
  assert.deepEqual(rooms, [room]);
  assert.equal((await worker.fetch(req('/ws?room=nope', { ...good, Upgrade: 'websocket' }), env)).status, 400);
  assert.equal((await worker.fetch(req('/ws?room=' + room, good), env)).status, 426);
  assert.equal((await worker.fetch(req('/nothing', good), env)).status, 404);
  assert.equal((await worker.fetch(req('/turn', good, 'POST'), env)).status, 405);
});
await ok('only allowed origins may connect', async () => {
  assert.equal((await worker.fetch(req('/ws?room=' + room, { Origin: 'https://evil.example', Upgrade: 'websocket' }), env)).status, 403);
  assert.equal((await worker.fetch(req('/turn', { Origin: 'https://evil.example' }), env)).status, 403);
  assert.equal((await worker.fetch(req('/ws?room=' + room, { Origin: 'https://anything', Upgrade: 'websocket' }), { ...env, ALLOWED_ORIGINS: '' })).status, 200);
});
await ok('/turn gives STUN only without secrets, and filtered TURN servers with them', async () => {
  let r = await worker.fetch(req('/turn', good), env);
  assert.deepEqual((await r.json()).iceServers[0].urls, ['stun:stun.cloudflare.com:3478']);
  assert.equal(r.headers.get('access-control-allow-origin'), 'https://jijiarc.github.io');
  let seen;
  globalThis.fetch = async (u, o) => {
    seen = { u, o };
    return new Response(JSON.stringify({ iceServers: [{ urls: ['stun:s:3478'] },
      { urls: ['turn:t:3478?transport=udp', 'turn:t:53?transport=udp', 'turns:t:443?transport=tcp'], username: 'u', credential: 'c' }] }), { status: 201 });
  };
  try {
    r = await worker.fetch(req('/turn', good), { ...env, TURN_KEY_ID: 'kid', TURN_KEY_API_TOKEN: 'tok' });
    const j = await r.json();
    assert.ok(seen.u.includes('/turn/keys/kid/credentials/generate-ice-servers'));
    assert.equal(seen.o.headers.Authorization, 'Bearer tok');
    assert.deepEqual(j.iceServers[1].urls, ['turn:t:3478?transport=udp', 'turns:t:443?transport=tcp']);
    assert.ok(!JSON.stringify(j).includes('tok'), 'API token leaked');
    globalThis.fetch = async () => { throw new Error('network'); };
    r = await worker.fetch(req('/turn', good), { ...env, TURN_KEY_ID: 'kid', TURN_KEY_API_TOKEN: 'tok' });
    assert.deepEqual((await r.json()).iceServers[0].urls, ['stun:stun.cloudflare.com:3478'], 'must degrade to STUN when Cloudflare is unreachable');
  } finally { globalThis.fetch = realFetch; }
});
await ok('Room relays to the other peer only, ignores oversize messages, drops the oldest on a third connection', async () => {
  const mk = () => ({ sent: [], closed: null, send(m) { this.sent.push(m); }, close(c) { this.closed = c; } });
  const socks = [];
  const ctx = { setWebSocketAutoResponse() {}, getWebSockets: () => socks.filter(s => s.closed === null), acceptWebSocket: s => socks.push(s) };
  const r = new Room(ctx, {});
  const [a, b, c] = [mk(), mk(), mk()];
  socks.push(a, b);
  await r.webSocketMessage(a, 'hello');
  assert.deepEqual(b.sent, ['hello']);
  assert.deepEqual(a.sent, []);
  await r.webSocketMessage(a, 'x'.repeat(30000));
  await r.webSocketMessage(a, new ArrayBuffer(8));
  assert.equal(b.sent.length, 1);
  globalThis.WebSocketPair = function () { return { 0: mk(), 1: c }; };
  await r.fetch(new Request('https://x/ws')).catch(() => {});   // Node cannot build a 101 Response; the eviction happens before that
  assert.equal(a.closed, 4000, 'oldest connection should be replaced');
  assert.equal(b.closed, null);
});

console.log(`\n${n} checks passed`);
