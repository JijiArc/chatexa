// Cloudflare Worker + Durable Object relay for Secret Room Chat.
//
// It does two jobs and never sees plaintext (every payload is AES-GCM sealed in the browser):
//   GET /ws?room=<32 hex>  WebSocket relay. One Durable Object per room forwards each message to the other peer.
//   GET /turn              Short-lived Cloudflare TURN credentials, so strict NATs / mobile carriers can still connect.
//   GET /health            Plain "ok".
//
// Deploy:  cd relay && npx wrangler deploy
// TURN (optional but strongly recommended):
//   npx wrangler secret put TURN_KEY_ID
//   npx wrangler secret put TURN_KEY_API_TOKEN
// Create the TURN key in the Cloudflare dashboard under Realtime > TURN.

import { DurableObject } from "cloudflare:workers";

const ROOM_RE = /^[0-9a-f]{32}$/;
const MAX_MESSAGE_CHARS = 24000;   // the client caps sealed envelopes well below this
const MAX_PEERS = 2;               // one-to-one chat
const STUN_ONLY = { iceServers: [{ urls: ["stun:stun.cloudflare.com:3478"] }] };

function allowedOrigin(request, env) {
  const list = String(env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  if (list.length === 0) return "*";                       // not configured: open
  const origin = request.headers.get("Origin") || "";
  return list.includes(origin) ? origin : null;
}

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors(origin) }
  });
}

async function turnCredentials(env, origin) {
  if (!env.TURN_KEY_ID || !env.TURN_KEY_API_TOKEN) return json(STUN_ONLY, 200, origin);
  try {
    const r = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${env.TURN_KEY_API_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({ ttl: 3600 }),
        signal: AbortSignal.timeout(5000)
      }
    );
    if (!r.ok) return json(STUN_ONLY, 200, origin);
    const data = await r.json();
    // Port 53 is blocked by browsers and would stall ICE gathering (the client does not trickle).
    const iceServers = (data.iceServers || []).map(s => ({
      ...s,
      urls: [].concat(s.urls).filter(u => !/:53(\?|$)/.test(u))
    }));
    return json({ iceServers }, 200, origin);
  } catch (e) {
    return json(STUN_ONLY, 200, origin);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = allowedOrigin(request, env);

    if (url.pathname === "/health") return new Response("ok");
    if (origin === null) return new Response("Origin not allowed", { status: 403 });
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });
    if (request.method !== "GET") return new Response("Method not allowed", { status: 405 });

    if (url.pathname === "/turn") return turnCredentials(env, origin);

    if (url.pathname === "/ws") {
      if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected WebSocket", { status: 426 });
      const room = url.searchParams.get("room") || "";
      if (!ROOM_RE.test(room)) return new Response("Bad room", { status: 400 });
      return env.ROOM.getByName(room).fetch(request);
    }

    return new Response("Not found", { status: 404 });
  }
};

// One instance per room. Uses the Hibernation API, so idle rooms cost nothing and sockets survive eviction.
export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // Keepalive: the client sends "ping" and gets "pong" without waking this object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request) {
    const [client, server] = Object.values(new WebSocketPair());
    // A third connection means an older one is a ghost (a phone that changed network, a dead tab): drop the oldest.
    const open = this.ctx.getWebSockets();
    while (open.length >= MAX_PEERS) {
      const old = open.shift();
      try { old.close(4000, "replaced"); } catch (e) { /* already gone */ }
    }
    this.ctx.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    if (typeof message !== "string" || message.length > MAX_MESSAGE_CHARS) return;
    for (const peer of this.ctx.getWebSockets()) {
      if (peer === ws) continue;
      try { peer.send(message); } catch (e) { /* peer is closing */ }
    }
  }

  async webSocketClose(ws, code) {
    const ok = code >= 1000 && code < 5000 && ![1005, 1006, 1015].includes(code);
    try { ws.close(ok ? code : 1000, "bye"); } catch (e) { /* already closed */ }
  }

  async webSocketError(ws) {
    try { ws.close(1011, "error"); } catch (e) { /* already closed */ }
  }
}
