// Cloudflare Worker: optional same-origin-style API gateway for Memento.
// Deploy with `wrangler deploy`. This is NOT an open proxy: it only forwards
// a small allowlist of GET endpoints to api.archivegenocide.com.

const UPSTREAM = "https://api.archivegenocide.com";
const ALLOWED_PATHS = [
  /^\/v1\/meta$/,
  /^\/v1\/archives$/,
  /^\/v1\/clips$/,
  /^\/v1\/clips\/[0-9]+$/,
  /^\/v1\/withdrawn$/
];
const ALLOWED_QUERY = new Set([
  "q", "type", "from", "to", "archive", "has_geo", "sort", "page", "per_page"
]);
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Accept, Content-Type",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin"
};

function response(body, status = 200, extra = {}) {
  return new Response(body, { status, headers: { ...CORS, ...extra } });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return response(null, 204);
    if (!["GET", "HEAD"].includes(request.method)) {
      return response(JSON.stringify({ error: "Method not allowed" }), 405, {
        "Content-Type": "application/json", "Allow": "GET, HEAD, OPTIONS"
      });
    }

    const path = url.pathname.replace(/\/+$/, "") || "/";
    if (!ALLOWED_PATHS.some(pattern => pattern.test(path))) {
      return response(JSON.stringify({ error: "Endpoint not allowed" }), 404, {
        "Content-Type": "application/json"
      });
    }

    for (const key of url.searchParams.keys()) {
      if (!ALLOWED_QUERY.has(key)) {
        return response(JSON.stringify({ error: `Query parameter not allowed: ${key}` }), 400, {
          "Content-Type": "application/json"
        });
      }
    }
    if (url.searchParams.getAll("q").some(q => q.length > 200)) {
      return response(JSON.stringify({ error: "Search text must be 200 characters or fewer" }), 400, {
        "Content-Type": "application/json"
      });
    }
    if (url.searchParams.get("per_page") &&
        (!/^\d+$/.test(url.searchParams.get("per_page")) ||
         Number(url.searchParams.get("per_page")) < 1 ||
         Number(url.searchParams.get("per_page")) > 100)) {
      return response(JSON.stringify({ error: "per_page must be between 1 and 100" }), 400, {
        "Content-Type": "application/json"
      });
    }

    const upstreamUrl = new URL(UPSTREAM + path);
    for (const [key, value] of url.searchParams) upstreamUrl.searchParams.append(key, value);

    // Cloudflare cache API response for 5 minutes. Query strings remain part of cache keys.
    const cacheKey = new Request(upstreamUrl.toString(), { method: "GET" });
    const cache = caches.default;
    let cached = await cache.match(cacheKey);
    if (cached) {
      const headers = new Headers(cached.headers);
      for (const [k, v] of Object.entries(CORS)) headers.set(k, v);
      headers.set("X-Memento-Cache", "HIT");
      return new Response(cached.body, { status: cached.status, headers });
    }

    let upstream;
    try {
      upstream = await fetch(upstreamUrl.toString(), {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "User-Agent": "MementoArchiveSearch/1.0 (Cloudflare Worker)"
        },
        signal: AbortSignal.timeout(18000)
      });
    } catch {
      return response(JSON.stringify({ error: "Upstream archive API is temporarily unreachable" }), 502, {
        "Content-Type": "application/json", "Cache-Control": "no-store"
      });
    }

    const headers = new Headers(CORS);
    headers.set("Content-Type", upstream.headers.get("Content-Type") || "application/json; charset=utf-8");
    headers.set("Cache-Control", upstream.ok ? "public, max-age=300" : "no-store");
    headers.set("X-Memento-Cache", "MISS");
    const result = new Response(upstream.body, { status: upstream.status, headers });

    if (upstream.ok && request.method === "GET") {
      const cacheCopy = result.clone();
      ctx.waitUntil(cache.put(cacheKey, cacheCopy));
    }
    return result;
  }
};
