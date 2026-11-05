# Secret Room Chat

A one-to-one chat that is a single static file. No backend, no accounts, no build step,
Two people type the same password; messages are encrypted in the browser (AES-GCM, key from PBKDF2 with 600,000 iterations) and vanish after 30 to 75 seconds.

## Requirements

- A current browser (Chrome, Edge, Firefox, Safari) on both sides.
- The page served over **HTTPS** (GitHub Pages does this) or opened from `localhost`. Browsers disable encryption APIs otherwise, and the page says so.
- Internet access to the relay (`ntfy.sh`, or your own Cloudflare relay, see below) and optionally Cloudflare STUN/TURN. Manual mode needs neither.

## Deploy on GitHub Pages

1. Create a repository containing `index.html`, `test/`, `LICENSE` and `.github/workflows/pages.yml`.
2. Settings, Pages, Source: **GitHub Actions**.
3. Push to `main`. The workflow runs the tests, then publishes. The URL shows in the workflow run.

Any static host works as long as it serves HTTPS. Locally: `python3 -m http.server` and open `http://localhost:8000`.

## Run inside Claude (optional)

Open the same file as an artifact. When Claude's room is available, "Automatic" uses it. Everywhere else it never touches `window.claude`.

## Connection modes

| Mode | Third parties | What they see |
| --- | --- | --- |
| Automatic | Relay (ntfy.sh or your Cloudflare worker), Cloudflare STUN/TURN (optional) | Tries a direct link; if two attempts fail, falls back to the encrypted relay |
| Direct only | ntfy.sh for setup, STUN optional | Sealed setup data, timing, your IP. Chat itself never touches the relay |
| Encrypted relay only | ntfy.sh | Every message sealed, but its timing and size are visible. Works on any network |
| Manual codes | None | Nothing. You exchange two encrypted codes yourself |

In a direct link the page closes its relay connection once the channel opens. Untick the STUN box for same-network use; then no STUN server sees your IP.

## Reliable relay on Cloudflare (recommended)

Public ntfy.sh is a free shared service. It rate-limits publishers, and its stream can drop messages while it
reconnects. Direct links with STUN alone also fail on many mobile and carrier networks (CGNAT, symmetric NAT). The
usual symptom is that messages arrive sometimes and not at other times, mostly when the two people are on different networks.

`relay/` is a small Cloudflare Worker with one Durable Object per room. It replaces ntfy.sh as the setup and relay
channel (a WebSocket with automatic reconnect and keepalive) and hands out short-lived TURN credentials so direct links
work across strict networks. It only ever forwards sealed envelopes.

1. `cd relay && npx wrangler deploy`. Note the `https://chatexa-relay.<your-subdomain>.workers.dev` URL it prints.
2. TURN (optional but strongly recommended): create a TURN key in the Cloudflare dashboard (Realtime, TURN), then
   `npx wrangler secret put TURN_KEY_ID` and `npx wrangler secret put TURN_KEY_API_TOKEN`.
3. In `relay/wrangler.jsonc`, set `ALLOWED_ORIGINS` to the origin your page is served from if it is not
   `https://jijiarc.github.io` (an empty string allows anyone), then deploy again.
4. In `index.html`, set `RELAY_URL` to the worker URL and add its host to `connect-src` in the CSP meta tag, both as
   `https://host` and `wss://host`. `node test/core.test.mjs` fails if the two disagree.

Check it with `https://<worker-url>/health` (prints `ok`) and `https://<worker-url>/turn` (lists STUN, plus TURN once the secrets are set).

## Optional components

- **TURN server:** the Cloudflare relay above provides TURN. Alternatively set `EXTRA_ICE_SERVERS` in `index.html` (for example your own coturn). Credentials in a public page are readable by everyone, so use a throwaway account.
- **Self-hosted ntfy:** change `NTFY_SERVER` and the host in the `connect-src` part of the CSP meta tag. Public ntfy.sh may rate-limit free use (check its docs for current limits); the page backs off its announcements and sends relay heartbeats slowly, and shows a clear message if the relay refuses a send.

## Trust model

- The password never leaves the page. The relay topic and the key both derive from it; each guess costs 600,000 PBKDF2 rounds, so use four or more random words.
- Setup messages (hello, offer, answer) are AES-GCM sealed, so someone without the password cannot read them or swap in their own connection fingerprint.
- Everything lives in memory. Locking, closing the tab, 5 minutes idle, or 2 minutes in the background wipes keys and messages.
- The content security policy permits connections only to the relay host (ntfy.sh, plus your Cloudflare worker if you set one). No external scripts, fonts or images.

## Not covered

Metadata and timing, IP addresses (each side sees the other's in a direct link), weak passwords, screenshots, spyware, and a hosting account that gets compromised and swaps the code.

## Tests

`node test/core.test.mjs` (Node 20+) checks key derivation, encryption and tamper rejection, replay and clock-drift defences, expiry, and that the page has no external scripts and keeps its CSP. CI runs it before every deploy.

## Files

- `index.html`: the whole app
- `relay/worker.js`, `relay/wrangler.jsonc`: optional Cloudflare relay and TURN credentials
- `test/core.test.mjs`: tests for the core logic and hosting rules
- `.github/workflows/pages.yml`: test and deploy
- `LICENSE`: MIT
