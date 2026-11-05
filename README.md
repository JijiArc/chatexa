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

`relay/` is a small Cloudflare Worker with one Durable Object per room. It carries setup and relay-mode traffic over a
WebSocket (automatic reconnect, keepalive) and hands out short-lived TURN credentials so direct links work across strict
networks. It only ever forwards sealed envelopes. ntfy.sh stays on as a standby, so neither provider is a single point of failure.

### Deploy from GitHub (no terminal)

1. Cloudflare dashboard, My Profile, API Tokens, Create Token, template **Edit Cloudflare Workers**. Copy the token.
   Copy your **Account ID** from the Workers & Pages overview page.
2. Optional but strongly recommended: Cloudflare dashboard, Realtime, TURN, create a TURN key. Copy its **Key ID** and **API token**.
3. GitHub repository, Settings, Secrets and variables, Actions, add these repository secrets:
   `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and (optional) `TURN_KEY_ID`, `TURN_KEY_API_TOKEN`.
4. Actions tab, **Deploy relay to Cloudflare**, Run workflow. It deploys `relay/` and sets the TURN secrets. The run
   summary shows your worker URL and checks `/health` and `/turn`. It runs again by itself whenever `relay/` changes on `main`.
5. In `index.html`, set `RELAY_URL` to the worker URL and add its host to `connect-src` in the CSP meta tag, both as
   `https://host` and `wss://host`. `node test/core.test.mjs` fails if the two disagree.
6. If the page is not served from `https://jijiarc.github.io`, set `ALLOWED_ORIGINS` in `relay/wrangler.jsonc` to its origin
   (an empty string allows any site).

Without the Action: `cd relay && npx wrangler deploy`, then `npx wrangler secret put TURN_KEY_ID` and `TURN_KEY_API_TOKEN`.

### What happens when something fails

| Problem | What the page does |
| --- | --- |
| Strict NAT / carrier network blocks a direct link | TURN relays the WebRTC traffic (UDP, TCP or TLS on 443), still end to end encrypted |
| Direct link still cannot be set up (two attempts) | Automatic mode moves the chat onto the encrypted relay |
| A working direct link drops (network change, Wi-Fi to mobile) | After 8 seconds of silence the link is discarded and the chat continues on the relay at once |
| Cloudflare relay unreachable or blocked | ntfy.sh carries setup and chat; both rails are listened to, so either can deliver |
| Relay connection dies silently (sleeping phone, NAT timeout) | A ping every 20 seconds detects it; the page also checks it when the network comes back or the tab returns to the foreground, then reconnects with backoff |
| A message is lost in transit, or its confirmation is | Unconfirmed messages are resent every few seconds while they live, from the third attempt on over every rail; repeats are dropped and confirmed again |
| Offline when sending | The message waits ("waiting for connection") and is sent when the connection is back, as long as it has not expired |
| Other person reloads or rejoins while you are on the relay | You answer their hello with a relay heartbeat, so they switch to the relay immediately instead of timing out |
| Both providers down, or both networks blocked | Use **Manual codes**: no server involved |

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

`node test/core.test.mjs` (Node 20+) checks key derivation, encryption and tamper rejection, replay and clock-drift defences, expiry, the relay channels (reconnect, standby routing, failover when a direct link drops, retries), and that the page has no external scripts and keeps its CSP. `node test/relay.test.mjs` checks the Cloudflare worker (routing, origin allowlist, TURN credentials, room behaviour). The `Tests` workflow runs both on every push.

## Files

- `index.html`: the whole app
- `relay/worker.js`, `relay/wrangler.jsonc`: optional Cloudflare relay and TURN credentials
- `.github/workflows/deploy-relay.yml`: deploys the relay from GitHub; `.github/workflows/ci.yml`: runs the tests
- `test/relay.test.mjs`: tests for the Cloudflare worker
- `test/core.test.mjs`: tests for the core logic and hosting rules
- `.github/workflows/pages.yml`: test and deploy
- `LICENSE`: MIT
