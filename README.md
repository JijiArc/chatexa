# Secret Room Chat

A one-to-one chat that is a single static file. No backend, no accounts, no build step, no Claude account needed.
Two people type the same password; messages are encrypted in the browser (AES-GCM, key from PBKDF2 with 600,000 iterations) and vanish after 30 to 75 seconds.

## Requirements

- A current browser (Chrome, Edge, Firefox, Safari) on both sides.
- The page served over **HTTPS** (GitHub Pages does this) or opened from `localhost`. Browsers disable encryption APIs otherwise, and the page says so.
- Internet access to `ntfy.sh` (and optionally Cloudflare STUN). Manual mode needs neither.

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
| Automatic | ntfy.sh, Cloudflare STUN (optional) | Tries a direct link; if two attempts fail, falls back to the encrypted relay |
| Direct only | ntfy.sh for setup, STUN optional | Sealed setup data, timing, your IP. Chat itself never touches the relay |
| Encrypted relay only | ntfy.sh | Every message sealed, but its timing and size are visible. Works on any network |
| Manual codes | None | Nothing. You exchange two encrypted codes yourself |

In a direct link the page closes its relay connection once the channel opens. Untick the STUN box for same-network use; then no STUN server sees your IP.

## Optional components

- **TURN server:** if you want direct links through strict firewalls without the relay fallback, set `EXTRA_ICE_SERVERS` in `index.html` (for example your own coturn). Credentials in a public page are readable by everyone, so use a throwaway account.
- **Self-hosted ntfy:** change `NTFY_SERVER` and the host in the `connect-src` part of the CSP meta tag. Public ntfy.sh may rate-limit free use (check its docs for current limits); the page backs off its announcements and sends relay heartbeats slowly, and shows a clear message if the relay refuses a send.

## Trust model

- The password never leaves the page. The relay topic and the key both derive from it; each guess costs 600,000 PBKDF2 rounds, so use four or more random words.
- Setup messages (hello, offer, answer) are AES-GCM sealed, so someone without the password cannot read them or swap in their own connection fingerprint.
- Everything lives in memory. Locking, closing the tab, 5 minutes idle, or 2 minutes in the background wipes keys and messages.
- The content security policy permits connections only to the ntfy host. No external scripts, fonts or images.

## Not covered

Metadata and timing, IP addresses (each side sees the other's in a direct link), weak passwords, screenshots, spyware, and a hosting account that gets compromised and swaps the code.

## Tests

`node test/core.test.mjs` (Node 20+) checks key derivation, encryption and tamper rejection, replay and clock-drift defences, expiry, and that the page has no external scripts and keeps its CSP. CI runs it before every deploy.

## Files

- `index.html`: the whole app
- `test/core.test.mjs`: tests for the core logic and hosting rules
- `.github/workflows/pages.yml`: test and deploy
- `LICENSE`: MIT
