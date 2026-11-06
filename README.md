# Secret Room Chat

A one-to-one chat that is a single static file. No backend, no accounts, no build step.
Two people type the same password; messages are encrypted in the browser (AES-GCM, key from PBKDF2 with 600,000 iterations) and vanish after 30 to 75 seconds.

## Requirements

- A current browser (Chrome, Edge, Firefox, Safari) on both sides.
- The page served over HTTPS (GitHub Pages does this) or opened from `localhost`. Browsers disable encryption APIs otherwise, and the page says so.
- Internet access to the open relays (`ntfy.sh` and a public MQTT broker, see below) and optionally a public STUN server. Manual mode needs neither.

## Deploy on GitHub Pages

1. Create a repository containing `index.html`, `group.html`, `sharing.html` and `search.html` at the root (they link to each other by relative path, so keep them together).
2. Settings, Pages, Source: GitHub Actions or the static root if you publish a single page.
3. Push to `main`.

Any static host works as long as it serves HTTPS. Locally: `python3 -m http.server` and open `http://localhost:8000`.

## Run inside Claude (optional)

Open the same file as an artifact. When Claude's room is available, "Automatic" uses it. Everywhere else it never touches `window.claude`.

## Connection modes

| Mode | Third parties | What they see |
| --- | --- | --- |
| Automatic | The open relays (ntfy.sh and a public MQTT broker), STUN (optional) | Tries a direct link; if two attempts fail, falls back to the encrypted relay |
| Direct only | The open relays for setup, STUN optional | Sealed setup data, timing, your IP. Chat itself never touches the relay |
| Encrypted relay only | The open relays | Every message sealed, but its timing and size are visible. Works on any network |
| Manual codes | None | Nothing. You exchange two encrypted codes yourself |

In a direct link the page closes its relay connection once the channel opens. Untick the STUN box for same-network use; then no STUN server sees your IP.

## Open relays (no account, no setup)

Setup messages and relay-mode chat travel over open public relays that need no account: `ntfy.sh` and a public MQTT broker (`broker.emqx.io`, reached over secure WebSocket). The page talks to all of them at once. A message counts as sent when any relay accepts it, a message that arrives on more than one relay is shown once, and the chat keeps working while at least one relay is up. That is what keeps it going when one free service rate-limits or drops messages.

Everything on a relay is an AES-GCM sealed envelope, so the operators and other users of a public broker cannot read it. They can see room ids, timing and sizes.

- Add or change a broker: edit `MQTT_BROKERS` in `index.html` (a `wss://` URL) and add its `host:port` to `connect-src` in the CSP meta tag. `node test/core.test.mjs` fails if the two disagree.
- Strict networks: an account-free TURN server is no longer available, so when a direct link is impossible (CGNAT, symmetric NAT) Automatic mode falls back to the encrypted relay after two failed attempts. Chat still works; the relays then see timing and size. If you run your own TURN server, put it in `EXTRA_ICE_SERVERS`.
- Public services change. They are free and shared, and they can rate-limit or disappear. That is why there is more than one.

## Optional components

- TURN server: set `EXTRA_ICE_SERVERS` in `index.html` (for example your own coturn). Credentials in a public page are readable by everyone, so use a throwaway account.
- Self-hosted ntfy: change `NTFY_SERVER` and the host in the `connect-src` part of the CSP meta tag. Public ntfy.sh may rate-limit free use; the page backs off and keeps working.

## Trust model

- The password never leaves the page. The relay topic and the key both derive from it; each guess costs 600,000 PBKDF2 rounds, so use four or more random words.
- Public MQTT brokers let anyone list topic names, so other users of the broker can see your room id. Anyone who sees it can test password guesses offline, which makes a strong password matter even more.
- Setup messages (hello, offer, answer) are AES-GCM sealed, so someone without the password cannot read them or swap in their own connection fingerprint.
- Everything lives in memory. Locking, closing the tab, 5 minutes idle, or 2 minutes in the background wipes keys and messages.
- The content security policy permits connections only to the relay hosts (ntfy.sh and the MQTT brokers). No external scripts, fonts or images.

## Not covered

Metadata and timing, IP addresses (each side sees the other's in a direct link), weak passwords, screenshots, spyware, and a hosting account that gets compromised and swaps the code.

## Tests

`node test/core.test.mjs` (Node 20+) checks key derivation, encryption and tamper rejection, replay and clock-drift defences, expiry, the MQTT client and relay fan-out, the File Vault file format, the static hosting rules, and that every page links to every other page without a broken link.

## Files

- `index.html`: one-to-one chat (the whole app)
- `group.html`: group chat placeholder page
- `sharing.html`: encrypted file vault
- `search.html`: archive search page
- `test/core.test.mjs`: tests for the core logic, hosting rules and page links
- `LICENSE`: MIT
