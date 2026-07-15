# ΦNET — Overlay Network

A Tor-inspired anonymous network rooted in number theory.

<img width="1059" height="687" alt="578398323-12ae45da-9ac1-49c8-bd33-bc61366b3e7d" src="https://github.com/user-attachments/assets/ec843bed-880f-4eef-82d1-7d114c449ac3" />

<img width="1059" height="687" alt="578398405-64537e4a-27f1-4e7b-a0ab-c192fc060282" src="https://github.com/user-attachments/assets/79872da1-fd4d-47fb-b8ff-a4d31937a5f1" />

<img width="1059" height="687" alt="578398490-efdbf237-748b-41cc-9d2c-42e7902a8ea2" src="https://github.com/user-attachments/assets/daba591f-4ec4-4909-917b-2f554b9a62be" />


## Architecture

```
phinet/
├── phinet-core/          Core library: certs, crypto, onion, DHT, HS, board
├── phinet-daemon/        Network daemon binary  (phinet-daemon)
├── phinet-cli/           Hidden service CLI     (phi)
├── phinet-bwscanner/     Bandwidth measurement → signed authority votes
└── phinet-browser/       Tauri + React browser  (phinet-browser)
```

## Building

**Prerequisites:** Rust 1.80+, Node 18+, npm 9+

```bash
# Build everything
cargo build --release

# Browser only
cd phinet-browser
npm install
cargo tauri build
```

## Quick Start

```bash
# 1. Start the overlay node
phinet-daemon --port 7700

# 2. Create a hidden service
phi new "my-blog"
phi init "my-blog" ./my-blog/
# edit ./my-blog/index.html
phi deploy <hs_id> ./my-blog/

# 3. Open the browser
phinet-browser
# navigate to:  <hs_id>.phinet
```

## Internet Setup

```bash
# Bootstrap node (VPS, open port 7700 inbound)
phinet-daemon --port 7700 --cert-bits 512

# Your machine
phinet-daemon --port 7700 --bootstrap <vps-ip>:7700
phinet-browser
```

## Certificate Sizes

| Bits | Gen time | PoW memory | Security |
|------|----------|------------|----------|
| 256  | ~0.3s    | 64 MiB     | Development |
| 512  | ~1s      | 256 MiB    | Standard |
| 1024 | ~8s      | 1 GiB      | High |
| 2048 | ~60s     | 4 GiB      | Maximum |

## Security Features

| Feature | Status |
|---------|--------|
| V2 certs (256–2048 bit, J-first construction) | ✓ |
| Hybrid X25519 + ML-KEM-1024 key exchange | ✓ |
| ChaCha20-Poly1305 per-hop encryption | ✓ |
| Argon2id admission PoW (Sybil resistance) | ✓ |
| Constant-rate traffic padding (flow correlation) | ✓ |
| Intro-puzzle DoS defence (auto-adjusting difficulty) | ✓ |
| Guard node pinning + /16 geographic diversity | ✓ |
| φ-cluster identity rotation | ✓ |
| Hidden services NOT indexed (no discoverability) | ✓ |
| PIR-style oblivious descriptor fetch | ✓ |
| 3-hop default / 5-hop high-security | ✓ |
| Forward secrecy per session | ✓ |
| **Ed25519 scalar-mul descriptor blinding** (v2) | ✓ |
| **Directory authority consensus** (k-of-n threshold) | ✓ |
| **Pluggable transport abstraction** (PT-1 SOCKS5) | ✓ |
| **Bandwidth scanner** (signed third-party attestations) | ✓ |
| **Real bandwidth measurement** (`bw-test:N` payload streaming) | ✓ |
| **HSM-friendly authority signer** (`ConsensusSigner` trait) | ✓ |
| **Consensus distribution** (HTTP serve + fetch with verify) | ✓ |
| **Client-only mode** (`--client-only` daemon flag) | ✓ |
| **Padding scheduler** (3 impls + per-circuit pump emitting RELAY_DROP) | ✓ |
| **Client-authorized hidden services** (X25519 + AEAD, signed wire format) | ✓ |
| **Layer-2 vanguards** (HS guard-discovery defense, wired into circuit build) | ✓ |
| **RTT congestion control** (Prop 324 Vegas, per-circuit adaptive cwnd) | ✓ |
| **Fixed-size link cells** (uniform 2 KB frames, fragmented + reassembled) | ✓ |
| **Encrypted link handshake** (cert/PoW carried under ephemeral X25519 DH) | ✓ |
| **Pluggable transports wired** (obfs4/meek/snowflake via `--transport`) | ✓ |
| **PT bridge / server-side transport** (run a bridge via `--bridge-transport`) | ✓ |
| **com** — E2E-encrypted messenger over ΦNET (sealed messages + web UI) | ✓ |
| **com offline delivery** — store-and-forward mailbox (gossip + pull) | ✓ |
| **com metadata privacy** — blinded mailbox addresses + sealed sender | ✓ |
| **com anonymous delivery** — circuit-injected store (sender-anonymous) | ✓ |
| **com groups & channels** — shared-key groups + per-sender Ed25519 signatures | ✓ |
| **com native app** — Tauri desktop client (`phinet-browser/`) | ✓ |
| Graceful shutdown (SIGTERM/SIGINT) | ✓ |
| Idle circuit eviction with cascading cleanup | ✓ |
| HS descriptor 12h auto-republish | ✓ |

## Wire Protocol

All messages: `[4-byte LE length][JSON payload]`, encrypted after session
establishment with ChaCha20-Poly1305 (per-direction nonce counters).

After session establishment the link carries **only fixed-size cells**: every
frame is exactly `LINK_CELL` (2 KB) of plaintext plus the AEAD tag. A message
smaller than one cell is padded to fill it; a message larger than one cell is
fragmented across several identical cells (`[more(1)][chunk_len(2)][data][pad]`
per cell) and reassembled by the receiver. A passive on-link observer therefore
sees a stream of indistinguishable frames and learns only the *number* of
cells, never any frame's true content size — it cannot tell a circuit RELAY
cell from a DHT query from a padding cell, and a bulk transfer looks like N
identical frames rather than one obviously-large frame. This is Tor's link
model (an OR connection carries fixed cells and nothing else) and supersedes
simple length padding, which still leaked a large message's size in one frame.
Applied in both send paths (`wire::send_session`, `PeerConn::send_msg`) and
reassembled in `wire::recv_session`. See `phinet-core/src/wire.rs` —
`frame_message`, `read_cell`, `LINK_CELL`.

**Encrypted handshake.** The link handshake exchanges only ephemeral X25519
public keys in the clear (fixed-size, random-looking); both sides derive a
session key from them and then send the certificate, admission PoW, and static
key *encrypted* under that session and framed as fixed link cells. A passive
observer therefore cannot read the certificate or infer `cert-bits` at
connection setup, nor easily fingerprint the exchange as ΦNET. *Threat model:*
this defeats passive traffic analysis; an active man-in-the-middle can still
perform two ephemeral DHs and observe the (public) cert, since the ephemeral DH
is unauthenticated. Binding the ephemeral to the static identity key (ntor-style)
to also resist active MitM is the natural next step. See the handshake in
`phinet-core/src/node.rs` (`handle_incoming` / `connect`).

### Congestion control (Proposal 324)

Per-circuit flow control uses a TCP-Vegas controller instead of a fixed
window. Each end times SENDMEs to sample RTT, estimates the in-network queue
as `cwnd·(rtt − rtt_min)/rtt`, and grows/shrinks the congestion window to hold
the queue in the Vegas `alpha`..`beta` band (exponential slow-start until the
first congestion signal, then additive steady state). Throughput now tracks
actual path capacity rather than being pinned at a fixed 1000-cell window.
Constants mirror Tor's `cc_*` consensus parameters. Both `OriginCircuit` (client
outbound) and `RelayCircuit` (exit backward) run their own controller. See
`phinet-core/src/congestion.rs` — `Vegas`.

## Hidden Service Addresses

```
identity = Ed25519 long-term keypair (persisted at ~/.phinet/hs_identity_<name>.json)
hs_id    = SHA-256("phi-hs-v1:" || identity_pub) → 64 hex chars
address  = <hs_id>.phinet
```

Hidden-service descriptors are signed by the HS identity key and published
under epoch-blinded subkeys. Receivers verify the signature before caching.
Descriptors auto-republish every 12 hours so services stay reachable
indefinitely. Addresses are **not indexed** anywhere — share them out-of-band.

## Cryptographic Construction Details

### Ed25519 scalar-mul descriptor blinding (v2)

Hidden service descriptors are signed under per-epoch **blinded
subkeys** rather than the long-term identity. The blinding scheme is
proper rend-spec-v3-style scalar multiplication on the Ed25519 group:

```
h         = H_512(BLIND_TAG || identity_pub || epoch_be) mod L
s_blinded = h * s   mod L      (s = clamped Ed25519 secret scalar)
A_blinded = h * A              (A = identity public point, scalar-mult)
```

The signer produces an EdDSA signature manually using `s_blinded`:
`r = H(prefix' || msg) mod L`, `R = rB`, `k = H(R || A_blinded || msg) mod L`,
`S = r + k·s_blinded mod L`. The deterministic-nonce prefix is itself
blinded (`prefix' = H(BLIND_V2_NONCE_TAG || prefix || epoch)`) so
nonces don't link across epochs.

Verifiers **independently re-derive** `A_blinded = h * identity_pub`
from the descriptor's identity_pub field and compare against the
descriptor's published `blinded_pub`. A mismatch is fatal: it means
either the signer used a different scheme or a malicious party tried
to substitute their own keypair. This closes the last "trust the
published blinded_pub" gap that the prior KDF-seed scheme had.

See `phinet-core/src/hs_identity.rs` — `blinding_scalar_v2`,
`derive_blinded_pub_v2`, `sign_blinded_v2`. Wire format unchanged
from v1.

### Directory authority consensus

A small set of hardcoded authorities (typically 4–9) each:

1. Observe the network independently (descriptor gossip, bandwidth
   scans, flag-policy checks).
2. Publish a signed **vote** every ~1 hour over the peer set they see.
3. Merge votes deterministically into a **consensus document**:
   median bandwidth per peer, majority-vote per flag, lex tiebreak
   on host/port disagreements.
4. Each authority signs the canonical consensus bytes with their
   long-term Ed25519 identity. Sigs are exchanged out-of-band.

Clients fetch the consensus from any authority and verify ≥ ⌈2n/3⌉
authority signatures over the canonical bytes. Sigs from unknown
authorities are silently ignored (don't count toward threshold but
don't reject the document). Sigs from the same authority twice count
as one. Sigs over a tampered consensus all fail.

Threshold trust model: compromise of fewer than ⌈2n/3⌉ authorities
cannot poison the consensus. Adding/removing an authority requires a
software release — this is the only point in the system that's not
fully decentralized, deliberately, for sybil resistance.

See `phinet-core/src/directory.rs` — `DirectoryAuthority`,
`build_consensus`, `verify_consensus`, `PeerFlags`.

### Pluggable transport abstraction

The `Transport` trait abstracts how peer-to-peer ΦNET connections are
carried. The default `PlainTcp` is what `node.rs` uses today. A
`SubprocessTransport` integrates with PT-1 spec binaries (obfs4proxy,
meek-client, snowflake-client) via SOCKS5 — bridge args are passed
verbatim in the SOCKS5 username field as the spec requires.

The SOCKS5 client supports both no-auth and user/pass paths, validates
all reply codes, and propagates errors with helpful diagnostics
(connection refused, host unreachable, etc). Subprocess management
itself (spawning the PT binary, parsing CMETHOD lines from its stdout)
is a deployment-time concern; in tests, the SOCKS5 endpoint is
injected via `set_socks_addr`.

See `phinet-core/src/transport.rs` — `Transport`, `Listener`,
`PlainTcp`, `SubprocessTransport`, `socks5_connect`.

### Bandwidth scanner

`phinet-bwscanner` is a separate binary that runs on each directory
authority. Every ~hour it:

1. Loads the current consensus
2. Measures throughput of every relay listed (median of N passes)
3. Adjusts the RUNNING flag based on measurement success
4. Outputs a signed authority vote ready for consensus merging

```bash
# Once: generate authority identity
phinet-bwscanner gen-identity --out ~/.phinet/auth.json

# Periodically (cron / systemd-timer):
phinet-bwscanner scan \
  --identity   ~/.phinet/auth.json \
  --consensus  /var/phinet/consensus.json \
  --output     /var/phinet/votes/vote-$(date +%s).json \
  --network-id phinet-mainnet
```

The `MeasurementTransport` trait abstracts how throughput is observed,
so the scanner pipeline (median aggregation, vote signing, RUNNING
flag derivation) is independent of the actual measurement mechanism.
A `--simulate` flag generates plausible synthetic values for
end-to-end testing without a live network. Real measurements through
the daemon's circuit-build path are a ~150-line addition once a
production network exists.

See `phinet-bwscanner/src/lib.rs` — `Scanner`, `MeasurementTransport`,
`RelayMeasurement`. The `votes_to_consensus_e2e` integration test
proves outputs feed correctly into `build_consensus` with proper
outlier rejection.

## Browser

The bundled Tauri browser (`phinet-browser`) supports both `.phinet` hidden
services and standard HTTP/HTTPS clearnet URLs. Clearnet uses pure-Rust
TLS via `rustls` — no system OpenSSL dependency, fully cross-platform.

**Architecture caveat:** the browser fetches top-level HTML via the Rust
backend, then renders it in an iframe via `srcdoc`. This means:

- Top-level page text and structure render correctly
- Subresources (`<img>`, external CSS, JS that fetches) won't load —
  the iframe has no URL context for them
- `.phinet` sites bundled as single-page HTML work fully
- Fully-featured clearnet browsing requires a future custom-protocol
  handler (Tauri 2 supports this — outside current scope)

The address bar accepts:
- `<64 hex>.phinet` — current Ed25519-derived hidden service
- `<40 hex>.phinet` — legacy BLAKE2b hidden service (still recognized)
- `https://example.com` — standard HTTPS
- `http://example.com` — flagged as not secure
- Bare text — treated as DuckDuckGo search

## CLI Reference

```
phi new <n>                  Create a hidden service
phi init <n> [dir]           Generate starter site files
phi deploy <hs_id> <dir>        Deploy directory
phi put <hs_id> <path> <file>   Upload single file
phi list                        List services
phi info <hs_id>                Show service files
phi delete <hs_id>              Delete service
phi register <hs_id>            Publish to live network
phi peers                       Show connected peers
phi status                      Daemon status
```

## Daemon Flags

```
phinet-daemon [OPTIONS]

  --port <PORT>         Listen port          [default: 7700]
  --host <HOST>         Listen host          [default: 0.0.0.0]
  --bootstrap HOST:PORT Bootstrap peer(s)
  --cert-bits <BITS>    256 | 512 | 1024 | 2048  [default: 256]
  --ctl-port <PORT>     Control socket       [default: 7799]
  --reset-identity      Regenerate identity
  --high-security       5-hop circuits + max padding
  --verbose             Debug logging

  Pluggable transports (censorship circumvention):
  --transport <NAME>       PT name: obfs4 | meek_lite | snowflake
  --pt-binary <PATH>       Path to the PT executable (e.g. obfs4proxy)
  --pt-bridge-args <ARGS>  Per-bridge params, e.g. "cert=…;iat-mode=0"
  --pt-state-dir <PATH>    PT state dir [default: ~/.phinet/pt-state]

  Run as a bridge (server-side PT, so others can reach you when ΦNET is blocked):
  --bridge-transport <NAME>  PT name to serve: obfs4 | meek_lite | snowflake
  --bridge-bind <ADDR:PORT>  Public address the bridge listens on, e.g. 0.0.0.0:443
  --bridge-options <OPTS>    Optional TOR_PT_SERVER_TRANSPORT_OPTIONS string
```

**Running a bridge.** `--bridge-transport obfs4 --bridge-bind 0.0.0.0:443
--pt-binary /usr/bin/obfs4proxy` spawns a server-side obfs4 proxy that listens
on the public port, de-obfuscates incoming connections, and forwards them to the
node's own local ΦNET listener (`127.0.0.1:<port>`). The node keeps using
`PlainTcp` internally — the PT is a shim in front. On startup the daemon prints
the **bridge line** (`obfs4 <addr:port> cert=…;iat-mode=0`); share it with
clients, who connect with `--transport obfs4 --pt-bridge-args "cert=…;iat-mode=0"
--bootstrap <bridge-host>:<port>`. For a bridge you typically also pass
`--host 127.0.0.1` so the raw ΦNET port isn't reachable except through the PT.

## License

MIT

## com — messaging over ΦNET

`com` is a Telegram-style messenger built on ΦNET. ΦNET provides the anonymity
and metadata resistance (circuits, guards, fixed-size cells, obfuscated
transports); `com` adds end-to-end confidentiality and authenticity of the
message content, so relays and mailbox nodes carrying a message can neither read
nor forge it. See `phinet-core/src/com.rs`.

**Identity.** Your com address is your ΦNET node identity `(node_id,
static_pub)`. No separate accounts.

**Sealing.** Each message mixes an ephemeral X25519 key (per-message forward
secrecy) with the sender's static key (sender authentication) via
`HKDF → ChaCha20-Poly1305`, close to the Noise `X` pattern. A successful open
proves the sender holds the claimed static key; tampering, forged senders, and
wrong-recipient all fail the AEAD tag.

**Using it.** The daemon serves a self-contained web UI at
`http://127.0.0.1:<ctl_port+2>` (default **7801**) — open it in a browser to get
a contacts list (currently-connected peers), conversation threads, and an
end-to-end-encrypted chat. The same operations are on the control socket
(`com_send`, `com_threads`, `com_thread`) and the localhost HTTP API
(`/api/whoami`, `/api/peers`, `/api/threads`, `/api/thread?peer=`,
`/api/send?peer=&text=`).

**Delivery.** `com_send` seals the message and injects it into the network as a
store-and-forward `ComStore` gossip (flooded with dedup). This covers both
cases: an online recipient receives it over the link and files it; for an
offline recipient, mailbox nodes hold the sealed envelope (24h TTL) until the
recipient reconnects and pulls it (`ComFetch`/`ComMail`, recipient-authenticated
so a peer can only pull its *own* mail). A background loop pulls mail on
reconnect. Keys are learned from authenticated peers and from opened messages,
so you can seal a reply to someone even after they go offline.

**Metadata privacy.** Envelopes use **sealed sender** and **blinded addressing**:
the sender's identity is encrypted *inside* the ciphertext (relays never see who
sent a message), and the recipient is addressed by a per-epoch blinded tag
`HKDF(recipient_pub ‖ epoch)` rather than a node id (relays never see who it's
for). A mailbox node learns only "opaque tag X holds a sealed blob." Sealing mixes
an ephemeral→recipient DH (confidentiality) with a sender→recipient static DH
(authentication), so a successful open both decrypts and proves the sender holds
the key revealed inside — no separate signature. Blinded addresses rotate daily;
recipients pull against a ±1-epoch window.

**Groups & channels.** A group/channel is a shared symmetric key plus membership.
The creator distributes the key by sending each member a sealed 1:1 **invite** (so
key delivery inherits sealed-sender privacy). Group messages are sealed under a
*per-message* key `HKDF(group_key ‖ random_salt)` (no nonce reuse across senders),
**signed** with the sender's Ed25519 key, and delivered to a per-epoch blinded
*group* address every member can compute. Each message carries the sender's
signing key inside the ciphertext; a member's key is bound to its node id on first
authenticated sighting (TOFU) and enforced thereafter, so **one member cannot
spoof another member's sender id** — the forgery fails signature/binding checks.
Channels are the same machinery with an `is_channel` flag and admin set.

**Anonymous delivery.** `com_send` prefers **circuit injection**: the sender
builds a circuit through relays and injects the sealed envelope at the exit
(`RelayCommand::ComInject`, compact-encoded to fit a relay cell), so its own guard
never sees it originate com traffic. It falls back to plain gossip if no circuit
can be built. Combined with sealed sender + blinded addressing, delivery reveals
neither party's identity to relays, and the sender's entry point is hidden behind
a circuit.

*Residual:* an attacker who already knows a victim's static key can still compute
their blinded address and observe mail volume/timing (not content). First-message
TOFU binding means a race on a member's very first post; membership-signed key
announcements would close that.

**Clients.** Two front-ends ship: the daemon-served web UI at
`http://127.0.0.1:<ctl_port+2>` (no build step), and a native **Tauri desktop
app** in `phinet-browser/` (`npm install && npm run tauri build`) that bridges to the
same control socket. Both support 1:1 chats, groups, and channels. See
`DEPLOYMENT.md` for running com across VPSs.
