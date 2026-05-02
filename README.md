# ΦNET — Overlay Network

A Tor-inspired network rooted in number theory. Identity = a valid ΦNET
certificate (untouchable × totient × prime). No accounts, no IP identity, no trust.

<img width="1059" height="687" alt="01" src="https://github.com/user-attachments/assets/12ae45da-9ac1-49c8-bd33-bc61366b3e7d" />

<img width="1059" height="687" alt="02" src="https://github.com/user-attachments/assets/64537e4a-27f1-4e7b-a0ab-c192fc060282" />

<img width="1059" height="687" alt="03" src="https://github.com/user-attachments/assets/efdbf237-748b-41cc-9d2c-42e7902a8ea2" />

## Architecture

```
phinet/
├── phinet-core/          Core library: certs, crypto, onion, DHT, HS, board
├── phinet-daemon/        Network daemon binary  (phinet-daemon)
├── phinet-cli/           Hidden service CLI     (phi)
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
npm run build
npm install @tauri-apps/api@~2.10.0
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

## Wire Protocol

All messages: `[4-byte LE length][JSON payload]`, encrypted after session
establishment with ChaCha20-Poly1305 (per-direction nonce counters).

## Hidden Service Addresses

```
hs_id = BLAKE2b-256(J_bytes || nonce || name)[..20 bytes] → 40 hex chars
address: <hs_id>.phinet
```

Addresses are **not indexed** anywhere. Share them out-of-band.
The network DHT stores descriptors but does not expose a directory.

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
```

## License

MIT
