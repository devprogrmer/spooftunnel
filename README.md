# SpoofTunnel

**Bidirectional IP‑spoofing tunnel for heavily censored networks.**

SpoofTunnel forwards IP packets between two hosts over a spoofed transport
(UDP, ICMP, raw IP protocols, TCP, or QUIC) to evade DPI and IP‑based
filtering. It creates a local TUN interface on each side and multiplexes
traffic through one or more parallel tunnels with optional FEC, padding, TTL
jitter, fake‑TLS framing, and a XOR/ChaCha20 stream cipher for obfuscation.

> ⚠️ **Platform:** Linux only. SpoofTunnel uses TUN devices, raw sockets, and
> Linux‑specific syscalls. It must run as root (or with `CAP_NET_RAW` +
> `CAP_NET_ADMIN`).
>
> ⚠️ **Legal:** This is a network‑research / censorship‑circumvention tool.
> IP spoofing is restricted or illegal on many networks. Only use it on
> infrastructure you own or are explicitly authorized to test.

---

## Features

- Multiple spoofed transports: `udp`, `icmp`, `proto58`, `tcp`, `quic`,
  `ipip` (IP‑in‑IP), `gre`.
- Independent uplink/downlink protocol selection.
- Multiple parallel tunnels with auto‑tuning based on CPU/RAM/NIC.
- Multiplexing + optional forward error correction (FEC).
- DPI‑evasion knobs: packet padding, TTL jitter, random DSCP, fake TLS record
  header, per‑packet port/ICMP‑id shuffling.
- Wire encryption: HMAC‑authenticated packets + optional XOR‑CTR / ChaCha20
  stream cipher keyed off the pre‑shared key.
- Built‑in spoofed‑IP reachability/latency check mode.

---

## Requirements

- Linux (x86‑64), kernel with TUN support (`/dev/net/tun`).
- Rust stable toolchain (2021 edition).
- Build dependencies for the bundled QUIC stack (`quiche`/BoringSSL): `cmake`,
  a C/C++ compiler, and `nasm` (on the CI these come with `ubuntu-22.04`).
- Root privileges to run.

---

## Build

```bash
# Debug build
cargo build --bins

# Optimized release build (recommended)
cargo build --release --bins

# Native‑CPU optimized (non‑portable binaries)
RUSTFLAGS="-C target-cpu=native" cargo build --release --bins
```

Binaries are produced in `target/release/`:

| Binary         | Purpose                                             |
| -------------- | --------------------------------------------------- |
| `spoof-tunnel` | Unified binary; role selected via config `role`.    |
| `client`       | Client‑only entry point (TUN forwarder).            |
| `server`       | Server‑only entry point (tunnel endpoint).          |

> **Note:** `Cargo.lock` is git‑ignored. For fully reproducible release
> builds, run `cargo generate-lockfile` and pin it in your own deployment.

---

## Configure

Copy and edit the sample configs in [`config/`](config):

- [`config/client.toml`](config/client.toml)
- [`config/server.toml`](config/server.toml)

Every option is documented inline. **Before deploying you must change at
least:**

- `pre_shared_key` — set the same random secret (≥ 32 chars) on both sides.
- `real_ip` / `peer_real_ip` — the actual addresses of each host.
- `spoofed_ip` / `peer_spoofed_ip` / `spoofed_ip_pool` — the spoofed source
  addresses each side presents.
- `interface` — the physical NIC to bind raw sockets to (e.g. `eth0`).

If you use the QUIC transport, provide `config/quic_cert.pem` /
`config/quic_key.pem` (these are git‑ignored — never commit private keys).

---

## Run

```bash
# Unified binary (role read from the TOML)
sudo ./target/release/spoof-tunnel --config config/server.toml   # on the server
sudo ./target/release/spoof-tunnel --config config/client.toml   # on the client

# Or the dedicated binaries
sudo ./target/release/server --config config/server.toml
sudo ./target/release/client --config config/client.toml
```

Override the log level at runtime with `--log-level debug`.

### Spoofed‑IP check mode

Measure which spoofed source IPs are reachable and their latency:

```bash
sudo ./target/release/client \
  --config config/client.toml \
  --check --check-ips ips.txt \
  --check-out check_latency.txt \
  --check-workers 64 --check-timeout-ms 1500
```

### Lifecycle management

[`scripts/spoof-manager.sh`](scripts/spoof-manager.sh) provides install /
systemd service / update helpers (requires bash 4+, systemd, root).

---

## Continuous Integration

- **`.github/workflows/rust.yml`** — builds, runs Clippy, and runs the test
  suite on every push / PR to `main`.
- **`.github/workflows/build-release.yml`** — builds Linux release binaries
  and publishes them to a GitHub Release when a `v*.*.*` tag is pushed.

---

## License

MIT — see [LICENSE](LICENSE).
