# SpoofTunnel

[![Build](https://github.com/devprogrmer/spooftunnel/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/devprogrmer/spooftunnel/actions/workflows/rust.yml)
[![Latest release](https://img.shields.io/github/v/release/devprogrmer/spooftunnel?sort=semver)](https://github.com/devprogrmer/spooftunnel/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

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

## Project status & latest release

- **Current version:** `4.1.0`
- **Latest release:** [**v4.1.0**](https://github.com/devprogrmer/spooftunnel/releases/tag/v4.1.0)
  — prebuilt Linux x86‑64 binaries (built against glibc 2.31).
- **CI:** both the build/test workflow and the release workflow are green.

📥 **[Download the latest release »](https://github.com/devprogrmer/spooftunnel/releases/latest)**

---

## Download (prebuilt release)

Prebuilt Linux x86‑64 binaries are attached to every `v*.*.*` release. Direct
links for `v4.1.0`:

| Asset | Description |
| ----- | ----------- |
| [`spoof-tunnel`](https://github.com/devprogrmer/spooftunnel/releases/download/v4.1.0/spoof-tunnel) | Unified binary (role selected via config). |
| [`client`](https://github.com/devprogrmer/spooftunnel/releases/download/v4.1.0/client) | Client‑only binary (TUN forwarder). |
| [`server`](https://github.com/devprogrmer/spooftunnel/releases/download/v4.1.0/server) | Server‑only binary (tunnel endpoint). |
| [`spoof-manager.sh`](https://github.com/devprogrmer/spooftunnel/releases/download/v4.1.0/spoof-manager.sh) | Install / systemd / update helper script. |

```bash
# Example: download and prepare the unified binary
curl -L -o spoof-tunnel \
  https://github.com/devprogrmer/spooftunnel/releases/download/v4.1.0/spoof-tunnel
chmod +x spoof-tunnel
```

> Binaries are built on `ubuntu-22.04` (glibc 2.31) for `x86_64-unknown-linux-gnu`.
> On older/newer glibc or other architectures, build from source instead.

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

## Requirements / dependencies

- Linux (x86‑64), kernel with TUN support (`/dev/net/tun`).
- Root privileges (or `CAP_NET_RAW` + `CAP_NET_ADMIN`) to run.
- **To build from source:**
  - Rust stable toolchain (2021 edition).
  - Build dependencies for the bundled QUIC stack (`quiche`/BoringSSL):
    `cmake`, a C/C++ compiler, and `nasm` (on CI these come with `ubuntu-22.04`).

---

## Quick install

One‑command setup for **Linux x86‑64** users. Both options fetch the **latest
published release** automatically.

### Option 1: install the latest unified binary

```bash
curl -fsSL -o spoof-tunnel \
  https://github.com/devprogrmer/spooftunnel/releases/latest/download/spoof-tunnel
chmod +x spoof-tunnel
sudo install -m 0755 spoof-tunnel /usr/local/bin/spoof-tunnel
```

Now `spoof-tunnel` is on your `PATH`:

```bash
sudo spoof-tunnel --config config/client.toml
```

### Option 2: guided install with `spoof-manager.sh`

Use the manager script for a guided install and systemd service management
(requires bash 4+, systemd, root):

```bash
curl -fsSL -o spoof-manager.sh \
  https://github.com/devprogrmer/spooftunnel/releases/latest/download/spoof-manager.sh
chmod +x spoof-manager.sh
sudo ./spoof-manager.sh
```

---

## Install from release

```bash
# 1. Download the binary you need (unified example)
curl -L -o spoof-tunnel \
  https://github.com/devprogrmer/spooftunnel/releases/download/v4.1.0/spoof-tunnel

# 2. Make it executable
chmod +x spoof-tunnel

# 3. (Optional) install it on PATH
sudo install -m 0755 spoof-tunnel /usr/local/bin/spoof-tunnel
```

The `client` and `server` binaries are installed the same way. For a guided
install with systemd units, download and run
[`spoof-manager.sh`](https://github.com/devprogrmer/spooftunnel/releases/download/v4.1.0/spoof-manager.sh)
(requires bash 4+, systemd, root).

---

## Install from source

```bash
git clone https://github.com/devprogrmer/spooftunnel.git
cd spooftunnel

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

## Usage

The unified `spoof-tunnel` binary picks its role (`client` / `server`) from the
`role` field in the TOML. The dedicated `client` and `server` binaries are
role‑fixed entry points. All binaries share the `--config` and `--log-level`
flags.

### Client usage

```bash
sudo ./target/release/client --config config/client.toml
```

| Flag                     | Default              | Description                                                    |
| ------------------------ | -------------------- | -------------------------------------------------------------- |
| `-c`, `--config <PATH>`  | `config/client.toml` | Path to the TOML configuration file.                           |
| `-l`, `--log-level <LVL>`| *(from config)*      | Override log level (e.g. `debug`, `info`, `warn`).             |
| `--check`                | off                  | Run spoofed‑IP check mode (no TUN, no tunnel forwarding).      |
| `--check-ips <FILE>`     | *(required with `--check`)* | IP list file (one IPv4 per line) used for check mode.   |
| `--check-out <FILE>`     | `check_latency.txt`  | Output file for check results.                                 |
| `--check-timeout-ms <N>` | `1500`               | Timeout per IP in milliseconds.                                |
| `--check-workers <N>`    | `64`                 | Concurrent workers for check mode.                             |

**Spoofed‑IP check mode** — measure which spoofed source IPs are reachable and
their latency:

```bash
sudo ./target/release/client \
  --config config/client.toml \
  --check --check-ips ips.txt \
  --check-out check_latency.txt \
  --check-workers 64 --check-timeout-ms 1500
```

### Server usage

```bash
sudo ./target/release/server --config config/server.toml
```

> On startup the `server` binary prompts for a **`License password:`** before
> it begins forwarding.

| Flag                     | Default              | Description                                          |
| ------------------------ | -------------------- | --------------------------------------------------- |
| `-c`, `--config <PATH>`  | `config/server.toml` | Path to the TOML configuration file.                |
| `-l`, `--log-level <LVL>`| *(from config)*      | Override log level.                                 |
| `--check-allow-any`      | off                  | Allow any source IP (bypass allowlist) for check mode. |

### Unified binary usage

```bash
# Role is read from the TOML (`role = "client"` or `role = "server"`).
sudo ./target/release/spoof-tunnel --config config/server.toml
sudo ./target/release/spoof-tunnel --config config/client.toml
```

The `spoof-tunnel` binary accepts the union of the client and server flags:
`-c/--config` (default `config/client.toml`), `-l/--log-level`, and — when the
config role is `client` — `--check`, `--check-ips`, `--check-out`,
`--check-timeout-ms`, `--check-workers`; when the role is `server`,
`--check-allow-any`.

### Lifecycle management

[`scripts/spoof-manager.sh`](scripts/spoof-manager.sh) provides install /
systemd service / update helpers (requires bash 4+, systemd, root).

---

## Troubleshooting

| Symptom | Cause / fix |
| ------- | ----------- |
| Fails to open a TUN device (`/dev/net/tun`) | The kernel TUN module isn't available. Ensure `/dev/net/tun` exists and the `tun` module is loaded. |
| Permission denied binding raw sockets / creating TUN | Run as root, or grant `CAP_NET_RAW` + `CAP_NET_ADMIN` to the binary. |
| `server` waits at `License password:` | Expected — the `server` binary prompts for a license password on startup before forwarding. |
| `--check-ips` reported as required | `--check-ips <FILE>` is mandatory whenever `--check` is used on the client. |
| QUIC transport fails to start | Provide `config/quic_cert.pem` and `config/quic_key.pem` (git‑ignored; never commit private keys). |
| Build fails on the QUIC/BoringSSL step | Install the build dependencies: `cmake`, a C/C++ compiler, and `nasm`. |
| Prebuilt binary won't run (glibc error) | Release binaries target glibc 2.31 / x86‑64. On a different glibc or arch, build from source. |

---

## Links

- **Repository:** https://github.com/devprogrmer/spooftunnel
- **Releases:** https://github.com/devprogrmer/spooftunnel/releases
- **Latest release:** https://github.com/devprogrmer/spooftunnel/releases/latest

---

## Continuous Integration

- **[`.github/workflows/rust.yml`](.github/workflows/rust.yml)** — builds, runs
  Clippy, and runs the test suite on every push / PR to `main`.
- **[`.github/workflows/build-release.yml`](.github/workflows/build-release.yml)**
  — builds Linux release binaries and publishes them to a GitHub Release when a
  `v*.*.*` tag is pushed.

Both workflows are currently green.

---

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 devprogrmer.
