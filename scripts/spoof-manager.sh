#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SpoofTunnel Manager  ─  Full lifecycle management script
#  Version: 4.1.0
#  Requires: bash 4+, systemd, curl/wget, root or sudo
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
#  Colour helpers
# ─────────────────────────────────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
err()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
step()    { echo -e "\n${BOLD}${BLUE}──▶${RESET}  ${BOLD}$*${RESET}"; }
banner()  {
  echo -e "${MAGENTA}"
  cat << 'BANNER'
 ____                  __  _____                     _
/ ___| _ __   ___   ___ / _||_   _|   _ _ __  _ __   ___| |
\___ \| '_ \ / _ \ / _ \ |_   | | | | | | '_ \| '_ \ / _ \ |
 ___) | |_) | (_) | (_) |  _|  | | | |_| | | | | | | |  __/ |
|____/| .__/ \___/ \___/|_|    |_|  \__,_|_| |_|_| |_|\___|_|
      |_|
                                     Manager v4.1.0
BANNER
  echo -e "${RESET}"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Constants / paths
# ─────────────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/spooftunnel"
CONFIG_DIR="/etc/spooftunnel"
LOG_DIR="/var/log/spooftunnel"
BIN_PATH="${INSTALL_DIR}/spoof-tunnel"
REPO_OWNER="devprogrmer"
REPO_NAME="spooftunnel"
GITHUB_API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_PREFIX="spooftunnel"

# ─────────────────────────────────────────────────────────────────────────────
#  Privilege check
# ─────────────────────────────────────────────────────────────────────────────
require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (or via sudo)."
    exit 1
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  Dependency checker
# ─────────────────────────────────────────────────────────────────────────────
check_deps() {
  local missing=()
  for cmd in curl systemctl ip iptables; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    err "Missing required commands: ${missing[*]}"
    err "Install them with: apt-get install -y curl iproute2 iptables"
    exit 1
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  Download helpers
# ─────────────────────────────────────────────────────────────────────────────
get_latest_version() {
  curl -fsSL "$GITHUB_API" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

get_download_url() {
  # Returns the download URL for the "spoof-tunnel" binary asset in the latest
  # release. The release publishes bare binaries (spoof-tunnel, client, server)
  # plus spoof-manager.sh — so anchor on a URL ending in exactly "/spoof-tunnel"
  # to avoid matching spoof-manager.sh or any future spoof-tunnel-* asset.
  curl -fsSL "$GITHUB_API" 2>/dev/null \
    | grep '"browser_download_url"' \
    | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/' \
    | grep -E '/spoof-tunnel$' \
    | head -1
}

cmd_download() {
  require_root
  step "Fetching latest SpoofTunnel release …"

  local version
  version=$(get_latest_version)
  if [[ -z "$version" ]]; then
    err "Could not fetch version info from GitHub API."
    err "Check connectivity: curl -fsSL '${GITHUB_API}'"
    exit 1
  fi
  info "Latest release: ${BOLD}${version}${RESET}"

  local url
  url=$(get_download_url)
  if [[ -z "$url" ]]; then
    err "Could not find the 'spoof-tunnel' binary asset in release ${version}."
    exit 1
  fi
  info "Download URL: ${DIM}${url}${RESET}"

  mkdir -p "$INSTALL_DIR"
  local tmp
  tmp=$(mktemp)
  curl -fL --progress-bar -o "$tmp" "$url"
  chmod +x "$tmp"

  # Verify it actually runs (quick sanity check)
  if "$tmp" --help &>/dev/null || "$tmp" --version &>/dev/null 2>&1; then
    :
  fi

  mv "$tmp" "$BIN_PATH"
  ok "Binary installed to ${BOLD}${BIN_PATH}${RESET}  (${version})"

  # Persist installed version
  echo "$version" > "${INSTALL_DIR}/VERSION"
  ln -sf "$BIN_PATH" /usr/local/bin/spoof-tunnel 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────────
#  Config wizard
# ─────────────────────────────────────────────────────────────────────────────

ask() {
  # ask VAR "Prompt text" "default"
  local var="$1" prompt="$2" default="${3:-}"
  local reply
  if [[ -n "$default" ]]; then
    read -rp "  ${CYAN}${prompt}${RESET} [${DIM}${default}${RESET}]: " reply
    reply="${reply:-$default}"
  else
    while true; do
      read -rp "  ${CYAN}${prompt}${RESET}: " reply
      [[ -n "$reply" ]] && break
      warn "  Value cannot be empty."
    done
  fi
  printf -v "$var" '%s' "$reply"
}

ask_bool() {
  # ask_bool VAR "Prompt text" "y|n default"
  local var="$1" prompt="$2" default="${3:-n}"
  local reply
  while true; do
    read -rp "  ${CYAN}${prompt}${RESET} [y/n, default: ${default}]: " reply
    reply="${reply:-$default}"
    case "${reply,,}" in
      y|yes) printf -v "$var" 'true';  return ;;
      n|no)  printf -v "$var" 'false'; return ;;
      *) warn "  Please answer y or n." ;;
    esac
  done
}

ask_choice() {
  # ask_choice VAR "Prompt" "opt1 opt2 ..." "default"
  local var="$1" prompt="$2" opts="$3" default="${4:-}"
  local reply
  echo -e "  ${CYAN}${prompt}${RESET}"
  local i=1
  local arr=($opts)
  for o in "${arr[@]}"; do
    if [[ "$o" == "$default" ]]; then
      echo -e "    ${GREEN}${i})${RESET} ${o} ${DIM}(default)${RESET}"
    else
      echo -e "    ${WHITE}${i})${RESET} ${o}"
    fi
    ((i++))
  done
  while true; do
    read -rp "  Choice [1-${#arr[@]}]: " reply
    reply="${reply:-}"
    # Accept by number or by value
    if [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= ${#arr[@]} )); then
      printf -v "$var" '%s' "${arr[$((reply-1))]}"
      return
    fi
    # If user just pressed Enter and there's a default, use it
    if [[ -z "$reply" && -n "$default" ]]; then
      printf -v "$var" '%s' "$default"
      return
    fi
    # Accept typed value directly if it's in the list
    for o in "${arr[@]}"; do
      if [[ "$reply" == "$o" ]]; then
        printf -v "$var" '%s' "$o"
        return
      fi
    done
    warn "  Invalid choice."
  done
}

generate_key() {
  # Generates a 48-char hex random string suitable as a PSK
  head -c 24 /dev/urandom | xxd -p | tr -d '\n'
}

# Helper: build a TOML string array from a comma-separated list of IPs/values
# Usage: build_toml_str_array VAR "1.1.1.1,2.2.2.2"
build_toml_str_array() {
  local var="$1" raw="$2"
  local result='['
  IFS=',' read -ra arr <<< "$raw"
  for item in "${arr[@]}"; do
    item="${item// /}"
    [[ -z "$item" ]] && continue
    result+='"'"$item"'", '
  done
  result="${result%, }]"
  printf -v "$var" '%s' "$result"
}

# Helper: build a TOML integer array from a comma-separated list of port numbers
# Usage: build_toml_int_array VAR "80,443,8080"
build_toml_int_array() {
  local var="$1" raw="$2"
  if [[ -z "$raw" ]]; then
    printf -v "$var" '[]'
    return
  fi
  local result='['
  IFS=',' read -ra arr <<< "$raw"
  for item in "${arr[@]}"; do
    item="${item// /}"
    [[ -z "$item" ]] && continue
    result+="${item}, "
  done
  result="${result%, }]"
  printf -v "$var" '%s' "$result"
}

cmd_configure() {
  # Optional preset role: "client" | "server" preselect the role and skip the
  # role prompt; "unified" (or empty) lets the user choose interactively.
  local preset_role="${1:-}"
  require_root
  mkdir -p "$CONFIG_DIR" "$LOG_DIR"

  banner
  echo -e "${BOLD}${WHITE}  ═══ SpoofTunnel Instance Configuration Wizard ═══${RESET}\n"
  echo -e "  ${DIM}Every option is configurable. Press Enter to accept the default shown in [brackets].${RESET}\n"

  # ── Instance name ──────────────────────────────────────────────────────────
  local instance_name
  ask instance_name "Instance name (alphanumeric, used as service name)" "spoof0"
  instance_name="${instance_name//[^a-zA-Z0-9_-]/}"
  if [[ -z "$instance_name" ]]; then instance_name="spoof0"; fi

  local cfg_file="${CONFIG_DIR}/${instance_name}.toml"

  if [[ -f "$cfg_file" ]]; then
    warn "Config file ${cfg_file} already exists."
    local overwrite
    ask_bool overwrite "Overwrite?" "n"
    [[ "$overwrite" == "false" ]] && { info "Aborted."; return; }
  fi

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  1. ROLE                                                                ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [1/11] Role ════════════════════════════════════════${RESET}"
  local role
  case "$preset_role" in
    client|server)
      role="$preset_role"
      echo -e "  ${GREEN}Role preset to:${RESET} ${BOLD}${role}${RESET} ${DIM}(from installer selection)${RESET}"
      ;;
    *)
      # "unified" or unspecified -> let the user choose the role to generate.
      ask_choice role "Role for this instance" "client server" "client"
      ;;
  esac

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  2. SPOOFING MODE                                                       ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [2/11] Spoofing Mode ═══════════════════════════════${RESET}"
  echo -e "  ${DIM}Spoofing mode: both sides forge their source IP in every packet —"
  echo -e "  makes traffic appear to originate from innocent public IPs (e.g. CDN/DNS)."
  echo -e "  No-spoof: real IPs are used as source; simpler but easier to fingerprint.${RESET}"
  echo ""
  local use_spoof
  ask_bool use_spoof "Enable IP spoofing (recommended for censored networks)?" "y"

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  3. IP ADDRESSING                                                       ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [3/11] IP Addressing ══════════════════════════════${RESET}"

  local real_ip peer_real_ip
  if [[ "$role" == "client" ]]; then
    ask real_ip      "This client's real IPv4 address"  "10.0.0.2"
    ask peer_real_ip "Server's real IPv4 address"       "203.0.113.1"
  else
    ask real_ip      "This server's real IPv4 address"  "203.0.113.1"
    ask peer_real_ip "Client's real IPv4 address"       "10.0.0.2"
  fi

  local spoofed_ip spoofed_ip_pool peer_spoofed_ip
  if [[ "$use_spoof" == "true" ]]; then
    echo ""
    echo -e "  ${DIM}Pick routable IPs you are authorised to emulate (e.g. CDN nodes, public DNS)."
    echo -e "  The pool is rotated each session for stronger evasion.${RESET}"
    echo ""
    if [[ "$role" == "client" ]]; then
      ask spoofed_ip      "Your spoofed source IP (primary)"                     "8.8.4.4"
      ask spoofed_ip_pool "Your spoofed IP pool (comma-separated, include primary)" "8.8.4.4,1.1.1.1,208.67.222.222"
      ask peer_spoofed_ip "Server's spoofed source IP (what server replies look like)" "1.2.3.4"
    else
      ask spoofed_ip      "Your spoofed source IP (primary)"                     "1.2.3.4"
      ask spoofed_ip_pool "Your spoofed IP pool (comma-separated, include primary)" "1.2.3.4,5.6.7.8"
      ask peer_spoofed_ip "Client's spoofed source IP (what client packets look like)" "8.8.4.4"
    fi
  else
    spoofed_ip="$real_ip"
    spoofed_ip_pool="$real_ip"
    peer_spoofed_ip="$peer_real_ip"
    info "No-spoof mode: spoofed_ip / peer_spoofed_ip set equal to real IPs."
  fi

  # allowed_peers — extra trusted IPs beyond peer_real_ip
  echo ""
  echo -e "  ${DIM}allowed_peers: additional trusted peer IPs beyond peer_real_ip."
  echo -e "  Leave empty for none (most common setup).${RESET}"
  local allowed_peers_raw=""
  ask allowed_peers_raw "Extra allowed peer IPs (comma-separated, empty = none)" ""

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  4. TRANSPORT                                                           ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [4/11] Transport Protocol ═════════════════════════${RESET}"
  echo -e "  ${DIM}uplink = outgoing packets from this node."
  echo -e "  downlink = incoming packets to this node."
  echo -e "  Both uplink and downlink MUST match on client and server.${RESET}"
  echo ""
  local uplink_protocol downlink_protocol
  ask_choice uplink_protocol   "Uplink protocol (outgoing)"   "udp icmp proto58 tcp quic ipip gre" "udp"
  ask_choice downlink_protocol "Downlink protocol (incoming)" "udp icmp proto58 tcp quic ipip gre" "udp"

  # ── Data port (UDP/TCP only) ───────────────────────────────────────────────
  local data_port="51820"
  if [[ "$uplink_protocol" != "icmp"    && "$uplink_protocol" != "proto58" && \
        "$uplink_protocol" != "ipip"    && "$uplink_protocol" != "gre" ]]; then
    ask data_port "Data port (UDP/TCP — must match both sides)" "51820"
  fi

  # ── Shuffle data port ─────────────────────────────────────────────────────
  local shuffle_data_port="false"
  local shuffle_port_min="49152"
  local shuffle_port_max="65535"
  if [[ "$uplink_protocol" != "quic"   && "$uplink_protocol" != "icmp" && \
        "$uplink_protocol" != "proto58" && "$uplink_protocol" != "ipip" && \
        "$uplink_protocol" != "gre" ]]; then
    ask_bool shuffle_data_port "Randomise data port per packet (shuffle_data_port)?" "n"
    if [[ "$shuffle_data_port" == "true" ]]; then
      ask shuffle_port_min "Shuffle range minimum port" "49152"
      ask shuffle_port_max "Shuffle range maximum port" "65535"
    fi
  fi

  # ── ICMP settings ─────────────────────────────────────────────────────────
  local icmp_id="0x4321"
  local random_icmp_id="false"
  if [[ "$uplink_protocol" == "icmp" || "$downlink_protocol" == "icmp" ]]; then
    echo ""
    echo -e "  ${DIM}ICMP settings (only relevant when protocol = icmp).${RESET}"
    ask icmp_id "ICMP echo identifier (hex or int, must match both sides)" "0x4321"
    ask_bool random_icmp_id "Randomise ICMP echo identifier per packet?" "n"
  fi

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  5. MULTIPLEXING & FEC                                                  ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [5/11] Multiplexing & FEC ═════════════════════════${RESET}"
  echo -e "  ${DIM}Mux batches multiple packets per wire frame — reduces syscall overhead."
  echo -e "  FEC adds parity frames so lost packets are recovered without retransmit."
  echo -e "  Not available for TCP or QUIC.${RESET}"
  echo ""
  local enable_multiplex="false"
  local multiplex_flush_ms="1"
  local multiplex_max_payload="1380"
  local enable_fec="false"
  local fec_group_size="4"
  if [[ "$uplink_protocol" == "tcp" || "$uplink_protocol" == "quic" ]]; then
    warn "Multiplexing and FEC are not supported for TCP/QUIC — skipped."
  else
    ask_bool enable_multiplex "Enable multiplexing?" "y"
    if [[ "$enable_multiplex" == "true" ]]; then
      ask multiplex_flush_ms    "Mux flush interval in ms (lower = less latency)" "1"
      ask multiplex_max_payload "Mux max payload bytes per wire frame"            "1380"
    fi
    ask_bool enable_fec "Enable XOR FEC (Forward Error Correction)?" "n"
    if [[ "$enable_fec" == "true" ]]; then
      ask fec_group_size "FEC group size (data frames per parity frame, ≥2)" "4"
    fi
  fi

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  6. QUIC SETTINGS                                                       ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  local quic_server_name="SpoofTunnel"
  local quic_cert="/etc/spooftunnel/quic_cert.pem"
  local quic_key="/etc/spooftunnel/quic_key.pem"
  local quic_alpn="h3"
  local quic_idle_timeout_ms="30000"
  local quic_max_data="134217728"
  local quic_max_stream_data="16777216"
  local quic_max_streams_bidi="256"
  if [[ "$uplink_protocol" == "quic" || "$downlink_protocol" == "quic" ]]; then
    echo ""
    echo -e "${BOLD}${WHITE}  ═══ [6/11] QUIC Settings ═══════════════════════════════${RESET}"
    echo -e "  ${DIM}Only used when uplink or downlink protocol = quic.${RESET}"
    echo ""
    ask quic_server_name      "QUIC TLS SNI server name"                     "SpoofTunnel"
    ask quic_cert             "Path to TLS certificate (PEM)"                "/etc/spooftunnel/quic_cert.pem"
    ask quic_key              "Path to TLS private key (PEM)"                "/etc/spooftunnel/quic_key.pem"
    ask quic_alpn             "QUIC ALPN label"                              "h3"
    ask quic_idle_timeout_ms  "QUIC idle connection timeout (ms)"            "30000"
    ask quic_max_data         "QUIC connection-level flow-control window (bytes)" "134217728"
    ask quic_max_stream_data  "QUIC per-stream flow-control window (bytes)"  "16777216"
    ask quic_max_streams_bidi "QUIC max concurrent bidirectional streams"    "256"
    echo ""
    local gen_cert
    ask_bool gen_cert "Generate a self-signed TLS cert+key now (requires openssl)?" "y"
    if [[ "$gen_cert" == "true" ]]; then
      if command -v openssl &>/dev/null; then
        mkdir -p "$(dirname "$quic_cert")" "$(dirname "$quic_key")"
        openssl req -x509 -newkey rsa:2048 \
          -keyout "$quic_key" -out "$quic_cert" \
          -days 365 -nodes -subj "/CN=${quic_server_name}" 2>/dev/null
        ok "Certificate: ${quic_cert}"
        ok "Private key : ${quic_key}"
      else
        warn "openssl not found — skipped. Generate manually before starting."
      fi
    fi
  fi

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  7. SECURITY                                                            ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [7/11] Security ════════════════════════════════════${RESET}"
  local psk_default
  psk_default=$(generate_key)
  local pre_shared_key
  ask pre_shared_key "Pre-shared key — HMAC-SHA256 auth (must match both sides)" "$psk_default"

  local enable_xor
  ask_bool enable_xor "Enable ChaCha20 wire encryption (enable_xor)?" "y"
  local xor_key=""
  if [[ "$enable_xor" == "true" ]]; then
    echo -e "  ${DIM}xor_key: leave empty to derive automatically from pre_shared_key.${RESET}"
    ask xor_key "ChaCha20 encryption key (empty = use pre_shared_key)" ""
  fi

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  8. DPI OBFUSCATION                                                     ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [8/11] DPI Bypass Obfuscation ═════════════════════${RESET}"
  echo -e "  ${DIM}All settings are independent. Both sides must have identical values.${RESET}"
  echo ""
  local packet_padding packet_padding_max ttl_jitter fake_tls_header random_dscp
  ask_bool packet_padding "Enable packet length padding (breaks length fingerprinting)?" "y"
  local packet_padding_max="64"
  if [[ "$packet_padding" == "true" ]]; then
    ask packet_padding_max "Maximum padding bytes per frame (1–255)" "64"
  fi
  ask_bool ttl_jitter      "Enable TTL jitter (randomise TTL from {64,128,255})?" "y"
  ask_bool fake_tls_header "Enable fake TLS Application Data header (TCP only)?"  "n"
  ask_bool random_dscp     "Enable random DSCP / ToS field?"                      "n"

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  9. TUN INTERFACE                                                       ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [9/11] TUN Interface ══════════════════════════════${RESET}"
  echo -e "  ${DIM}tun_ip and tun_peer_ip must be SWAPPED between client and server.${RESET}"
  echo ""
  local tun_name tun_ip tun_peer_ip tun_netmask tun_mtu interface
  ask tun_name "TUN interface name" "spoof0"
  if [[ "$role" == "client" ]]; then
    ask tun_ip      "Local TUN IP  (this side)" "10.66.0.1"
    ask tun_peer_ip "Remote TUN IP (peer)"      "10.66.0.2"
  else
    ask tun_ip      "Local TUN IP  (this side)" "10.66.0.2"
    ask tun_peer_ip "Remote TUN IP (peer)"      "10.66.0.1"
  fi
  ask tun_netmask "TUN netmask (/30 point-to-point)" "255.255.255.252"
  ask interface   "Physical NIC name for raw socket binding" "eth0"

  # ── MTU / TUN MTU ─────────────────────────────────────────────────────────
  local mtu
  ask mtu "Payload MTU in bytes (tune to path MTU; 1380 safe for most links)" "1380"
  # tun_mtu defaults to mtu if not set; we ask explicitly
  ask tun_mtu "TUN interface MTU (leave same as MTU unless you know why to differ)" "$mtu"

  # ── Port forwarding (client only) ─────────────────────────────────────────
  local forward_ports_toml='[]'
  if [[ "$role" == "client" ]]; then
    echo ""
    echo -e "  ${DIM}forward_ports: TCP/UDP ports forwarded through the tunnel."
    echo -e "  Leave empty to forward ALL ports arriving at the TUN interface.${RESET}"
    local fwd_raw=""
    ask fwd_raw "Forward ports (comma-separated e.g. 80,443,8080 — empty = all)" ""
    build_toml_int_array forward_ports_toml "$fwd_raw"
  fi

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  10. PERFORMANCE                                                        ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [10/11] Performance ═══════════════════════════════${RESET}"
  echo -e "  ${DIM}auto_tune=true overrides most manual values automatically — recommended.${RESET}"
  echo ""
  local perf_mode auto_tune
  ask_choice perf_mode "Performance mode" "throughput latency balanced" "throughput"
  ask_bool auto_tune "Enable auto-tune (detects CPU/RAM/NIC — overrides manual values)?" "y"

  local tunnel_count channel_capacity io_channel_capacity runtime_worker_threads
  if [[ "$auto_tune" == "false" ]]; then
    echo ""
    echo -e "  ${DIM}Manual performance values (auto_tune is OFF):${RESET}"
    ask tunnel_count           "Number of parallel tunnel streams"          "4"
    ask channel_capacity       "Per-tunnel async channel capacity"          "8192"
    ask io_channel_capacity    "Raw I/O and mux queue capacity"             "16384"
    ask runtime_worker_threads "Tokio worker threads (0 = auto)"           "0"
  else
    tunnel_count="4"
    channel_capacity="8192"
    io_channel_capacity="16384"
    runtime_worker_threads="0"
  fi

  # ╔══════════════════════════════════════════════════════════════════════════╗
  # ║  11. LOGGING                                                            ║
  # ╚══════════════════════════════════════════════════════════════════════════╝
  echo ""
  echo -e "${BOLD}${WHITE}  ═══ [11/11] Logging ════════════════════════════════════${RESET}"
  local log_level
  ask_choice log_level "Log level" "error warn info debug trace" "info"

  # ══════════════════════════════════════════════════════════════════════════
  #  Build TOML arrays
  # ══════════════════════════════════════════════════════════════════════════
  local pool_toml allowed_peers_toml
  build_toml_str_array pool_toml          "$spoofed_ip_pool"
  build_toml_str_array allowed_peers_toml "$allowed_peers_raw"

  # xor_key line: write key if non-empty, else comment it out
  local xor_key_line
  if [[ -n "$xor_key" ]]; then
    xor_key_line="xor_key = \"${xor_key}\""
  else
    xor_key_line="# xor_key = \"\"   # empty = derived automatically from pre_shared_key"
  fi

  # tun_mtu line (only write if different from mtu to keep config clean)
  local tun_mtu_line="tun_mtu = ${tun_mtu}"

  # ══════════════════════════════════════════════════════════════════════════
  #  Write configuration file
  # ══════════════════════════════════════════════════════════════════════════
  step "Writing configuration to ${cfg_file} …"
  cat > "$cfg_file" << TOML
# SpoofTunnel – ${role} configuration
# Instance : ${instance_name}
# Generated: $(date -Iseconds)  by spoof-manager.sh
# Spoofing : ${use_spoof}
# ─────────────────────────────────────────────────────────────────────────────

role = "${role}"

# ─────────────────────────────────────────────────────────────────────────────
# IP Addressing
# ─────────────────────────────────────────────────────────────────────────────

real_ip      = "${real_ip}"
peer_real_ip = "${peer_real_ip}"

# Spoofed IPs — set equal to real IPs when spoofing is disabled.
spoofed_ip      = "${spoofed_ip}"
peer_spoofed_ip = "${peer_spoofed_ip}"
spoofed_ip_pool = ${pool_toml}

# Extra trusted peer IPs beyond peer_real_ip (empty = none).
allowed_peers = ${allowed_peers_toml}

# ─────────────────────────────────────────────────────────────────────────────
# Transport / Channel
# ─────────────────────────────────────────────────────────────────────────────

uplink_protocol   = "${uplink_protocol}"
downlink_protocol = "${downlink_protocol}"

data_port         = ${data_port}
shuffle_data_port = ${shuffle_data_port}
shuffle_port_min  = ${shuffle_port_min}
shuffle_port_max  = ${shuffle_port_max}

icmp_id        = ${icmp_id}
random_icmp_id = ${random_icmp_id}

# ─────────────────────────────────────────────────────────────────────────────
# Multiplexing & FEC  (UDP / ICMP / Proto58 / IPIP only)
# ─────────────────────────────────────────────────────────────────────────────

enable_multiplex      = ${enable_multiplex}
multiplex_flush_ms    = ${multiplex_flush_ms}
multiplex_max_payload = ${multiplex_max_payload}
enable_fec            = ${enable_fec}
fec_group_size        = ${fec_group_size}

# ─────────────────────────────────────────────────────────────────────────────
# QUIC  (only used when uplink_protocol or downlink_protocol = "quic")
# ─────────────────────────────────────────────────────────────────────────────

quic_server_name      = "${quic_server_name}"
quic_cert             = "${quic_cert}"
quic_key              = "${quic_key}"
quic_alpn             = "${quic_alpn}"
quic_idle_timeout_ms  = ${quic_idle_timeout_ms}
quic_max_data         = ${quic_max_data}
quic_max_stream_data  = ${quic_max_stream_data}
quic_max_streams_bidi = ${quic_max_streams_bidi}

# ─────────────────────────────────────────────────────────────────────────────
# Security
# ─────────────────────────────────────────────────────────────────────────────

pre_shared_key = "${pre_shared_key}"

# ─────────────────────────────────────────────────────────────────────────────
# ChaCha20 Wire Encryption
# ─────────────────────────────────────────────────────────────────────────────

enable_xor = ${enable_xor}
${xor_key_line}

# ─────────────────────────────────────────────────────────────────────────────
# DPI Bypass Obfuscation  (both sides must be identical)
# ─────────────────────────────────────────────────────────────────────────────

packet_padding     = ${packet_padding}
packet_padding_max = ${packet_padding_max}
ttl_jitter         = ${ttl_jitter}
fake_tls_header    = ${fake_tls_header}
random_dscp        = ${random_dscp}

# ─────────────────────────────────────────────────────────────────────────────
# TUN Interface
# ─────────────────────────────────────────────────────────────────────────────

tun_name    = "${tun_name}"
tun_ip      = "${tun_ip}"
tun_peer_ip = "${tun_peer_ip}"
tun_netmask = "${tun_netmask}"
${tun_mtu_line}
interface   = "${interface}"
forward_ports = ${forward_ports_toml}

# ─────────────────────────────────────────────────────────────────────────────
# Performance
# ─────────────────────────────────────────────────────────────────────────────

perf_mode              = "${perf_mode}"
auto_tune              = ${auto_tune}
tunnel_count           = ${tunnel_count}
mtu                    = ${mtu}
channel_capacity       = ${channel_capacity}
io_channel_capacity    = ${io_channel_capacity}
runtime_worker_threads = ${runtime_worker_threads}

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

log_level = "${log_level}"
TOML

  ok "Configuration saved: ${BOLD}${cfg_file}${RESET}"

  # ── Create systemd service ────────────────────────────────────────────────
  echo ""
  local create_svc
  ask_bool create_svc "Create and enable systemd service for this instance?" "y"
  if [[ "$create_svc" == "true" ]]; then
    _create_service "$instance_name" "$cfg_file"
    echo ""
    local start_now
    ask_bool start_now "Start the service now?" "y"
    if [[ "$start_now" == "true" ]]; then
      cmd_start "$instance_name"
    fi
  fi

  echo ""
  ok "Instance '${BOLD}${instance_name}${RESET}' configured successfully."
  echo -e "  Config : ${BOLD}${cfg_file}${RESET}"
  echo -e "  Service: ${BOLD}${SERVICE_PREFIX}@${instance_name}.service${RESET}"
  echo -e "  Logs   : journalctl -u ${SERVICE_PREFIX}@${instance_name} -f"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Systemd service management
# ─────────────────────────────────────────────────────────────────────────────

# Write the template service unit (run once)
_ensure_template_service() {
  local template="${SYSTEMD_DIR}/${SERVICE_PREFIX}@.service"
  if [[ -f "$template" ]]; then return; fi

  step "Creating systemd template unit ${template} …"
  mkdir -p "$LOG_DIR"
  cat > "$template" << 'UNIT'
[Unit]
Description=SpoofTunnel instance %i
Documentation=https://github.com/devprogrmer/spooftunnel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/spooftunnel
ExecStart=/opt/spooftunnel/spoof-tunnel --config /etc/spooftunnel/%i.toml
Restart=always
RestartSec=5s
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  ok "Template service unit registered."
}

_create_service() {
  local instance_name="$1"
  local cfg_file="$2"
  
  _ensure_template_service
  
  systemctl daemon-reload
  systemctl enable "${SERVICE_PREFIX}@${instance_name}.service"
  ok "Service enabled: ${SERVICE_PREFIX}@${instance_name}.service"
}

cmd_start() {
  local instance_name="$1"
  require_root
  step "Starting service ${SERVICE_PREFIX}@${instance_name} …"
  systemctl start "${SERVICE_PREFIX}@${instance_name}.service"
  ok "Service started."
}

cmd_stop() {
  local instance_name="$1"
  require_root
  step "Stopping service ${SERVICE_PREFIX}@${instance_name} …"
  systemctl stop "${SERVICE_PREFIX}@${instance_name}.service"
  ok "Service stopped."
}

cmd_restart() {
  local instance_name="$1"
  require_root
  step "Restarting service ${SERVICE_PREFIX}@${instance_name} …"
  systemctl restart "${SERVICE_PREFIX}@${instance_name}.service"
  ok "Service restarted."
}

cmd_status() {
  local instance_name="${1:-}"
  if [[ -n "$instance_name" ]]; then
    systemctl status "${SERVICE_PREFIX}@${instance_name}.service" || true
  else
    systemctl status "${SERVICE_PREFIX}@*" || true
  fi
}

cmd_logs() {
  local instance_name="$1"
  journalctl -u "${SERVICE_PREFIX}@${instance_name}.service" -n 100 --no-pager
}

cmd_follow() {
  local instance_name="$1"
  journalctl -u "${SERVICE_PREFIX}@${instance_name}.service" -f
}

cmd_uninstall() {
  require_root
  warn "This will stop all instances, remove binary, systemd configurations, and logs."
  local confirm
  ask_bool confirm "Proceed with uninstallation?" "n"
  if [[ "$confirm" != "true" ]]; then
    info "Uninstall aborted."
    return
  fi

  step "Cleaning up SpoofTunnel components …"
  
  # Stop and disable active instances
  local active_services
  active_services=$(systemctl list-units --type=service --all --no-legend "${SERVICE_PREFIX}@*" | awk '{print $1}' || true)
  for svc in $active_services; do
    info "Stopping and disabling $svc"
    systemctl stop "$svc" &>/dev/null || true
    systemctl disable "$svc" &>/dev/null || true
  done

  # Remove template service
  local template="${SYSTEMD_DIR}/${SERVICE_PREFIX}@.service"
  rm -f "$template"

  # Remove paths
  rm -f /usr/local/bin/spoof-tunnel 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  rm -rf "$CONFIG_DIR"
  rm -rf "$LOG_DIR"
  
  systemctl daemon-reload
  ok "SpoofTunnel completely uninstalled."
}

# ─────────────────────────────────────────────────────────────────────────────
#  Full guided installer flow
# ─────────────────────────────────────────────────────────────────────────────
#  setup = dependency check -> download/install latest binary -> configuration
#  wizard -> (the wizard then offers to create/enable/start the systemd service).
#  Optional preset role: client | server | unified.
cmd_setup() {
  local preset_role="${1:-}"
  require_root
  step "Guided setup${preset_role:+ (${preset_role})} — dependency check"
  check_deps
  cmd_download
  echo ""
  cmd_configure "$preset_role"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Interactive menu (shown when the script is run with no arguments)
# ─────────────────────────────────────────────────────────────────────────────
_prompt_instance() {
  # Echoes an instance name read from the user (default: spoof0)
  local reply
  read -rp "  Instance name [spoof0]: " reply
  echo "${reply:-spoof0}"
}

interactive_menu() {
  banner
  echo -e "${BOLD}${WHITE}  ═══ SpoofTunnel Installer ═══${RESET}\n"
  echo -e "   ${GREEN}1)${RESET} Client setup            ${DIM}(install + configure client)${RESET}"
  echo -e "   ${GREEN}2)${RESET} Server setup            ${DIM}(install + configure server)${RESET}"
  echo -e "   ${GREEN}3)${RESET} Unified setup           ${DIM}(install + choose role)${RESET}"
  echo -e "   ${GREEN}4)${RESET} Download only           ${DIM}(fetch/refresh binary)${RESET}"
  echo -e "   ${GREEN}5)${RESET} Configure existing install"
  echo -e "   ${GREEN}6)${RESET} Start service"
  echo -e "   ${GREEN}7)${RESET} Stop service"
  echo -e "   ${GREEN}8)${RESET} Status"
  echo -e "   ${GREEN}9)${RESET} Logs"
  echo -e "  ${GREEN}10)${RESET} Uninstall"
  echo -e "  ${GREEN}11)${RESET} Exit"
  echo ""
  local choice
  read -rp "  Select an option [1-11]: " choice
  echo ""
  case "$choice" in
    1)  cmd_setup client ;;
    2)  cmd_setup server ;;
    3)  cmd_setup unified ;;
    4)  check_deps; cmd_download ;;
    5)  cmd_configure ;;
    6)  cmd_start "$(_prompt_instance)" ;;
    7)  cmd_stop "$(_prompt_instance)" ;;
    8)  cmd_status ;;
    9)  cmd_logs "$(_prompt_instance)" ;;
    10) cmd_uninstall ;;
    11) info "Bye."; exit 0 ;;
    *)  err "Invalid selection: ${choice:-<empty>}"; exit 1 ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
#  Main Entrypoint
# ─────────────────────────────────────────────────────────────────────────────
usage() {
  echo "Usage: $0 [command] [arg]"
  echo ""
  echo "Commands:"
  echo "  (no args)            Open the interactive installer menu"
  echo "  setup [role]         Full guided install: deps + download + configure + service"
  echo "                       Optional role: client | server | unified"
  echo "  download             Download/install the latest binary only"
  echo "  configure [role]     Run the configuration wizard only"
  echo "                       Optional role: client | server | unified"
  echo "  start   <instance>   Start a service instance"
  echo "  stop    <instance>   Stop a service instance"
  echo "  restart <instance>   Restart a service instance"
  echo "  status  [instance]   Show service status"
  echo "  logs    <instance>   Show last 100 log lines"
  echo "  follow  <instance>   Follow logs live"
  echo "  uninstall            Remove binary, services, configs and logs"
}

main() {
  # No arguments -> interactive menu (the primary installer UX).
  if [[ $# -lt 1 ]]; then
    interactive_menu
    exit 0
  fi

  local action="$1"
  shift || true

  case "$action" in
    setup)
      # Optional role preset: setup [client|server|unified]
      cmd_setup "${1:-}"
      ;;
    download)
      check_deps
      cmd_download
      ;;
    configure)
      # Optional role preset: configure [client|server|unified]
      cmd_configure "${1:-}"
      ;;
    start)
      if [[ $# -lt 1 ]]; then err "Missing instance name"; exit 1; fi
      cmd_start "$1"
      ;;
    stop)
      if [[ $# -lt 1 ]]; then err "Missing instance name"; exit 1; fi
      cmd_stop "$1"
      ;;
    restart)
      if [[ $# -lt 1 ]]; then err "Missing instance name"; exit 1; fi
      cmd_restart "$1"
      ;;
    status)
      cmd_status "${1:-}"
      ;;
    logs)
      if [[ $# -lt 1 ]]; then err "Missing instance name"; exit 1; fi
      cmd_logs "$1"
      ;;
    follow)
      if [[ $# -lt 1 ]]; then err "Missing instance name"; exit 1; fi
      cmd_follow "$1"
      ;;
    uninstall)
      cmd_uninstall
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      err "Unknown command: $action"
      usage
      exit 1
      ;;
  esac
}

main "$@"
