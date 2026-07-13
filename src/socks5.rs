//! Raw-socket I/O layer.
//!
//! Provides two abstractions:
//!
//! - [`RawSender`] – builds and transmits spoofed IPv4/UDP, IPv4/ICMP, or
//!   IPv4/TCP packets
//!   via a `SOCK_RAW | IPPROTO_RAW` socket with `IP_HDRINCL`.
//! - [`RawReceiver`] – receives raw IP packets from a `SOCK_RAW | IPPROTO_UDP`,
//!   `SOCK_RAW | IPPROTO_ICMP`, or `SOCK_RAW | IPPROTO_TCP` socket and
//!   demultiplexes them into
//!   `SpoofPacket`s.
//!
//! Both types are bridge objects between the blocking raw-socket world and the
//! async task graph.  Each spawns background `std::thread`s that communicate
//! through `async-channel` channels.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_channel as mpsc;
use bytes::Bytes;
use pnet_packet::icmp::{
    echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes,
};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::MutableTcpPacket;
use pnet_packet::udp::MutableUdpPacket;
use pnet_packet::Packet;

use crate::config::{DpiObfuscation, TunnelProtocol};
use crate::mux_fec::{decode_packets_from_frame, decode_payload, FecDecoder, MuxFecConfig};
use crate::packet::SpoofPacket;
use crate::xor::XorCipher;

// ── Constants ────────────────────────────────────────────────────────────────

const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const TCP_HDR_LEN: usize = 20;
const ICMP_ECHO_HDR_LEN: usize = 8;
/// Minimal RFC 2784 GRE header: 2-byte flags/version (both zero) + 2-byte protocol type.
const GRE_HDR_LEN: usize = 4;
/// GRE protocol type – 0x0800 = IPv4 payload (used as a plausible inner type).
const GRE_PROTO_IPV4: u16 = 0x0800;

/// Default TTL when TTL jitter is disabled.
const SPOOF_TTL: u8 = 64;
/// Realistic OS TTL pool: Linux=64, Windows=128, Cisco/BSD=255.
const TTL_POOL: [u8; 3] = [64, 128, 255];
/// Fake TLS Application Data record header: type=0x17, version=TLS1.2, len follows.
const TLS_RECORD_TYPE: u8 = 0x17;
const TLS_VERSION: [u8; 2] = [0x03, 0x03];
/// DSCP value pool: 0=default, 0x28=AF11 (assured forwarding), 0x10=CS1.
const DSCP_POOL: [u8; 3] = [0x00, 0x28, 0x10];
/// Magic byte that marks a padding-suffixed frame on the wire.
/// The last byte of a padded payload is the pad length (1–255).
/// This is stripped by the receiver before decoding.
const PAD_MARKER_SHIFT: u8 = 0; // pad_len stored as the last byte

/// Fast wrapping counter for IPv4 identification field.
/// Avoids calling `rand::random()` on every outgoing packet.
static IP_ID_COUNTER: AtomicU16 = AtomicU16::new(1);

// ── Outgoing packet descriptor ────────────────────────────────────────────────

/// A request to transmit a single spoofed packet.
#[derive(Debug)]
pub enum OutPacket {
    /// Send a UDP packet carrying `payload` on the data channel.
    Udp {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: Bytes,
    },
    /// Send an ICMP Echo Request carrying `payload` on the control channel.
    Icmp {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        id: u16,
        seq: u16,
        payload: Bytes,
    },
    /// Send an ICMP Echo Reply (server → client) on the control channel.
    IcmpReply {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        id: u16,
        seq: u16,
        payload: Bytes,
    },
    /// Send a raw IPv4 packet with protocol number 58 and no L4 header.
    Proto58 {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: Bytes,
    },
    /// Send an IP-in-IP (protocol 4) packet.  The `payload` is placed
    /// directly after the outer IPv4 header with no additional L4 header.
    Ipip {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: Bytes,
    },
    /// Send a GRE (protocol 47, RFC 2784) packet.
    /// A minimal 4-byte GRE header (flags=0, proto=0x0800 IPv4) is inserted
    /// between the outer IPv4 header and the SpoofTunnel payload.
    Gre {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: Bytes,
    },
    /// Send a TCP packet carrying `payload` on the data channel.
    Tcp {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Bytes,
    },
}

/// A received packet that has been validated and parsed.
#[derive(Debug)]
pub struct InPacket {
    /// True source IP (from the IP header).
    pub src_ip: Ipv4Addr,
    /// Parsed SpoofTunnel application packet.
    pub pkt: SpoofPacket,
}

/// A raw UDP datagram (payload only) received from a spoofed packet.
#[derive(Debug)]
pub struct UdpDatagram {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Bytes,
}

// ── Port filtering ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PortFilter {
    single: u16,
    set: Option<Arc<HashSet<u16>>>,
    range: Option<(u16, u16)>,
}

impl PortFilter {
    pub fn new(single: u16, pool: Option<Arc<Vec<u16>>>, range: Option<(u16, u16)>) -> Self {
        let set = pool.and_then(|ports| {
            if ports.is_empty() {
                None
            } else {
                Some(Arc::new(ports.iter().copied().collect()))
            }
        });
        Self { single, set, range }
    }

    pub fn matches(&self, port: u16) -> bool {
        if let Some((min_port, max_port)) = self.range {
            if port >= min_port && port <= max_port {
                return true;
            }
        }
        if let Some(set) = &self.set {
            set.contains(&port)
        } else {
            port == self.single
        }
    }
}

// ── RawSender ────────────────────────────────────────────────────────────────

/// Sends spoofed IPv4 packets using a background thread.
///
/// Clone the inner `mpsc::Sender` to send packets from multiple tasks.
#[derive(Clone)]
pub struct RawSender {
    tx: mpsc::Sender<OutPacket>,
}

impl RawSender {
    /// Spawn the background sender thread and return a `RawSender` handle.
    ///
    /// When `xor` is `Some`, every outgoing packet payload is XOR-encrypted.
    /// `dpi` controls optional DPI obfuscation (padding, TTL jitter, etc.).
    pub fn spawn(capacity: usize, xor: Option<XorCipher>, dpi: DpiObfuscation) -> Result<Self> {
        log::debug!(
            "raw sender spawn capacity={} xor={} padding={} ttl_jitter={} fake_tls={} dscp={}",
            capacity.max(1),
            xor.is_some(),
            dpi.packet_padding,
            dpi.ttl_jitter,
            dpi.fake_tls_header,
            dpi.random_dscp,
        );
        let fd = create_raw_send_socket()?;
        let cap = capacity.max(1);
        let (tx, rx): (mpsc::Sender<OutPacket>, mpsc::Receiver<OutPacket>) = mpsc::bounded(cap);

        std::thread::Builder::new()
            .name("raw-send".into())
            .spawn(move || {
                while let Ok(out) = rx.recv_blocking() {
                    // 1. Optionally apply fake TLS header (TCP only, before XOR).
                    let out = if dpi.fake_tls_header {
                        apply_fake_tls(out)
                    } else {
                        out
                    };
                    // 2. Optionally append random padding (before XOR so padding is encrypted).
                    let out = if dpi.packet_padding {
                        apply_padding(out, dpi.packet_padding_max)
                    } else {
                        out
                    };
                    // 3. Optionally XOR-encrypt.
                    let out = match &xor {
                        Some(cipher) => encrypt_out_packet(out, cipher),
                        None => out,
                    };
                    // 4. Build and send the wire packet (TTL jitter + DSCP applied inside).
                    if let Err(e) = send_out_packet(fd, out, &dpi) {
                        log::warn!("raw-send error: {}", e);
                    }
                }
                unsafe { libc::close(fd) };
            })
            .context("spawn raw send thread")?;

        Ok(Self { tx })
    }

    /// Enqueue an [`OutPacket`] for transmission.
    pub async fn send(&self, pkt: OutPacket) -> Result<()> {
        self.tx.send(pkt).await.context("raw sender closed")
    }
}
