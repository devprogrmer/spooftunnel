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

// ── RawReceiver ───────────────────────────────────────────────────────────────

/// Receives and parses incoming raw IP packets in a background thread.
pub struct RawReceiver {
    rx: mpsc::Receiver<InPacket>,
}

/// Receives raw UDP payloads without SpoofPacket decoding.
pub struct RawUdpReceiver {
    rx: mpsc::Receiver<UdpDatagram>,
}

impl RawReceiver {
    /// Spawn background threads for reception and return a `RawReceiver`.
    ///
    /// `icmp_id` – the ICMP identifier to match (filters out foreign pings).
    /// `allow_any_icmp_id` – accept any ICMP identifier.
    /// `allowed` – set of peer IPs whose packets are trusted.
    pub fn spawn(
        protocol: TunnelProtocol,
        port_filter: PortFilter,
        icmp_id: u16,
        allow_any_icmp_id: bool,
        allowed: Vec<Ipv4Addr>,
        mux_fec: MuxFecConfig,
        capacity: usize,
        xor: Option<XorCipher>,
        dpi: DpiObfuscation,
    ) -> Result<Self> {
        log::debug!(
            "raw receiver spawn proto={:?} allow_any_icmp_id={} allowed_peers={} mux_fec={} xor={} padding={}",
            protocol,
            allow_any_icmp_id,
            allowed.len(),
            mux_fec.is_enabled(),
            xor.is_some(),
            dpi.packet_padding,
        );
        let cap = capacity.max(1);
        let (tx, rx): (mpsc::Sender<InPacket>, mpsc::Receiver<InPacket>) = mpsc::bounded(cap);

        let padding = dpi.packet_padding;
        let fake_tls = dpi.fake_tls_header;

        match protocol {
            TunnelProtocol::Udp => {
                let udp_fd = create_raw_recv_socket(libc::IPPROTO_UDP as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let port_filter2 = port_filter.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-udp".into())
                    .spawn(move || {
                        udp_recv_loop(
                            udp_fd,
                            port_filter2,
                            &allowed2,
                            tx2,
                            mux_fec2,
                            xor2.as_ref(),
                            padding,
                        );
                    })
                    .context("spawn udp recv thread")?;
            }
            TunnelProtocol::Icmp => {
                let icmp_fd = create_raw_recv_socket(libc::IPPROTO_ICMP as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-icmp".into())
                    .spawn(move || {
                        icmp_recv_loop(
                            icmp_fd,
                            icmp_id,
                            allow_any_icmp_id,
                            &allowed2,
                            tx2,
                            mux_fec2,
                            xor2.as_ref(),
                            padding,
                        );
                    })
                    .context("spawn icmp recv thread")?;
            }
            TunnelProtocol::Proto58 => {
                let proto_fd = create_raw_recv_socket(libc::IPPROTO_ICMPV6 as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-proto58".into())
                    .spawn(move || {
                        proto58_recv_loop(
                            proto_fd,
                            &allowed2,
                            tx2,
                            mux_fec2,
                            xor2.as_ref(),
                            padding,
                        );
                    })
                    .context("spawn proto58 recv thread")?;
            }
            TunnelProtocol::Tcp => {
                let tcp_fd = create_raw_recv_socket(libc::IPPROTO_TCP as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let port_filter2 = port_filter.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-tcp".into())
                    .spawn(move || {
                        tcp_recv_loop(
                            tcp_fd,
                            port_filter2,
                            &allowed2,
                            tx2,
                            xor2.as_ref(),
                            padding,
                            fake_tls,
                        );
                    })
                    .context("spawn tcp recv thread")?;
            }
            TunnelProtocol::Ipip => {
                let ipip_fd = create_raw_recv_socket(libc::IPPROTO_IPIP as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-ipip".into())
                    .spawn(move || {
                        ipip_recv_loop(
                            ipip_fd,
                            &allowed2,
                            tx2,
                            mux_fec2,
                            xor2.as_ref(),
                            padding,
                        );
                    })
                    .context("spawn ipip recv thread")?;
            }
            TunnelProtocol::Gre => {
                const IPPROTO_GRE: libc::c_int = 47;
                let gre_fd = create_raw_recv_socket(IPPROTO_GRE)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-gre".into())
                    .spawn(move || {
                        gre_recv_loop(
                            gre_fd,
                            &allowed2,
                            tx2,
                            mux_fec2,
                            xor2.as_ref(),
                            padding,
                        );
                    })
                    .context("spawn gre recv thread")?;
            }
            TunnelProtocol::Quic => {
                bail!("raw receiver does not support quic");
            }
        }

        Ok(Self { rx })
    }

    /// Await the next validated incoming packet.
    pub async fn recv(&mut self) -> Option<InPacket> {
        self.rx.recv().await.ok()
    }
}

impl RawUdpReceiver {
    /// Spawn background thread for UDP payload reception.
    pub fn spawn(port_filter: PortFilter, allowed: Vec<Ipv4Addr>, capacity: usize) -> Result<Self> {
        let cap = capacity.max(1);
        let (tx, rx): (mpsc::Sender<UdpDatagram>, mpsc::Receiver<UdpDatagram>) = mpsc::bounded(cap);
        let udp_fd = create_raw_recv_socket(libc::IPPROTO_UDP as libc::c_int)?;
        std::thread::Builder::new()
            .name("raw-recv-udp-raw".into())
            .spawn(move || {
                udp_payload_loop(udp_fd, port_filter, &allowed, tx);
            })
            .context("spawn udp raw recv thread")?;

        Ok(Self { rx })
    }

    pub async fn recv(&mut self) -> Option<UdpDatagram> {
        self.rx.recv().await.ok()
    }
}

// ── Socket creation helpers ───────────────────────────────────────────────────

/// 4 MiB kernel socket send/receive buffer – large enough to absorb 1 Gbps+ bursts.
const SOCK_BUF_SIZE: libc::c_int = 4 * 1024 * 1024;

fn set_sock_buf(fd: RawFd) {
    let size = SOCK_BUF_SIZE;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        );
    }
}

fn create_raw_send_socket() -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed – CAP_NET_RAW required");
    }
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
    }
    set_sock_buf(fd);
    Ok(fd)
}

fn create_raw_recv_socket(proto: libc::c_int) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("socket(AF_INET, SOCK_RAW, …) failed – CAP_NET_RAW required");
    }
    set_sock_buf(fd);
    Ok(fd)
}

// ── Packet transmission ───────────────────────────────────────────────────────

fn send_out_packet(fd: RawFd, out: OutPacket, dpi: &DpiObfuscation) -> Result<()> {
    match out {
        OutPacket::Udp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
        } => {
            let mut raw = build_udp_packet(src_ip, dst_ip, src_port, dst_port, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Icmp {
            src_ip,
            dst_ip,
            id,
            seq,
            payload,
        } => {
            let mut raw = build_icmp_echo(src_ip, dst_ip, id, seq, &payload, false);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::IcmpReply {
            src_ip,
            dst_ip,
            id,
            seq,
            payload,
        } => {
            let mut raw = build_icmp_echo(src_ip, dst_ip, id, seq, &payload, true);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Proto58 {
            src_ip,
            dst_ip,
            payload,
        } => {
            let mut raw = build_proto58_packet(src_ip, dst_ip, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
        } => {
            let mut raw = build_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Ipip { src_ip, dst_ip, payload } => {
            let mut raw = build_ipip_packet(src_ip, dst_ip, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Gre { src_ip, dst_ip, payload } => {
            let mut raw = build_gre_packet(src_ip, dst_ip, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
    }
}

// ── Packet reception loops ────────────────────────────────────────────────────

fn udp_recv_loop(
    fd: RawFd,
    port_filter: PortFilter,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec { Some(FecDecoder::new()) } else { None };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("udp recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            log::trace!("udp drop src_not_allowed={}", src_ip);
            continue;
        }

        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + UDP_HDR_LEN {
            continue;
        }
        let udp_data = &data[ihl..];

        let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
        if !port_filter.matches(dst_port) {
            log::trace!("udp drop dst_port={}", dst_port);
            continue;
        }

        if udp_data.len() < UDP_HDR_LEN {
            continue;
        }
        let raw_payload = bytes::Bytes::copy_from_slice(&udp_data[UDP_HDR_LEN..]);
        let payload = match xor {
            Some(c) => match c.decrypt(raw_payload) {
                Some(p) => p,
                None => {
                    log::trace!("udp xor decrypt failed");
                    continue;
                }
            },
            None => raw_payload,
        };
        let payload = if padding {
            match strip_padding(payload) {
                Some(p) => p,
                None => {
                    log::trace!("udp pad strip failed");
                    continue;
                }
            }
        } else {
            payload
        };

        if mux_fec.is_enabled() {
            match decode_payload(payload) {
                Ok(frame) => match decode_packets_from_frame(frame, fec_state.as_mut()) {
                    Ok(pkts) => {
                        for pkt in pkts {
                            let _ = tx.send_blocking(InPacket { src_ip, pkt });
                        }
                    }
                    Err(e) => log::trace!("udp mux decode: {}", e),
                },
                Err(e) => log::trace!("udp mux frame: {}", e),
            }
        } else {
            match SpoofPacket::decode(payload) {
                Ok(pkt) => {
                    let _ = tx.send_blocking(InPacket { src_ip, pkt });
                }
                Err(e) => log::trace!("udp decode: {}", e),
            }
        }
    }
}

fn icmp_recv_loop(
    fd: RawFd,
    icmp_id: u16,
    allow_any_icmp_id: bool,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec { Some(FecDecoder::new()) } else { None };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("icmp recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            log::trace!("icmp drop src_not_allowed={}", src_ip);
            continue;
        }

        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + ICMP_ECHO_HDR_LEN {
            continue;
        }
        let icmp_data = &data[ihl..];

        let icmp_type = icmp_data[0];
        if icmp_type != 8 && icmp_type != 0 {
            continue;
        }

        let id = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
        if !allow_any_icmp_id && id != icmp_id {
            log::trace!("icmp drop id_mismatch id={}", id);
            continue;
        }

        let raw_payload = bytes::Bytes::copy_from_slice(&icmp_data[ICMP_ECHO_HDR_LEN..]);
        let payload = match xor {
            Some(c) => match c.decrypt(raw_payload) {
                Some(p) => p,
                None => {
                    log::trace!("icmp xor decrypt failed");
                    continue;
                }
            },
            None => raw_payload,
        };
        let payload = if padding {
            match strip_padding(payload) {
                Some(p) => p,
                None => {
                    log::trace!("icmp pad strip failed");
                    continue;
                }
            }
        } else {
            payload
        };

        if mux_fec.is_enabled() {
            match decode_payload(payload) {
                Ok(frame) => match decode_packets_from_frame(frame, fec_state.as_mut()) {
                    Ok(pkts) => {
                        for pkt in pkts {
                            let _ = tx.send_blocking(InPacket { src_ip, pkt });
                        }
                    }
                    Err(e) => log::trace!("icmp mux decode: {}", e),
                },
                Err(e) => log::trace!("icmp mux frame: {}", e),
            }
        } else {
            match SpoofPacket::decode(payload) {
                Ok(pkt) => {
                    let _ = tx.send_blocking(InPacket { src_ip, pkt });
                }
                Err(e) => log::trace!("icmp decode: {}", e),
            }
        }
    }
}

// ... same pattern continues below:
// - proto58_recv_loop: SpoofPacket::decode
// - ipip_recv_loop comments: SpoofTunnel payload + SpoofPacket::decode
// - gre_recv_loop comments: SpoofTunnel payload + SpoofPacket::decode
// - tcp_recv_loop: SpoofPacket::decode

fn fill_ipv4_header(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: pnet_packet::ip::IpNextHeaderProtocol,
    ip_total: usize,
) {
    let mut pkt = MutableIpv4Packet::new(buf).unwrap();
    pkt.set_version(4);
    pkt.set_header_length(5);
    pkt.set_dscp(0);
    pkt.set_ecn(0);
    pkt.set_total_length(ip_total as u16);
    pkt.set_identification(IP_ID_COUNTER.fetch_add(1, Ordering::Relaxed));
    // Leave DF clear: let the network fragment if needed. SpoofTunnel already
    // limits payload to the configured MTU so fragmentation is rare in practice,
    // but a hard DF causes silent black-holes when the path MTU is smaller.
    pkt.set_flags(0u8);
    pkt.set_fragment_offset(0);
    pkt.set_ttl(SPOOF_TTL);
    pkt.set_next_level_protocol(protocol);
    pkt.set_source(src_ip);
    pkt.set_destination(dst_ip);
    pkt.set_checksum(0);
    let cksum = pnet_packet::ipv4::checksum(&pkt.to_immutable());
    pkt.set_checksum(cksum);
}
