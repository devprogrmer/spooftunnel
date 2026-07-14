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
use bytes::{BufMut, Bytes, BytesMut};
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

// ── Wire packet builders ──────────────────────────────────────────────────────
//
// Each builder returns a full IPv4 packet (header included) ready to be handed
// to `patch_ip_header` and `raw_sendto`. The outer IPv4 header is assembled by
// the shared `fill_ipv4_header` helper; the L4 header and checksum are filled in
// here.

fn build_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = IP_HDR_LEN + UDP_HDR_LEN + payload.len();
    let mut buf = vec![0u8; total];
    fill_ipv4_header(
        &mut buf[..IP_HDR_LEN],
        src,
        dst,
        IpNextHeaderProtocols::Udp,
        total,
    );
    {
        let mut udp = MutableUdpPacket::new(&mut buf[IP_HDR_LEN..]).unwrap();
        udp.set_source(sport);
        udp.set_destination(dport);
        udp.set_length((UDP_HDR_LEN + payload.len()) as u16);
        udp.set_payload(payload);
        udp.set_checksum(0);
        let cksum = pnet_packet::udp::ipv4_checksum(&udp.to_immutable(), &src, &dst);
        udp.set_checksum(cksum);
    }
    buf
}

fn build_icmp_echo(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
    reply: bool,
) -> Vec<u8> {
    let total = IP_HDR_LEN + ICMP_ECHO_HDR_LEN + payload.len();
    let mut buf = vec![0u8; total];
    fill_ipv4_header(
        &mut buf[..IP_HDR_LEN],
        src,
        dst,
        IpNextHeaderProtocols::Icmp,
        total,
    );
    {
        let mut echo = MutableEchoRequestPacket::new(&mut buf[IP_HDR_LEN..]).unwrap();
        echo.set_icmp_type(if reply {
            IcmpTypes::EchoReply
        } else {
            IcmpTypes::EchoRequest
        });
        echo.set_icmp_code(IcmpCode::new(0));
        echo.set_identifier(id);
        echo.set_sequence_number(seq);
        echo.set_payload(payload);
    }
    // Checksum spans the whole ICMP message (header + payload).
    {
        let mut icmp = pnet_packet::icmp::MutableIcmpPacket::new(&mut buf[IP_HDR_LEN..]).unwrap();
        icmp.set_checksum(0);
        let cksum = pnet_packet::icmp::checksum(&IcmpPacket::new(icmp.packet()).unwrap());
        icmp.set_checksum(cksum);
    }
    buf
}

fn build_proto58_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = IP_HDR_LEN + payload.len();
    let mut buf = vec![0u8; total];
    let proto = pnet_packet::ip::IpNextHeaderProtocol::new(58);
    fill_ipv4_header(&mut buf[..IP_HDR_LEN], src, dst, proto, total);
    buf[IP_HDR_LEN..].copy_from_slice(payload);
    buf
}

fn build_ipip_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = IP_HDR_LEN + payload.len();
    let mut buf = vec![0u8; total];
    // Protocol 4 = IP-in-IP. The payload is the inner packet with no L4 header.
    let proto = pnet_packet::ip::IpNextHeaderProtocol::new(4);
    fill_ipv4_header(&mut buf[..IP_HDR_LEN], src, dst, proto, total);
    buf[IP_HDR_LEN..].copy_from_slice(payload);
    buf
}

fn build_gre_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = IP_HDR_LEN + GRE_HDR_LEN + payload.len();
    let mut buf = vec![0u8; total];
    // Protocol 47 = GRE (RFC 2784).
    let proto = pnet_packet::ip::IpNextHeaderProtocol::new(47);
    fill_ipv4_header(&mut buf[..IP_HDR_LEN], src, dst, proto, total);
    // Minimal GRE header: 2-byte flags/version (all zero) + 2-byte protocol type.
    buf[IP_HDR_LEN] = 0;
    buf[IP_HDR_LEN + 1] = 0;
    buf[IP_HDR_LEN + 2..IP_HDR_LEN + GRE_HDR_LEN].copy_from_slice(&GRE_PROTO_IPV4.to_be_bytes());
    buf[IP_HDR_LEN + GRE_HDR_LEN..].copy_from_slice(payload);
    buf
}

#[allow(clippy::too_many_arguments)]
fn build_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = IP_HDR_LEN + TCP_HDR_LEN + payload.len();
    let mut buf = vec![0u8; total];
    fill_ipv4_header(
        &mut buf[..IP_HDR_LEN],
        src,
        dst,
        IpNextHeaderProtocols::Tcp,
        total,
    );
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IP_HDR_LEN..]).unwrap();
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5); // 20-byte header, no options.
        tcp.set_flags(flags);
        tcp.set_window(65535);
        tcp.set_payload(payload);
        tcp.set_checksum(0);
        let cksum = pnet_packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(cksum);
    }
    buf
}

// ── IPv4 header post-processing (DPI obfuscation) ─────────────────────────────

/// Apply optional TTL jitter / DSCP randomisation to an already-built IPv4
/// packet and recompute the header checksum.
fn patch_ip_header(buf: &mut [u8], dpi: &DpiObfuscation) {
    if !dpi.ttl_jitter && !dpi.random_dscp {
        return;
    }
    let mut pkt = match MutableIpv4Packet::new(buf) {
        Some(p) => p,
        None => return,
    };
    if dpi.ttl_jitter {
        let ttl = TTL_POOL[(rand::random::<u8>() as usize) % TTL_POOL.len()];
        pkt.set_ttl(ttl);
    }
    if dpi.random_dscp {
        // DSCP_POOL holds ToS bytes; the 6-bit DSCP field is the top 6 bits.
        let tos = DSCP_POOL[(rand::random::<u8>() as usize) % DSCP_POOL.len()];
        pkt.set_dscp(tos >> 2);
    }
    pkt.set_checksum(0);
    let cksum = pnet_packet::ipv4::checksum(&pkt.to_immutable());
    pkt.set_checksum(cksum);
}

// ── Raw socket send/recv syscalls ─────────────────────────────────────────────

fn sockaddr_in(dst: Ipv4Addr) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = u32::from(dst).to_be();
    addr
}

fn raw_sendto(fd: RawFd, buf: &[u8], dst: Ipv4Addr) -> Result<()> {
    let addr = sockaddr_in(dst);
    let ret = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("sendto");
    }
    Ok(())
}

fn raw_recvfrom(fd: RawFd, buf: &mut [u8]) -> Result<(usize, Ipv4Addr)> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addrlen,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("recvfrom");
    }
    let src = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok((n as usize, src))
}

// ── Source-IP allowlist ───────────────────────────────────────────────────────

/// An empty allowlist means "accept any source" (used for `--check-allow-any`).
fn is_allowed(src: Ipv4Addr, allowed: &[Ipv4Addr]) -> bool {
    allowed.is_empty() || allowed.contains(&src)
}

// ── Padding / XOR / fake-TLS payload transforms ───────────────────────────────

fn map_payload<F: FnOnce(Bytes) -> Bytes>(out: OutPacket, f: F) -> OutPacket {
    match out {
        OutPacket::Udp { src_ip, dst_ip, src_port, dst_port, payload } => OutPacket::Udp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload: f(payload),
        },
        OutPacket::Icmp { src_ip, dst_ip, id, seq, payload } => OutPacket::Icmp {
            src_ip,
            dst_ip,
            id,
            seq,
            payload: f(payload),
        },
        OutPacket::IcmpReply { src_ip, dst_ip, id, seq, payload } => OutPacket::IcmpReply {
            src_ip,
            dst_ip,
            id,
            seq,
            payload: f(payload),
        },
        OutPacket::Proto58 { src_ip, dst_ip, payload } => OutPacket::Proto58 {
            src_ip,
            dst_ip,
            payload: f(payload),
        },
        OutPacket::Ipip { src_ip, dst_ip, payload } => OutPacket::Ipip {
            src_ip,
            dst_ip,
            payload: f(payload),
        },
        OutPacket::Gre { src_ip, dst_ip, payload } => OutPacket::Gre {
            src_ip,
            dst_ip,
            payload: f(payload),
        },
        OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
        } => OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload: f(payload),
        },
    }
}

/// Append `1..=max` random bytes, with the final byte encoding the pad length.
/// Reversed by [`strip_padding`] on the receiver.
fn apply_padding(out: OutPacket, max: u8) -> OutPacket {
    map_payload(out, |p| {
        let max = max.max(1);
        let pad_len = (rand::random::<u8>() % max) as usize + 1; // 1..=max
        let mut b = BytesMut::with_capacity(p.len() + pad_len);
        b.put_slice(&p);
        for _ in 0..pad_len - 1 {
            b.put_u8(rand::random::<u8>());
        }
        b.put_u8(pad_len as u8);
        b.freeze()
    })
}

/// Reverse [`apply_padding`]. Returns `None` if the trailer is malformed.
fn strip_padding(payload: Bytes) -> Option<Bytes> {
    if payload.is_empty() {
        return None;
    }
    let pad_len = *payload.last().unwrap() as usize;
    if pad_len == 0 || pad_len > payload.len() {
        return None;
    }
    Some(payload.slice(0..payload.len() - pad_len))
}

fn encrypt_out_packet(out: OutPacket, cipher: &XorCipher) -> OutPacket {
    map_payload(out, |p| cipher.encrypt(&p))
}

/// Prefix a TCP payload with a 5-byte fake TLS Application-Data record header.
/// Non-TCP packets are returned unchanged.
fn apply_fake_tls(out: OutPacket) -> OutPacket {
    match out {
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
            let mut b = BytesMut::with_capacity(5 + payload.len());
            b.put_u8(TLS_RECORD_TYPE);
            b.put_slice(&TLS_VERSION);
            b.put_u16(payload.len() as u16);
            b.put_slice(&payload);
            OutPacket::Tcp {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq,
                ack,
                flags,
                payload: b.freeze(),
            }
        }
        other => other,
    }
}

// ── Shared receive-path helpers ───────────────────────────────────────────────

/// XOR-decrypt (if enabled) then strip padding (if enabled). Returns the
/// recovered SpoofTunnel frame, or `None` if either step fails.
fn deobfuscate(raw: Bytes, xor: Option<&XorCipher>, padding: bool) -> Option<Bytes> {
    let p = match xor {
        Some(c) => c.decrypt(raw)?,
        None => raw,
    };
    if padding {
        strip_padding(p)
    } else {
        Some(p)
    }
}

/// Decode a recovered frame (mux/FEC or a bare SpoofPacket) and forward it.
fn deliver(
    payload: Bytes,
    src_ip: Ipv4Addr,
    mux_fec: &MuxFecConfig,
    fec_state: &mut Option<FecDecoder>,
    tx: &mpsc::Sender<InPacket>,
) {
    if mux_fec.is_enabled() {
        match decode_payload(payload) {
            Ok(frame) => match decode_packets_from_frame(frame, fec_state.as_mut()) {
                Ok(pkts) => {
                    for pkt in pkts {
                        let _ = tx.send_blocking(InPacket { src_ip, pkt });
                    }
                }
                Err(e) => log::trace!("mux decode: {}", e),
            },
            Err(e) => log::trace!("mux frame: {}", e),
        }
    } else {
        match SpoofPacket::decode(payload) {
            Ok(pkt) => {
                let _ = tx.send_blocking(InPacket { src_ip, pkt });
            }
            Err(e) => log::trace!("decode: {}", e),
        }
    }
}

// ── Additional protocol receive loops ─────────────────────────────────────────

/// Receive loop for a raw-IP transport whose payload sits immediately after the
/// IPv4 header (protocol 58 and IP-in-IP).
fn raw_ip_recv_loop(
    name: &str,
    fd: RawFd,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec {
        Some(FecDecoder::new())
    } else {
        None
    };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("{} recvfrom: {}", name, e);
                continue;
            }
        };
        let data = &buf[..n];
        if data.len() < IP_HDR_LEN || !is_allowed(src_ip, allowed) {
            continue;
        }
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl {
            continue;
        }
        let raw_payload = Bytes::copy_from_slice(&data[ihl..]);
        let payload = match deobfuscate(raw_payload, xor, padding) {
            Some(p) => p,
            None => continue,
        };
        deliver(payload, src_ip, &mux_fec, &mut fec_state, &tx);
    }
}

fn proto58_recv_loop(
    fd: RawFd,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    raw_ip_recv_loop("proto58", fd, allowed, tx, mux_fec, xor, padding);
}

fn ipip_recv_loop(
    fd: RawFd,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    raw_ip_recv_loop("ipip", fd, allowed, tx, mux_fec, xor, padding);
}

fn gre_recv_loop(
    fd: RawFd,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec {
        Some(FecDecoder::new())
    } else {
        None
    };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("gre recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];
        if data.len() < IP_HDR_LEN || !is_allowed(src_ip, allowed) {
            continue;
        }
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + GRE_HDR_LEN {
            continue;
        }
        // Skip the 4-byte GRE header before the SpoofTunnel frame.
        let raw_payload = Bytes::copy_from_slice(&data[ihl + GRE_HDR_LEN..]);
        let payload = match deobfuscate(raw_payload, xor, padding) {
            Some(p) => p,
            None => continue,
        };
        deliver(payload, src_ip, &mux_fec, &mut fec_state, &tx);
    }
}

fn tcp_recv_loop(
    fd: RawFd,
    port_filter: PortFilter,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    xor: Option<&XorCipher>,
    padding: bool,
    fake_tls: bool,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("tcp recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];
        if data.len() < IP_HDR_LEN || !is_allowed(src_ip, allowed) {
            continue;
        }
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + TCP_HDR_LEN {
            continue;
        }
        let tcp = &data[ihl..];
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        if !port_filter.matches(dst_port) {
            continue;
        }
        let data_off = ((tcp[12] >> 4) as usize) * 4;
        if data_off < TCP_HDR_LEN || tcp.len() < data_off {
            continue;
        }
        let mut payload = Bytes::copy_from_slice(&tcp[data_off..]);
        payload = match xor {
            Some(c) => match c.decrypt(payload) {
                Some(p) => p,
                None => continue,
            },
            None => payload,
        };
        if padding {
            payload = match strip_padding(payload) {
                Some(p) => p,
                None => continue,
            };
        }
        if fake_tls {
            if payload.len() < 5 {
                continue;
            }
            payload = payload.slice(5..);
        }
        match SpoofPacket::decode(payload) {
            Ok(pkt) => {
                let _ = tx.send_blocking(InPacket { src_ip, pkt });
            }
            Err(e) => log::trace!("tcp decode: {}", e),
        }
    }
}

/// Receive loop for [`RawUdpReceiver`]: extracts raw UDP payloads without
/// SpoofPacket decoding or de-obfuscation.
fn udp_payload_loop(
    fd: RawFd,
    port_filter: PortFilter,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<UdpDatagram>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("udp-raw recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];
        if data.len() < IP_HDR_LEN || !is_allowed(src_ip, allowed) {
            continue;
        }
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + UDP_HDR_LEN {
            continue;
        }
        let udp = &data[ihl..];
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        if !port_filter.matches(dst_port) {
            continue;
        }
        let payload = Bytes::copy_from_slice(&udp[UDP_HDR_LEN..]);
        let _ = tx.send_blocking(UdpDatagram {
            src_ip,
            src_port,
            dst_port,
            payload,
        });
    }
}
