//! SpoofTunnel wire protocol - the application-level packet that rides inside
//! spoofed UDP (data channel) or ICMP Echo (control channel) payloads.

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// 4-byte magic number at the start of every SpoofPacket.
pub const MAGIC: u32 = 0xCA_FE_5F_00;
/// Current protocol version.
pub const VERSION: u8 = 1;
/// Minimum wire size of a SpoofPacket (no payload).
pub const HEADER_SIZE: usize = 14;

/// Type of a SpoofPacket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    /// Application data.
    Data = 0,
    /// Tunnel open request (client -> server).
    Syn = 1,
    /// Tunnel open acknowledgement (server -> client).
    SynAck = 2,
    /// Tunnel teardown.
    Fin = 3,
    /// Keepalive ping.
    Heartbeat = 4,
    /// Keepalive pong.
    HeartbeatAck = 5,
}

impl TryFrom<u8> for PacketKind {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Syn),
            2 => Ok(Self::SynAck),
            3 => Ok(Self::Fin),
            4 => Ok(Self::Heartbeat),
            5 => Ok(Self::HeartbeatAck),
            _ => bail!("unknown packet kind {}", v),
        }
    }
}

/// An application-level SpoofTunnel packet.
///
/// Wire format (big-endian):
///
/// ```text
/// [magic:4][version:1][kind:1][tunnel_id:4][seq:4][payload...]
/// ```
#[derive(Debug, Clone)]
pub struct SpoofPacket {
    /// Packet type.
    pub kind: PacketKind,
    /// Identifier of the tunnel this packet belongs to.
    pub tunnel_id: u32,
    /// Per-tunnel sequence number.
    pub seq: u32,
    /// Application payload (empty for control packets).
    pub payload: Bytes,
}

impl SpoofPacket {
    /// Construct a data packet carrying `payload`.
    pub fn new_data(tunnel_id: u32, seq: u32, payload: Bytes) -> Self {
        Self { kind: PacketKind::Data, tunnel_id, seq, payload }
    }

    /// Construct a tunnel-open request (client -> server).
    pub fn new_syn(tunnel_id: u32, seq: u32) -> Self {
        Self { kind: PacketKind::Syn, tunnel_id, seq, payload: Bytes::new() }
    }

    /// Construct a tunnel-open acknowledgement (server -> client).
    pub fn new_syn_ack(tunnel_id: u32, seq: u32) -> Self {
        Self { kind: PacketKind::SynAck, tunnel_id, seq, payload: Bytes::new() }
    }

    /// Construct a tunnel teardown packet.
    pub fn new_fin(tunnel_id: u32) -> Self {
        Self { kind: PacketKind::Fin, tunnel_id, seq: 0, payload: Bytes::new() }
    }

    /// Construct a keepalive heartbeat.
    pub fn new_heartbeat(tunnel_id: u32, seq: u32) -> Self {
        Self { kind: PacketKind::Heartbeat, tunnel_id, seq, payload: Bytes::new() }
    }

    /// Serialize to wire bytes:
    /// `[magic:4][version:1][kind:1][tunnel_id:4][seq:4][payload...]`.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.put_u32(MAGIC);
        buf.put_u8(VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u32(self.tunnel_id);
        buf.put_u32(self.seq);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    /// Parse a [`SpoofPacket`] from wire bytes produced by [`SpoofPacket::encode`].
    ///
    /// The returned payload is a zero-copy slice of `frame`.
    pub fn decode(mut frame: Bytes) -> Result<Self> {
        if frame.len() < HEADER_SIZE {
            bail!("spoof packet too short: {} < {}", frame.len(), HEADER_SIZE);
        }
        let magic = frame.get_u32();
        if magic != MAGIC {
            bail!("bad spoof packet magic: {:#010x}", magic);
        }
        let version = frame.get_u8();
        if version != VERSION {
            bail!("unsupported spoof packet version: {}", version);
        }
        let kind = PacketKind::try_from(frame.get_u8())?;
        let tunnel_id = frame.get_u32();
        let seq = frame.get_u32();
        // `get_*` advanced the cursor past the 14-byte header; the remainder is
        // the payload.
        let payload = frame;
        Ok(Self { kind, tunnel_id, seq, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_data() {
        let pkt = SpoofPacket::new_data(42, 7, Bytes::from_static(b"hello world"));
        let enc = pkt.encode();
        assert_eq!(enc.len(), HEADER_SIZE + 11);
        let dec = SpoofPacket::decode(enc).unwrap();
        assert_eq!(dec.kind, PacketKind::Data);
        assert_eq!(dec.tunnel_id, 42);
        assert_eq!(dec.seq, 7);
        assert_eq!(&dec.payload[..], b"hello world");
    }

    #[test]
    fn roundtrip_control_empty_payload() {
        for pkt in [
            SpoofPacket::new_syn(1, 100),
            SpoofPacket::new_syn_ack(1, 200),
            SpoofPacket::new_fin(1),
            SpoofPacket::new_heartbeat(1, 300),
        ] {
            let dec = SpoofPacket::decode(pkt.encode()).unwrap();
            assert_eq!(dec.tunnel_id, pkt.tunnel_id);
            assert_eq!(dec.kind, pkt.kind);
            assert!(dec.payload.is_empty());
        }
    }

    #[test]
    fn decode_rejects_short_and_bad_magic() {
        assert!(SpoofPacket::decode(Bytes::from_static(b"tiny")).is_err());
        let mut bad = BytesMut::from(&SpoofPacket::new_fin(1).encode()[..]);
        bad[0] ^= 0xff;
        assert!(SpoofPacket::decode(bad.freeze()).is_err());
    }
}
