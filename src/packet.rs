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
```text
/// [magic:4][version:1][kind:1][tunnel_id:4][seq:4][payload...]
/// 
