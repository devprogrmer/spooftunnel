//! SpoofTunnel — bidirectional IP spoofing tunnel for heavily censored networks.
//!
//! This crate is consumed by the `client`, `server`, and `spoof-tunnel`
//! binaries (see `src/bin/`). All shared runtime logic lives in the modules
//! re-exported below.

// High-performance global allocator. Substantially reduces allocation overhead
// under heavy multi-threaded packet I/O. Applies to every binary that links
// this crate.
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub mod app;
pub mod check;
pub mod config;
pub mod logging;
pub mod mux_fec;
pub mod packet;
pub mod port_forward;
pub mod quic;
pub mod raw_socket;
pub mod tun;
pub mod tun_bridge;
pub mod tuning;
pub mod tunnel;
pub mod xor;
