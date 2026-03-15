use iris_core::{
    L4Pdu,
    protocols::packet::{tcp::TCP_PROTOCOL, udp::UDP_PROTOCOL},
};

/// See Section 7.1 in the original paper
pub const WINDOW_SIZE_ACK: usize = 150;
/// Analysis window size - see Section 7.2
pub const WINDOW_SIZE_ANALYSIS: usize = 100;

lazy_static::lazy_static! {
    /// Required packets
    pub static ref N_REQ_PKTS: usize = std::cmp::min(WINDOW_SIZE_ACK, WINDOW_SIZE_ANALYSIS);
}

/// OpenVPN-specific constants
pub const TCP_HDRLEN_BYTES: usize = 3;
pub const UDP_HDRLEN_BYTES: usize = 1;

/// OpenVPN header
pub fn openvpn_hdrlen(pdu: &L4Pdu) -> usize {
    match pdu.ctxt.proto {
        TCP_PROTOCOL => TCP_HDRLEN_BYTES,
        UDP_PROTOCOL => UDP_HDRLEN_BYTES,
        _ => 0,
    }
}

/// Valid OpenVPN opcodes
/// Note: can't rely on these due to encryption/XOR'd payloads
#[allow(dead_code)]
pub const OPCODES: [u8; 10] = [
    0x01, // client reset
    0x02, // server reset
    0x03, // soft reset
    0x04, // control
    0x05, // ack
    0x06, // data
    0x07, // client reset
    0x08, // server reset
    0x09, // data
    0x0A, // client reset
];

pub const CRST_OPCODE: u8 = 0x01;
pub const SRST_OPCODE: u8 = 0x02;

pub const N_OPCODES: usize = OPCODES.len();
