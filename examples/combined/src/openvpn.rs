use iris_compiler::*;
use iris_core::L4Pdu;

/// See section 6.2
const ACK_BIN_SIZE: usize = 10;
const BIN_ARRAY_SIZE: usize = WINDOW_SIZE_ANALYSIS / ACK_BIN_SIZE;

#[derive(Clone, Debug)]
#[datatype]
pub struct OpenVPNAcks {
    /// Expected length of ACK packets, inferred by second client packet
    /// (third packet overall)
    pub ack_len: Option<usize>,

    /// Bins for tracking number of ACK packets
    pub bins: [usize; BIN_ARRAY_SIZE],

    /// Number of packets with data beyond TCP/UDP header.
    pub n_payload_pkts_ctos: usize,
    pub n_payload_pkts_stoc: usize,

    /// (TODO placeholder until datatype can return false)
    pub drop: bool,
}

impl OpenVPNAcks {
    pub fn new(_: &L4Pdu) -> Self {
        OpenVPNAcks {
            ack_len: None,
            bins: [0; BIN_ARRAY_SIZE],
            n_payload_pkts_ctos: 0,
            n_payload_pkts_stoc: 0,
            drop: false,
        }
    }

    #[datatype_group("OpenVPNAcks,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        if self.drop {
            return;
        }

        // Ignore packets without a (potential) OpenVPN header
        if pdu.length() < openvpn_hdrlen(pdu) {
            return;
        }

        // Update packet counters to end of window
        if pdu.dir {
            self.n_payload_pkts_ctos += 1;
        } else {
            self.n_payload_pkts_stoc += 1;
        }
        if self.n_payload_pkts() > WINDOW_SIZE_ACK {
            self.drop = true;
            return;
        }

        // Stop recording ACKs, but only include flows with
        // at least 150 data packets (15 bins)
        if self.n_payload_pkts() > WINDOW_SIZE_ANALYSIS {
            return;
        }

        // Record OpenVPN handshake if this is the 3rd packet in the handshake
        if self.ack_len.is_none() {
            if pdu.dir && self.n_payload_pkts_ctos == 2 && self.n_payload_pkts_stoc == 1 {
                self.ack_len = Some(pdu.length());
            } else if self.n_payload_pkts_ctos > 2 || self.n_payload_pkts_stoc > 1 {
                // Missed the handshake
                self.drop = true;
                return;
            }
        }

        // If packet has same len as ACK, add to bin count
        if let Some(ack_len) = self.ack_len {
            if pdu.length() == ack_len {
                let curr_bin = (self.n_payload_pkts() - 1) / 10;
                if curr_bin < self.bins.len() {
                    self.bins[curr_bin] += 1;
                }
            }
        }
    }

    // Table 2
    pub fn apply_ack_fingerprint(&self) -> bool {
        // 1st bin >= 1, <= 3
        self.bins[0] >= 1 && self.bins[0] > 3 &&
            // 2nd bin >= 2, <= 5
            self.bins[1] >= 2 && self.bins[1] <= 5 &&
            // Bins 3-5: <= 5
            self.bins[2..5].iter().all(|b| *b <= 5) &&
            // Bins 6 to end of analysis: <= 1
            self.bins[5..BIN_ARRAY_SIZE].iter().all(|b| *b <= 1)
    }

    #[inline]
    pub fn n_payload_pkts(&self) -> usize {
        self.n_payload_pkts_ctos + self.n_payload_pkts_stoc
    }
}

use std::collections::HashSet;

#[datatype]
pub struct OpenVPNOpcode {
    /// Expected CRST opcode, inferred by first byte of first client packet
    pub crst: Option<u8>,
    /// Expected SRST opcode, inferred by first byte of first server packet
    pub srst: Option<u8>,

    /// Client or server reset seen after handshake
    pub rst_in_payl: bool,

    /// Bitfield of all observed opcodes
    pub opcodes_tot: HashSet<u8>,

    /// Number of packets with data beyond TCP/UDP header
    pub n_payload_pkts: usize,

    /// Number of malformed packets (len/offset fields in headers incorrect)
    pub malformed: usize,
}

impl OpenVPNOpcode {
    pub fn new(_pdu: &L4Pdu) -> Self {
        OpenVPNOpcode {
            crst: None,
            srst: None,
            opcodes_tot: HashSet::new(),
            n_payload_pkts: 0,
            malformed: 0,
            rst_in_payl: false,
        }
    }

    #[datatype_group("OpenVPNOpcode,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        // Ignore if connection has been reset
        if self.rst_in_payl || self.opcodes_tot.len() > N_OPCODES {
            return;
        }

        // Ignore packets without a (potential) OpenVPN header
        if pdu.length() < openvpn_hdrlen(pdu) {
            return;
        }

        // Record payload packets
        if pdu.length() > 0 {
            self.n_payload_pkts += 1;
        }
        if self.n_payload_pkts > WINDOW_SIZE_ANALYSIS {
            return;
        }

        // Check for and record valid opcode
        if let Ok(payload) = pdu.mbuf_ref().get_data_slice(pdu.offset(), pdu.length()) {
            // We expect the first byte of the header to be an opcode
            let b = payload[0];
            self.opcodes_tot.insert(b);

            // Record values being used for the CRST and SRST opcodes
            if pdu.dir {
                if self.opcodes_tot.len() == 1 {
                    self.crst = Some(b);
                }
            } else {
                if self.opcodes_tot.len() == 2 {
                    self.srst = Some(b);
                }
            }

            // If we've already seen client/server reset and ACKs,
            // make sure we don't see another.
            if let (Some(crst), Some(srst)) = (self.crst, self.srst)
                && (b == crst || b == srst)
                && self.openvpn_hshk_done()
            {
                self.rst_in_payl = true;
            }
        } else {
            // Value stored in offset/length fields are incorrect
            self.malformed += 1;
        }
    }

    /// At least 4 different opcodes needed to
    /// complete handshake (Algorithm 1)
    pub fn openvpn_hshk_done(&self) -> bool {
        self.opcodes_tot.len() >= 4 && self.crst.is_some() && self.srst.is_some()
    }

    /// Apply opcode fingerprinting algorithm (Algorithm 1)
    pub fn apply_opcode_fingerprint(&self) -> bool {
        self.openvpn_hshk_done() && self.opcodes_tot.len() <= N_OPCODES
    }
}

use std::sync::atomic::{AtomicUsize, Ordering};

lazy_static::lazy_static! {
    static ref CHECKED: AtomicUsize = AtomicUsize::new(0);

    static ref FLAGGED_ANY: AtomicUsize = AtomicUsize::new(0);
    static ref FLAGGED_ACK: AtomicUsize = AtomicUsize::new(0);
    static ref FLAGGED_OPS: AtomicUsize = AtomicUsize::new(0);

    static ref RAW_OPCODES: AtomicUsize = AtomicUsize::new(0);
}

/// S8 in original paper - recorded TCP and UDP flows
#[callback("tcp or udp,level=L4InPayload")]
pub fn callback(opcodes: &OpenVPNOpcode, acks: &OpenVPNAcks) -> bool {
    // Reset
    if opcodes.rst_in_payl {
        return false;
    }

    // Keep receiving data
    if acks.n_payload_pkts() < *N_REQ_PKTS {
        return true;
    }

    // Time to fingerprint!
    CHECKED.fetch_add(1, Ordering::Relaxed);
    let op_id = opcodes.apply_opcode_fingerprint();
    let ack_id = acks.apply_ack_fingerprint();
    if op_id || ack_id {
        FLAGGED_ANY.fetch_add(1, Ordering::Relaxed);
    }
    if op_id {
        FLAGGED_OPS.fetch_add(1, Ordering::Relaxed);
        if opcodes.opcodes_tot.iter().all(|o| OPCODES.contains(&o))
            && opcodes.crst.unwrap() == CRST_OPCODE
            && opcodes.srst.unwrap() == SRST_OPCODE
        {
            RAW_OPCODES.fetch_add(1, Ordering::Relaxed);
        }
    }
    if ack_id {
        FLAGGED_ACK.fetch_add(1, Ordering::Relaxed);
    }

    false
}

use iris_core::protocols::packet::{tcp::TCP_PROTOCOL, udp::UDP_PROTOCOL};

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

pub fn print() {
    println!(
        "Done. Results: {} checked, {} flagged total.
        Flagged: {} ack fingerprint, {} opcode fingerprint.
        Of opcode fingerprint, {} raw opcodes",
        CHECKED.load(Ordering::Relaxed),
        FLAGGED_ANY.load(Ordering::Relaxed),
        FLAGGED_ACK.load(Ordering::Relaxed),
        FLAGGED_OPS.load(Ordering::Relaxed),
        RAW_OPCODES.load(Ordering::Relaxed)
    );
}
