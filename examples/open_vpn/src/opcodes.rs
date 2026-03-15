use iris_compiler::*;
use iris_core::L4Pdu;
use std::collections::HashSet;

use crate::utils::{N_OPCODES, WINDOW_SIZE_ANALYSIS, openvpn_hdrlen};

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
            } else if self.opcodes_tot.len() == 2 {
                self.srst = Some(b);
            }

            // If we've already seen client/server reset and ACKs,
            // make sure we don't see another.
            if let (Some(crst), Some(srst)) = (self.crst, self.srst) {
                if (b == crst || b == srst) && self.openvpn_hshk_done() {
                    self.rst_in_payl = true;
                }
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
