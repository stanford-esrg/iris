use iris_compiler::*;
use iris_core::L4Pdu;

use crate::utils::{WINDOW_SIZE_ACK, WINDOW_SIZE_ANALYSIS, openvpn_hdrlen};

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
