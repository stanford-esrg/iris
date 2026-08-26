//! A streaming filter that heuristically accepts connections that look like
//! QUIC: on UDP port 443, not clearly another protocol, and initial packets
//! with (potential) QUIC short headers.
//!
//! Per RFC 9000, the first byte of a QUIC short header starts with bits
//! `01`. Long-header packets (Initial, Handshake, 0-RTT, Retry) have both
//! bits set and do not match, but the Iris `quic` parser should pick those up.
//!
//! This filter only inspects UDP traffic on [`QUIC_PORT`] (443).
//!
//! This filter requires at least two distinct first-byte values among the
//! matched packets before accepting. This avoids false positives
//! from other protocols that pin their first byte in the same `0x40..=0x7f`
//! range (e.g., some BitTorrent, OpenVPN, and IPv4-in-UDP packets).

#[allow(unused_imports)]
use iris_compiler::{filter, filter_fn};
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::subscription::{FilterResult, StreamingFilter};
use iris_core::L4Pdu;

/// Number of payload-bearing packets inspected before making a decision.
pub const MAYBE_QUIC_WINDOW: usize = 12;
/// Fraction of the first [`MAYBE_QUIC_WINDOW`] payload-bearing packets that
/// must look like QUIC short headers for the connection to be accepted.
/// Mid-stream QUIC is very nearly all short headers, so this is set high.
/// The slack tolerates one stray packet.
pub const MAYBE_QUIC_MIN_FRACTION: f64 = 0.9;
/// Minimum payload-bearing packets needed to judge a connection that ended
/// before [`MAYBE_QUIC_WINDOW`] was reached. Shorter connections carry too
/// little evidence to classify and are dropped.
pub const MAYBE_QUIC_MIN_PKTS: usize = 6;
/// UDP port QUIC traffic is expected on.
pub const QUIC_PORT: u16 = 443;

/// Check that first byte starts with `01`
#[inline]
fn is_quic_short_header(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(b) if b & 0xc0 == 0x40)
}

/// Number of short headers required within a full window of
/// [`MAYBE_QUIC_WINDOW`] packets to meet [`MAYBE_QUIC_MIN_FRACTION`].
#[inline]
fn required_short_hdrs() -> usize {
    (MAYBE_QUIC_WINDOW as f64 * MAYBE_QUIC_MIN_FRACTION).ceil() as usize
}

/// Accepts a connection once at least [`MAYBE_QUIC_MIN_FRACTION`] of its
/// first [`MAYBE_QUIC_WINDOW`] payload-bearing packets (UDP, port
/// [`QUIC_PORT`]) start with what looks like a QUIC short header, and
/// those matches don't all share a single first-byte value. Non-UDP or
/// non-QUIC-port connections are dropped immediately.
#[cfg_attr(not(feature = "skip_expand"), filter)]
#[derive(Debug)]
pub struct MaybeQuic {
    /// Payload-bearing packets inspected so far.
    seen: usize,
    /// Of those, how many started with a QUIC short header.
    short_hdrs: usize,
    /// First byte of the first matched packet, to detect a constant value.
    first_byte: Option<u8>,
    /// True once a matched packet's first byte differs from `first_byte`.
    distinct_seen: bool,
}

impl StreamingFilter for MaybeQuic {
    fn new(_first_packet: &L4Pdu) -> Self {
        Self {
            seen: 0,
            short_hdrs: 0,
            first_byte: None,
            distinct_seen: false,
        }
    }

    fn clear(&mut self) {
        self.seen = 0;
        self.short_hdrs = 0;
        self.first_byte = None;
        self.distinct_seen = false;
    }
}

impl MaybeQuic {
    /// Updates counts from one payload
    fn record(&mut self, data: &[u8]) {
        self.seen += 1;
        if !is_quic_short_header(data) {
            return;
        }
        self.short_hdrs += 1;
        if !self.distinct_seen {
            match self.first_byte {
                None => self.first_byte = Some(data[0]),
                Some(b) if b != data[0] => self.distinct_seen = true,
                _ => {}
            }
        }
    }

    /// Resolves the current counts to a `FilterResult`
    fn decide(&self) -> FilterResult {
        let required = required_short_hdrs();
        if self.short_hdrs >= required && self.distinct_seen {
            return FilterResult::Accept;
        }
        if self.seen >= MAYBE_QUIC_WINDOW {
            // Window exhausted
            return FilterResult::Drop;
        }
        // Impossible to reach required number of short headers
        let remaining = MAYBE_QUIC_WINDOW - self.seen;
        if self.short_hdrs + remaining < required {
            return FilterResult::Drop;
        }
        // Not enough evidence yet
        FilterResult::Continue
    }

    #[cfg_attr(not(feature = "skip_expand"), filter_fn("MaybeQuic,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) -> FilterResult {
        // Drop traffic not on UDP port 443
        if pdu.ctxt.proto != UDP_PROTOCOL
            || (pdu.ctxt.src.port() != QUIC_PORT && pdu.ctxt.dst.port() != QUIC_PORT)
        {
            return FilterResult::Drop;
        }
        // Skip packets with no payload
        if pdu.length() == 0 {
            return FilterResult::Continue;
        }
        // Extract data
        if let Ok(data) = pdu.mbuf_ref().get_data_slice(pdu.offset(), pdu.length()) {
            self.record(data);
        }
        self.decide()
    }

    /// Reached only if the connection terminated before the window filled.
    /// The fraction is applied to the packets actually observed, but only
    /// once there are enough of them to be meaningful.
    #[cfg_attr(
        not(feature = "skip_expand"),
        filter_fn("MaybeQuic,level=L4Terminated")
    )]
    pub fn terminated(&self) -> FilterResult {
        if self.seen >= MAYBE_QUIC_MIN_PKTS
            && self.distinct_seen
            && self.short_hdrs as f64 >= self.seen as f64 * MAYBE_QUIC_MIN_FRACTION
        {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_header_bit_pattern() {
        assert!(is_quic_short_header(&[0x41, 0x00]));
        assert!(is_quic_short_header(&[0x40]));
        assert!(!is_quic_short_header(&[0x00])); // fixed bit clear
        assert!(!is_quic_short_header(&[0xc0])); // long header (both bits set)
        assert!(!is_quic_short_header(&[0x80])); // long header
        assert!(!is_quic_short_header(&[]));
    }

    #[test]
    fn required_short_hdrs_matches_configured_threshold() {
        // 12 * 0.9 = 10.8, so 11 of 12 -- tolerates exactly one stray packet.
        assert_eq!(required_short_hdrs(), 11);
    }

    #[test]
    fn terminated_drops_flows_below_the_evidence_floor() {
        // Every packet matched, and two distinct bytes -- but too few
        // packets to classify.
        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x42]
            .into_iter()
            .cycle()
            .take(MAYBE_QUIC_MIN_PKTS - 1)
        {
            f.record(&[b]);
        }
        assert!(matches!(f.terminated(), FilterResult::Drop));

        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x42].into_iter().cycle().take(MAYBE_QUIC_MIN_PKTS) {
            f.record(&[b]);
        }
        assert!(matches!(f.terminated(), FilterResult::Accept));
    }

    #[test]
    fn terminated_applies_fraction_to_observed_packets() {
        let mut f = MaybeQuic::new_for_test();
        for _ in 0..10 {
            f.record(&[0x41]);
        }
        f.record(&[0x42]); // second distinct byte
        for _ in 0..1 {
            f.record(&[0x00]); // not a short header
        }
        // 12 seen, 11 matched across two distinct bytes -- 92% >= 90%
        assert_eq!(f.seen, 12);
        assert!(matches!(f.terminated(), FilterResult::Accept));

        let mut f = MaybeQuic::new_for_test();
        for _ in 0..9 {
            f.record(&[0x41]);
        }
        f.record(&[0x42]);
        for _ in 0..2 {
            f.record(&[0x00]);
        }
        // 12 seen, 10 matched -- 83% < 90%
        assert!(matches!(f.terminated(), FilterResult::Drop));
    }

    #[test]
    fn terminated_rejects_a_constant_first_byte() {
        // Every packet matches and the fraction is 100%, but it's the same
        // byte throughout -- the OpenVPN/TURN/bencode/GTP false-positive
        // shape this check exists to catch.
        let mut f = MaybeQuic::new_for_test();
        for _ in 0..MAYBE_QUIC_WINDOW {
            f.record(&[0x48]); // e.g. OpenVPN P_DATA_V2, key_id 0
        }
        assert!(matches!(f.terminated(), FilterResult::Drop));
    }

    #[test]
    fn decide_drops_once_window_exhausted_on_constant_byte() {
        let mut f = MaybeQuic::new_for_test();
        let mut result = FilterResult::Continue;
        for _ in 0..MAYBE_QUIC_WINDOW {
            f.record(&[0x64]); // e.g. bencoded BitTorrent DHT message
            result = f.decide();
        }
        assert!(matches!(result, FilterResult::Drop));
    }

    #[test]
    fn decide_accepts_once_a_second_distinct_byte_appears() {
        let mut f = MaybeQuic::new_for_test();
        for _ in 0..(required_short_hdrs() - 1) {
            f.record(&[0x41]);
        }
        assert!(matches!(f.decide(), FilterResult::Continue));
        f.record(&[0x52]);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    impl MaybeQuic {
        fn new_for_test() -> Self {
            Self {
                seen: 0,
                short_hdrs: 0,
                first_byte: None,
                distinct_seen: false,
            }
        }
    }
}
