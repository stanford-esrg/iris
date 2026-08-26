//! A streaming filter that heuristically accepts connections that look like
//! Zoom: on a UDP port in [`ZOOM_PORT_RANGE`], with initial packets whose
//! first byte matches one of Zoom's observed payload-type markers.

#[allow(unused_imports)]
use iris_compiler::{filter, filter_fn};
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::subscription::{FilterResult, StreamingFilter};
use iris_core::L4Pdu;

/// Number of payload-bearing packets inspected before making a decision.
pub const MAYBE_ZOOM_WINDOW: usize = 30;
/// Fraction of the first [`MAYBE_ZOOM_WINDOW`] payload-bearing packets that
/// must look like Zoom for the connection to be accepted.
pub const MAYBE_ZOOM_MIN_FRACTION: f64 = 0.95;
/// Minimum payload-bearing packets needed to judge a connection that ended
/// before [`MAYBE_ZOOM_WINDOW`] was reached.
pub const MAYBE_ZOOM_MIN_PKTS: usize = MAYBE_ZOOM_WINDOW;
/// UDP port range Zoom traffic is expected on.
pub const ZOOM_PORT_RANGE: std::ops::RangeInclusive<u16> = 8801..=8810;
/// First-byte values that mark a Zoom payload.
pub const ZOOM_FIRST_BYTES: [u8; 4] = [0x03, 0x04, 0x05, 0x07];

/// Check that the first byte matches one of [`ZOOM_FIRST_BYTES`].
#[inline]
fn is_zoom_payload(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(b) if ZOOM_FIRST_BYTES.contains(b))
}

/// Number of matching payloads required within a full window of
/// [`MAYBE_ZOOM_WINDOW`] packets to meet [`MAYBE_ZOOM_MIN_FRACTION`].
#[inline]
fn required_matches() -> usize {
    (MAYBE_ZOOM_WINDOW as f64 * MAYBE_ZOOM_MIN_FRACTION).ceil() as usize
}

/// Accepts a connection once at least [`MAYBE_ZOOM_MIN_FRACTION`] of its
/// first [`MAYBE_ZOOM_WINDOW`] payload-bearing packets (UDP, port in
/// [`ZOOM_PORT_RANGE`]) start with one of [`ZOOM_FIRST_BYTES`]. Non-UDP or
/// non-Zoom-port connections are dropped immediately.
#[cfg_attr(not(feature = "skip_expand"), filter)]
#[derive(Debug)]
pub struct MaybeZoom {
    /// Payload-bearing packets inspected so far.
    seen: usize,
    /// Of those, how many matched a Zoom first-byte marker.
    matched: usize,
}

impl StreamingFilter for MaybeZoom {
    fn new(_first_packet: &L4Pdu) -> Self {
        Self {
            seen: 0,
            matched: 0,
        }
    }

    fn clear(&mut self) {
        self.seen = 0;
        self.matched = 0;
    }
}

impl MaybeZoom {
    /// Updates counts from one payload
    fn record(&mut self, data: &[u8]) {
        self.seen += 1;
        if is_zoom_payload(data) {
            self.matched += 1;
        }
    }

    /// Resolves the current counts to a `FilterResult`
    fn decide(&self) -> FilterResult {
        let required = required_matches();
        if self.matched >= required {
            return FilterResult::Accept;
        }
        if self.seen >= MAYBE_ZOOM_WINDOW {
            // Window exhausted
            return FilterResult::Drop;
        }
        // Impossible to reach required number of matches
        let remaining = MAYBE_ZOOM_WINDOW - self.seen;
        if self.matched + remaining < required {
            return FilterResult::Drop;
        }
        // Not enough evidence yet
        FilterResult::Continue
    }

    #[cfg_attr(not(feature = "skip_expand"), filter_fn("MaybeZoom,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) -> FilterResult {
        // Drop traffic not on a UDP port in ZOOM_PORT_RANGE
        if pdu.ctxt.proto != UDP_PROTOCOL
            || (!ZOOM_PORT_RANGE.contains(&pdu.ctxt.src.port())
                && !ZOOM_PORT_RANGE.contains(&pdu.ctxt.dst.port()))
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
        filter_fn("MaybeZoom,level=L4Terminated")
    )]
    pub fn terminated(&self) -> FilterResult {
        if self.seen >= MAYBE_ZOOM_MIN_PKTS
            && self.matched as f64 >= self.seen as f64 * MAYBE_ZOOM_MIN_FRACTION
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
    fn zoom_payload_bit_pattern() {
        assert!(is_zoom_payload(&[0x03, 0x00]));
        assert!(is_zoom_payload(&[0x04]));
        assert!(is_zoom_payload(&[0x05]));
        assert!(is_zoom_payload(&[0x07]));
        assert!(!is_zoom_payload(&[0x00]));
        assert!(!is_zoom_payload(&[0x06]));
        assert!(!is_zoom_payload(&[]));
    }

    #[test]
    fn required_matches_matches_configured_threshold() {
        // 30 * 0.95 = 28.5, so 29 of 30 -- tolerates exactly one stray packet.
        assert_eq!(required_matches(), 29);
    }

    #[test]
    fn terminated_drops_flows_below_the_evidence_floor() {
        let mut f = MaybeZoom::new_for_test();
        for b in [0x03, 0x04]
            .into_iter()
            .cycle()
            .take(MAYBE_ZOOM_MIN_PKTS - 1)
        {
            f.record(&[b]);
        }
        assert!(matches!(f.terminated(), FilterResult::Drop));

        let mut f = MaybeZoom::new_for_test();
        for b in [0x03, 0x04].into_iter().cycle().take(MAYBE_ZOOM_MIN_PKTS) {
            f.record(&[b]);
        }
        assert!(matches!(f.terminated(), FilterResult::Accept));
    }

    #[test]
    fn terminated_applies_fraction_to_observed_packets() {
        let mut f = MaybeZoom::new_for_test();
        for _ in 0..29 {
            f.record(&[0x03]);
        }
        for _ in 0..1 {
            f.record(&[0x00]); // not a Zoom marker
        }
        // 30 seen, 29 matched -- 97% >= 95%
        assert_eq!(f.seen, 30);
        assert!(matches!(f.terminated(), FilterResult::Accept));

        let mut f = MaybeZoom::new_for_test();
        for _ in 0..27 {
            f.record(&[0x03]);
        }
        for _ in 0..3 {
            f.record(&[0x00]);
        }
        // 30 seen, 27 matched -- 90% < 95%
        assert!(matches!(f.terminated(), FilterResult::Drop));
    }

    #[test]
    fn decide_drops_once_window_exhausted_below_threshold() {
        let mut f = MaybeZoom::new_for_test();
        let mut result = FilterResult::Continue;
        for i in 0..MAYBE_ZOOM_WINDOW {
            if i < 9 {
                f.record(&[0x03]);
            } else {
                f.record(&[0x00]);
            }
            result = f.decide();
        }
        assert!(matches!(result, FilterResult::Drop));
    }

    #[test]
    fn decide_accepts_once_threshold_reached() {
        let mut f = MaybeZoom::new_for_test();
        for _ in 0..(required_matches() - 1) {
            f.record(&[0x04]);
        }
        assert!(matches!(f.decide(), FilterResult::Continue));
        f.record(&[0x05]);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    impl MaybeZoom {
        fn new_for_test() -> Self {
            Self {
                seen: 0,
                matched: 0,
            }
        }
    }
}
