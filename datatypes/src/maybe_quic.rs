//! A streaming filter that heuristically accepts connections that look like
//! QUIC: on an expected port, not clearly another protocol, and initial
//! packets with (potential) QUIC short headers.
//!
//! Per RFC 9000, the first byte of a QUIC short header starts with bits
//! `01`: header form 0, fixed bit 1. Header protection (Section 5.4.1) masks
//! only the low five bits of that byte, so the top two are directly
//! observable and the low five are pseudorandom per packet -- a genuine
//! 32-value uniform source, which the entropy check below relies on.
//!
//! Three shapes count as evidence of QUIC (see [`Shape`]):
//!
//! - **Short header** -- `01` in the top two bits.
//! - **Long header** -- high bit set, a version Iris recognizes, and not
//!   Version Negotiation (`0x00000000`, which is no evidence the connection
//!   will carry a 1-RTT packet, and a shape length- and ID-prefixed binary
//!   formats hit by accident). Meant to capture connections observed
//!   mid-handshake and coalesced datagrams.
//! - **Greased short header** -- an endpoint whose peer advertised
//!   `grease_quic_bit` may set the fixed bit to any value on its 1-RTT
//!   packets (RFC 9287), so roughly half of a greasing endpoint's packets
//!   have it clear. Credited only once the connection has shown at least one
//!   unambiguous QUIC packet, and only when the datagram is large enough to
//!   hold a 1-RTT packet.
//!
//! For a datagram at least [`MIN_1RTT_DATAGRAM_LEN`] bytes, the short-header
//! and greased shapes together cover every value with the high bit clear --
//! the fixed bit only sorts a packet into one bucket or the other, and both
//! count toward acceptance. What actually filters non-QUIC traffic is:
//! requiring at least one unambiguous packet before anything is credited;
//! requiring [`MAYBE_QUIC_MIN_DISTINCT_LOW5`] distinct low-5-bit values
//! across the matched packets -- or one recognized long header in place of
//! that, since a 32-bit version match is stronger on its own -- which is
//! nearly free against traffic with a uniformly random first byte and
//! rejects protocols that pin their low bits (TURN ChannelData, uTP,
//! OpenVPN); and the window, fraction, and packet floor below, which set the
//! false-positive rate against that random-looking traffic directly.
//!
//! Greased packets are counted toward the entropy check: RFC 9287 greasing
//! flips only the fixed bit, never the low five, so a greased packet carries
//! the same per-packet entropy as any other 1-RTT packet. Masking to five
//! bits is what keeps that safe -- a TURN relay mixing `0x40`/`0x41`
//! ChannelData with `0x00`/`0x01` STUN collapses to two distinct low-5
//! values either way, still short of the gate.

#[allow(unused_imports)]
use iris_compiler::{filter, filter_fn};
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::protocols::stream::quic::is_quic_version;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::{FilterResult, StreamingFilter};
use iris_core::L4Pdu;

/// Number of payload-bearing packets inspected before making a decision.
pub const MAYBE_QUIC_WINDOW: usize = 12;
/// Fraction of the first [`MAYBE_QUIC_WINDOW`] payload-bearing packets that
/// must look like QUIC headers for the connection to be accepted.
/// Mid-stream QUIC is very nearly all short headers, so this is set high.
/// The slack tolerates one stray packet.
pub const MAYBE_QUIC_MIN_FRACTION: f64 = 0.9;
/// Minimum payload-bearing packets needed to judge a connection that ended
/// before [`MAYBE_QUIC_WINDOW`] was reached. Shorter connections carry too
/// little evidence to classify and are dropped.
///
/// This is somewhat arbitrarily chosen, and it will drop some genuine
/// QUIC traffic. This has a 1/170 chance of matching random-looking traffic,
/// but will miss some short QUIC connections.
pub const MAYBE_QUIC_MIN_PKTS: usize = 11;
/// 443 (HTTP/3), 853 (DNS-over-QUIC, RFC 9250), 4433 (QUIC interop/test port), 8
/// 443 (alt HTTPS/HTTP-3). A connection on any other port is dropped without inspection.
pub const QUIC_PORTS: [u16; 4] = [443, 853, 4433, 8443];
/// Smallest datagram that can carry a 1-RTT packet: one header byte, a
/// zero-length destination connection ID, and the four packet-number bytes plus
/// 16-byte sample that RFC 9000 Section 5.4.2 requires header protection to be
/// able to sample. Used to keep short non-QUIC datagrams out of the greased
/// [`Shape::GreasedShortHeader`] bucket, where the fixed bit is no help.
pub const MIN_1RTT_DATAGRAM_LEN: usize = 21;
/// Distinct values of a matched packet's low five header bits (`first &
/// 0x1f`) required before those packets are credited -- see
/// [`MaybeQuic::header_entropy_ok`]. Header protection (RFC 9000 Section
/// 5.4.1) makes those bits pseudorandom per packet.
/// This exists to reject protocols that pin their low bits.
/// Five is the minimum to avoid matching on OpenVPN and TURN.
pub const MAYBE_QUIC_MIN_DISTINCT_LOW5: usize = 5;

/// Number of matching packets required within a full window of
/// [`MAYBE_QUIC_WINDOW`] packets to meet [`MAYBE_QUIC_MIN_FRACTION`], i.e.
/// `ceil(MAYBE_QUIC_WINDOW * MAYBE_QUIC_MIN_FRACTION)`.
pub const MAYBE_QUIC_REQUIRED_MATCHES: usize = {
    let exact = MAYBE_QUIC_WINDOW as f64 * MAYBE_QUIC_MIN_FRACTION;
    let truncated = exact as usize;
    if (truncated as f64) < exact {
        truncated + 1
    } else {
        truncated
    }
};

/// How a datagram's first byte -- plus, for the shapes where the QUIC
/// invariants pin a version field or a minimum size, its length -- classifies
/// against the QUIC packet headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Short header with the fixed bit set: `01` in the top two bits.
    ShortHeader,
    /// Long header carrying a version Iris recognizes.
    LongHeader,
    /// Short *form* with the fixed bit cleared, large enough to be a 1-RTT
    /// packet. Possible RFC 9287 greased packet. Only useful in a
    /// connection that has also shown a [`Shape::ShortHeader`] or
    /// [`Shape::LongHeader`] packet.
    GreasedShortHeader,
    /// Nothing that looks like QUIC.
    Other,
}

/// Classifies one datagram's payload by its first byte and length.
#[inline]
fn classify(payload: &[u8]) -> Shape {
    let Some(&first) = payload.first() else {
        return Shape::Other;
    };
    if first & 0x80 != 0 {
        // Long header: bytes 1..5 are version
        if payload.len() < 5 {
            return Shape::Other;
        }
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        // Version 0 is Version Negotiation, but "high bit set
        // followed by four zero bytes" is a pattern that can easily be hit accidentally.
        if version != 0 && is_quic_version(version) {
            Shape::LongHeader
        } else {
            Shape::Other
        }
    } else if first & 0x40 != 0 {
        Shape::ShortHeader
    } else if payload.len() >= MIN_1RTT_DATAGRAM_LEN {
        // First bit clear, long enough to be 1-RTT packet
        Shape::GreasedShortHeader
    } else {
        Shape::Other
    }
}

/// Accepts a connection once at least [`MAYBE_QUIC_MIN_FRACTION`] of its
/// first [`MAYBE_QUIC_WINDOW`] payload-bearing packets (UDP, on one of
/// [`QUIC_PORTS`]) look like QUIC packet headers, and those matches carry
/// enough header entropy -- see [`MaybeQuic::header_entropy_ok`]. Non-UDP or
/// non-QUIC-port connections are dropped immediately.
#[cfg_attr(not(feature = "skip_expand"), filter)]
#[derive(Debug)]
pub struct MaybeQuic {
    /// Payload-bearing packets inspected so far.
    seen: usize,
    /// Of those, how many were unambiguously QUIC-shaped: a short header with
    /// the fixed bit set, or a long header with a recognized version.
    quic_like: usize,
    /// Of those, how many were fixed-bit-clear short-form datagrams big enough
    /// to be greased 1-RTT packets. Credited only if `quic_like` is nonzero.
    greased: usize,
    /// Bit `v` is set once some short-form matched packet (`ShortHeader` or
    /// `GreasedShortHeader`) had `first & 0x1f == v`. RFC 9287 greasing never
    /// touches these bits, so greased packets contribute here even before
    /// `quic_like` is nonzero -- see [`MaybeQuic::header_entropy_ok`].
    low5_seen: u32,
    /// True once a `LongHeader` packet has been seen. A 32-bit version match
    /// is stronger evidence than the entropy check, so it satisfies that
    /// check outright.
    saw_long_header: bool,
}

impl StreamingFilter for MaybeQuic {
    fn new(_first_packet: &L4Pdu) -> Self {
        Self {
            seen: 0,
            quic_like: 0,
            greased: 0,
            low5_seen: 0,
            saw_long_header: false,
        }
    }

    fn clear(&mut self) {
        self.seen = 0;
        self.quic_like = 0;
        self.greased = 0;
        self.low5_seen = 0;
        self.saw_long_header = false;
    }
}

impl MaybeQuic {
    /// Updates counts from one payload
    fn record(&mut self, data: &[u8]) {
        self.seen += 1;
        match classify(data) {
            Shape::ShortHeader => {
                self.quic_like += 1;
                self.low5_seen |= 1 << (data[0] & 0x1f);
            }
            Shape::LongHeader => {
                self.quic_like += 1;
                self.saw_long_header = true;
            }
            Shape::GreasedShortHeader => {
                self.greased += 1;
                self.low5_seen |= 1 << (data[0] & 0x1f);
            }
            Shape::Other => {}
        }
    }

    /// Packets credited as QUIC. Greased packets count only once the connection
    /// has independently shown a real QUIC packet -- see
    /// [`Shape::GreasedShortHeader`].
    #[inline]
    fn matches(&self) -> usize {
        if self.quic_like == 0 {
            0
        } else {
            self.quic_like + self.greased
        }
    }

    /// Upper bound on [`MaybeQuic::matches`] if the rest of the connection
    /// cooperates.
    #[inline]
    fn reachable_matches(&self) -> usize {
        self.quic_like + self.greased
    }

    /// True once the matched packets carry enough header entropy to trust:
    /// [`MAYBE_QUIC_MIN_DISTINCT_LOW5`] distinct low-5-bit values, or a
    /// recognized long header on its own.
    #[inline]
    fn header_entropy_ok(&self) -> bool {
        self.saw_long_header || self.low5_seen.count_ones() as usize >= MAYBE_QUIC_MIN_DISTINCT_LOW5
    }

    /// Resolves the current counts to a `FilterResult`
    fn decide(&self) -> FilterResult {
        if self.matches() >= MAYBE_QUIC_REQUIRED_MATCHES && self.header_entropy_ok() {
            return FilterResult::Accept;
        }
        if self.seen >= MAYBE_QUIC_WINDOW {
            // Window exhausted
            return FilterResult::Drop;
        }
        // Impossible to reach the required number of matches
        let remaining = MAYBE_QUIC_WINDOW - self.seen;
        if self.reachable_matches() + remaining < MAYBE_QUIC_REQUIRED_MATCHES {
            return FilterResult::Drop;
        }
        // Not enough evidence yet
        FilterResult::Continue
    }

    #[cfg_attr(not(feature = "skip_expand"), filter_fn("MaybeQuic,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) -> FilterResult {
        // Drop traffic that isn't UDP on a port QUIC is expected on
        if pdu.ctxt.proto != UDP_PROTOCOL
            || !(QUIC_PORTS.contains(&pdu.ctxt.src.port())
                || QUIC_PORTS.contains(&pdu.ctxt.dst.port()))
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

    /// Vetoes the connection once a parser has identified it, so that
    /// `MaybeQuic` reports only what the parsers missed.
    ///
    /// `SessionProto` resolves at `L7OnDisc`, which is dispatched as soon as
    /// discovery concludes -- on the first packet or two of a connection whose
    /// handshake is visible, and so always before [`MaybeQuic::update`] can
    /// reach [`MAYBE_QUIC_REQUIRED_MATCHES`] and accept. Returning `Drop` here
    /// also deactivates the filter, so `update` stops being called for the rest
    /// of the connection.
    ///
    /// Mid-stream QUIC -- the population this filter exists for -- never gets
    /// here: the `quic` probe answers `Unsure` for a short header and never
    /// concludes, so `L7OnDisc` is not dispatched at all and the heuristic
    /// runs to its own verdict.
    ///
    /// One case still overlaps: a connection whose long-header packet arrives
    /// after the window has already closed on an accept. There is no veto left
    /// to apply at that point, and the accept was made on its own evidence.
    #[cfg_attr(not(feature = "skip_expand"), filter_fn("MaybeQuic,level=L7OnDisc"))]
    pub fn unclaimed(&self, proto: &SessionProto) -> FilterResult {
        match proto {
            // A parser claimed the connection; it is already reported as that
            // protocol, and a heuristic guess on top would double-count it.
            SessionProto::Tls
            | SessionProto::Dns
            | SessionProto::Http
            | SessionProto::Quic
            | SessionProto::Ssh => FilterResult::Drop,
            // Nothing has claimed it: `Probing` while discovery is still
            // running, `Null` once every registered parser has declined.
            SessionProto::Null | SessionProto::Probing => FilterResult::Continue,
            // `ConnParser::protocol` never yields the transport-layer variants
            // -- they exist for the filter AST -- but they are listed rather
            // than wildcarded so that adding an L7 parser is a compile error
            // here instead of a silent hole in the veto.
            SessionProto::Ipv4 | SessionProto::Ipv6 | SessionProto::Tcp | SessionProto::Udp => {
                FilterResult::Continue
            }
        }
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
            && self.header_entropy_ok()
            && self.matches() as f64 >= self.seen as f64 * MAYBE_QUIC_MIN_FRACTION
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

    /// QUIC v1 long header (Initial), first five bytes: form+fixed bits set,
    /// then version `0x00000001`.
    const LONG_HDR_V1: [u8; 5] = [0xc3, 0x00, 0x00, 0x00, 0x01];
    /// The same long header with the fixed bit greased away (RFC 9287).
    const LONG_HDR_V1_GREASED: [u8; 5] = [0x83, 0x00, 0x00, 0x00, 0x01];

    /// A fixed-bit-clear short-form datagram long enough to be a greased
    /// 1-RTT packet.
    fn greased(first: u8) -> [u8; MIN_1RTT_DATAGRAM_LEN] {
        let mut buf = [0u8; MIN_1RTT_DATAGRAM_LEN];
        buf[0] = first;
        buf
    }

    #[test]
    fn short_header_bit_pattern() {
        assert_eq!(classify(&[0x41, 0x00]), Shape::ShortHeader);
        assert_eq!(classify(&[0x40]), Shape::ShortHeader);
        assert_eq!(classify(&[0x7f]), Shape::ShortHeader);
        // Fixed bit clear and too short to be a 1-RTT packet.
        assert_eq!(classify(&[0x00]), Shape::Other);
        // Long header, but no room for a version field.
        assert_eq!(classify(&[0xc0]), Shape::Other);
        assert_eq!(classify(&[0x80]), Shape::Other);
        assert_eq!(classify(&[]), Shape::Other);
    }

    #[test]
    fn long_header_matches_only_on_a_recognized_version() {
        assert_eq!(classify(&LONG_HDR_V1), Shape::LongHeader);
        // The fixed bit may be greased on a long header too; the version
        // carries the decision.
        assert_eq!(classify(&LONG_HDR_V1_GREASED), Shape::LongHeader);
        // QUIC v2 (RFC 9369).
        assert_eq!(classify(&[0xc0, 0x6b, 0x33, 0x43, 0xcf]), Shape::LongHeader);
        // RTP: version 2, and the following four bytes are not a QUIC version.
        assert_eq!(classify(&[0x80, 0x60, 0x12, 0x34, 0x56]), Shape::Other);
    }

    #[test]
    fn version_zero_is_not_evidence_of_quic() {
        // Version Negotiation (RFC 9000 Section 6). `is_quic_version` accepts
        // it for the parser's sake, but a datagram shaped `0x?? 00 00 00 00`
        // is also a pattern length- and ID-prefixed binary formats hit by
        // accident, and it isn't evidence of a 1-RTT-bearing connection.
        assert_eq!(classify(&[0xc0, 0x00, 0x00, 0x00, 0x00]), Shape::Other);
        assert_eq!(classify(&[0x80, 0x00, 0x00, 0x00, 0x00]), Shape::Other);
    }

    #[test]
    fn greased_short_header_needs_room_for_a_1rtt_packet() {
        assert_eq!(classify(&greased(0x08)), Shape::GreasedShortHeader);
        // One byte short of the header-protection sampling minimum.
        assert_eq!(
            classify(&greased(0x08)[..MIN_1RTT_DATAGRAM_LEN - 1]),
            Shape::Other
        );
    }

    #[test]
    fn required_matches_derives_from_the_configured_threshold() {
        // 12 * 0.9 = 10.8, so 11 of 12 -- tolerates exactly one stray packet.
        assert_eq!(MAYBE_QUIC_REQUIRED_MATCHES, 11);
    }

    #[test]
    fn distinct_low5_masks_out_the_header_bits() {
        // 0x40 and 0x60 are different first bytes but the same low-5 value.
        let mut f = MaybeQuic::new_for_test();
        f.record(&[0x40]);
        f.record(&[0x60]);
        assert_eq!(f.low5_seen.count_ones(), 1);
    }

    #[test]
    fn terminated_drops_flows_below_the_evidence_floor() {
        // Five distinct low-5 values, but too few packets to clear the floor.
        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x42, 0x43, 0x44, 0x45]
            .into_iter()
            .cycle()
            .take(MAYBE_QUIC_MIN_PKTS - 1)
        {
            f.record(&[b]);
        }
        assert!(matches!(f.terminated(), FilterResult::Drop));

        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x42, 0x43, 0x44, 0x45]
            .into_iter()
            .cycle()
            .take(MAYBE_QUIC_MIN_PKTS)
        {
            f.record(&[b]);
        }
        assert!(matches!(f.terminated(), FilterResult::Accept));
    }

    #[test]
    fn terminated_applies_fraction_to_observed_packets() {
        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x42, 0x43, 0x44, 0x45] {
            f.record(&[b]);
        }
        for _ in 0..5 {
            f.record(&[0x41]);
        }
        f.record(&[0x00]); // not a short header
                           // 11 seen, 10 matched across five distinct low-5 values -- 91% >= 90%
        assert_eq!(f.seen, 11);
        assert!(matches!(f.terminated(), FilterResult::Accept));

        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x42, 0x43, 0x44, 0x45] {
            f.record(&[b]);
        }
        for _ in 0..4 {
            f.record(&[0x41]);
        }
        for _ in 0..2 {
            f.record(&[0x00]);
        }
        // 11 seen, 9 matched -- 82% < 90%
        assert!(matches!(f.terminated(), FilterResult::Drop));
    }

    #[test]
    fn terminated_rejects_a_low_entropy_first_byte() {
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
    fn decide_accepts_once_header_entropy_is_reached() {
        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x42, 0x43, 0x44] {
            for _ in 0..2 {
                f.record(&[b]);
            }
        }
        for _ in 0..2 {
            f.record(&[0x41]);
        }
        // 10 seen, all matched, but only four distinct low-5 values.
        assert!(matches!(f.decide(), FilterResult::Continue));
        f.record(&[0x45]);
        // 11 seen, 11 matched, five distinct low-5 values.
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn pinned_first_byte_protocols_are_rejected() {
        // uTP: ST_SYN (0x41) sets the fixed bit; ST_DATA (0x01) and ST_STATE
        // (0x21) don't, but their datagrams are large enough for the greased
        // bucket. All three share the same low-5 value (0x01), so the
        // entropy gate rejects the mix even though matches() alone clears
        // the bar.
        let mut f = MaybeQuic::new_for_test();
        for i in 0..MAYBE_QUIC_WINDOW {
            match i % 3 {
                0 => f.record(&[0x41]),
                1 => f.record(&greased(0x01)),
                _ => f.record(&greased(0x21)),
            }
        }
        assert_eq!(f.low5_seen.count_ones(), 1);
        assert!(matches!(f.decide(), FilterResult::Drop));

        // OpenVPN P_DATA_V2 across four key IDs: more distinct low-5 values,
        // but still one short of the threshold.
        let mut f = MaybeQuic::new_for_test();
        for b in [0x48, 0x49, 0x4a, 0x4b]
            .into_iter()
            .cycle()
            .take(MAYBE_QUIC_WINDOW)
        {
            f.record(&[b]);
        }
        assert_eq!(f.low5_seen.count_ones(), 4);
        assert!(matches!(f.decide(), FilterResult::Drop));
    }

    #[test]
    fn turn_channeldata_mixed_with_stun_is_rejected() {
        // TURN ChannelData (0x40, fixed bit set) interleaved with STUN
        // (0x01, top two bits clear, well over the 1-RTT minimum size).
        // Low-5 values collapse to {0x00, 0x01} -- far short of the gate.
        let mut f = MaybeQuic::new_for_test();
        let mut result = FilterResult::Continue;
        for i in 0..MAYBE_QUIC_WINDOW {
            if i % 2 == 0 {
                f.record(&[0x40]);
            } else {
                f.record(&greased(0x01));
            }
            result = f.decide();
        }
        assert_eq!(f.low5_seen.count_ones(), 2);
        assert!(matches!(result, FilterResult::Drop));
    }

    #[test]
    fn long_headers_count_toward_the_threshold() {
        // A capture that starts mid-handshake: the first datagrams are long
        // headers. These used to be scored against the connection, dropping
        // it at the second one. A recognized long header also satisfies the
        // entropy gate outright, so the short headers here don't need to be
        // individually diverse.
        let mut f = MaybeQuic::new_for_test();
        for _ in 0..4 {
            f.record(&LONG_HDR_V1);
            assert!(matches!(f.decide(), FilterResult::Continue));
        }
        for b in [0x41, 0x52, 0x4a, 0x5c, 0x43, 0x50, 0x4f] {
            f.record(&[b]);
        }
        // 11 of 11 matched.
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn a_long_header_satisfies_the_entropy_gate_on_its_own() {
        // Only one distinct low-5 value among the short-form packets, but a
        // recognized long header is independently strong enough evidence.
        let mut f = MaybeQuic::new_for_test();
        f.record(&LONG_HDR_V1);
        for _ in 0..10 {
            f.record(&[0x41]);
        }
        // 11 seen, 11 matched (1 long header + 10 identical short headers).
        assert_eq!(f.matches(), 11);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn a_stray_long_header_mid_stream_is_not_held_against_the_connection() {
        // Handshake packets are still interleaved after 1-RTT traffic begins;
        // two of them anywhere in the window used to be fatal.
        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x52] {
            f.record(&[b]);
        }
        f.record(&LONG_HDR_V1);
        f.record(&[0x4a]);
        f.record(&LONG_HDR_V1);
        assert!(matches!(f.decide(), FilterResult::Continue));
        for b in [0x5c, 0x43, 0x50, 0x4f, 0x48, 0x5e] {
            f.record(&[b]);
        }
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn greased_packets_count_once_the_connection_shows_real_quic() {
        let mut f = MaybeQuic::new_for_test();
        // Alternating greased and fixed-bit-set packets, as a connection with
        // one greasing endpoint looks.
        for b in [0x41, 0x52, 0x4a, 0x5c, 0x43, 0x50] {
            f.record(&greased(0x08));
            f.record(&[b]);
        }
        // 12 seen: 6 unambiguous, 6 greased and credited.
        assert_eq!(f.seen, 12);
        assert_eq!(f.matches(), 12);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn greased_packets_contribute_header_entropy() {
        // A single fixed-bit-set packet, then several distinct greased ones
        // that clear the entropy gate largely on their own.
        let mut f = MaybeQuic::new_for_test();
        f.record(&[0x41]);
        for b in [0x02, 0x03, 0x04, 0x05] {
            f.record(&greased(b));
        }
        for _ in 0..6 {
            f.record(&[0x41]);
        }
        // 11 seen: 7 unambiguous, 4 greased -- 11 matched, five distinct
        // low-5 values contributed mostly by the greased packets.
        assert_eq!(f.seen, 11);
        assert_eq!(f.matches(), 11);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn a_genuine_two_way_greasing_connection_is_accepted() {
        // Both endpoints grease per-packet: roughly half the datagrams clear
        // the fixed bit, but their low-5 bits still vary like real header
        // protection.
        let mut f = MaybeQuic::new_for_test();
        for k in 0..6u8 {
            f.record(&[0x40 | k]);
            f.record(&greased(k));
        }
        // 12 seen: 6 unambiguous, 6 greased, all credited.
        assert_eq!(f.seen, 12);
        assert_eq!(f.matches(), 12);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn greased_packets_alone_are_not_evidence_of_quic() {
        // STUN pins its top two bits to `00`, and its messages are well over
        // the 1-RTT minimum. Without a real QUIC packet these earn nothing --
        // and they must not satisfy the entropy gate either.
        let mut f = MaybeQuic::new_for_test();
        let mut result = FilterResult::Continue;
        for b in [0x00, 0x01].into_iter().cycle().take(MAYBE_QUIC_WINDOW) {
            f.record(&greased(b));
            result = f.decide();
        }
        assert_eq!(f.greased, MAYBE_QUIC_WINDOW);
        assert_eq!(f.matches(), 0);
        assert!(!f.header_entropy_ok());
        assert!(matches!(result, FilterResult::Drop));
        assert!(matches!(f.terminated(), FilterResult::Drop));
    }

    #[test]
    fn a_greased_opening_does_not_trigger_the_impossibility_drop() {
        // Both of the first two datagrams have the fixed bit clear -- roughly a
        // one-in-four opening for a greasing endpoint. Writing them off would
        // drop the connection here, before any short header arrives.
        let mut f = MaybeQuic::new_for_test();
        f.record(&greased(0x08));
        f.record(&greased(0x08));
        assert!(matches!(f.decide(), FilterResult::Continue));
        for b in [0x41, 0x52, 0x4a, 0x5c, 0x43, 0x50, 0x4f, 0x48, 0x5e] {
            f.record(&[b]);
        }
        // 11 seen, 9 unambiguous + 2 greased.
        assert_eq!(f.matches(), 11);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn a_parser_identifying_the_connection_vetoes_the_heuristic() {
        let f = MaybeQuic::new_for_test();
        // Any parser claiming the connection takes it out of `MaybeQuic`'s
        // population -- not just the `quic` parser.
        for proto in [
            SessionProto::Quic,
            SessionProto::Tls,
            SessionProto::Dns,
            SessionProto::Http,
            SessionProto::Ssh,
        ] {
            assert!(
                matches!(f.unclaimed(&proto), FilterResult::Drop),
                "{:?} should veto",
                proto
            );
        }
        // Unclaimed: discovery still running, or every parser declined.
        for proto in [SessionProto::Probing, SessionProto::Null] {
            assert!(
                matches!(f.unclaimed(&proto), FilterResult::Continue),
                "{:?} should not veto",
                proto
            );
        }
    }

    #[test]
    fn the_veto_leaves_an_already_matching_connection_to_its_own_verdict() {
        // The veto is a `Continue`/`Drop` decision only: it never accepts, and
        // an unclaimed connection carries on accumulating evidence.
        let mut f = MaybeQuic::new_for_test();
        for b in [0x41, 0x42, 0x43, 0x44] {
            for _ in 0..2 {
                f.record(&[b]);
            }
        }
        for _ in 0..2 {
            f.record(&[0x41]);
        }
        assert!(matches!(
            f.unclaimed(&SessionProto::Null),
            FilterResult::Continue
        ));
        f.record(&[0x45]);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn quic_ports_cover_h3_doq_and_the_interop_port() {
        assert!(QUIC_PORTS.contains(&443));
        assert!(QUIC_PORTS.contains(&853));
        assert!(QUIC_PORTS.contains(&4433));
        assert!(QUIC_PORTS.contains(&8443));
        assert!(!QUIC_PORTS.contains(&80));
    }

    impl MaybeQuic {
        fn new_for_test() -> Self {
            Self {
                seen: 0,
                quic_like: 0,
                greased: 0,
                low5_seen: 0,
                saw_long_header: false,
            }
        }
    }
}
