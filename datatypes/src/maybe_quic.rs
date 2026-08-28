//! A streaming filter that heuristically accepts connections that look like
//! QUIC: on an expected port, not clearly another protocol, and initial packets
//! with (potential) QUIC short headers.
//!
//! Per RFC 9000, the first byte of a QUIC short header starts with bits
//! `01`. Long-header packets (Initial, Handshake, 0-RTT, Retry) have both
//! bits set and do not match, but the Iris `quic` parser should pick those up.
//!
//! Three shapes count as evidence of QUIC (see [`Shape`]):
//!
//! - **Short header** -- `01` in the top two bits.
//! - **Long header** -- high bit set *and* a version Iris recognizes.
//!   This is meant to capture QUIC connections observed mid-handshake
//!   and coalesced datagrams.
//! - **Greased short header** -- an endpoint whose peer advertised
//!   `grease_quic_bit` may set the fixed bit to any value on its 1-RTT packets.
//!   Credited only once the connection has shown at least one QUIC packet
//!   and only when the datagram is large enough to hold a 1-RTT packet.
//!
//! This filter requires at least two distinct first-byte values before accepting.
//! This avoids false positives from other protocols that pin their first byte
//! in the same range.

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
pub const MAYBE_QUIC_MIN_PKTS: usize = 6;
/// UDP ports QUIC traffic is expected on: 443 (HTTP/3), 853 (DNS-over-QUIC,
/// RFC 9250), 4433 (the de-facto QUIC interop/test port), and 8443 (alternate
/// HTTPS/HTTP-3). A connection on any other port is dropped without inspection.
pub const QUIC_PORTS: [u16; 4] = [443, 853, 4433, 8443];
/// Smallest datagram that can carry a 1-RTT packet: one header byte, a
/// zero-length destination connection ID, and the four packet-number bytes plus
/// 16-byte sample that RFC 9000 Section 5.4.2 requires header protection to be
/// able to sample. Used to keep short non-QUIC datagrams out of the greased
/// [`Shape::GreasedShortHeader`] bucket, where the fixed bit is no help.
pub const MIN_1RTT_DATAGRAM_LEN: usize = 21;

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
        if is_quic_version(version) {
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
/// [`QUIC_PORTS`]) look like QUIC packet headers, and those matches don't all
/// share a single first-byte value. Non-UDP or non-QUIC-port connections are
/// dropped immediately.
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
    /// First byte of the first `quic_like` packet, to detect a constant value.
    first_byte: Option<u8>,
    /// True once a `quic_like` packet's first byte differs from `first_byte`.
    distinct_seen: bool,
}

impl StreamingFilter for MaybeQuic {
    fn new(_first_packet: &L4Pdu) -> Self {
        Self {
            seen: 0,
            quic_like: 0,
            greased: 0,
            first_byte: None,
            distinct_seen: false,
        }
    }

    fn clear(&mut self) {
        self.seen = 0;
        self.quic_like = 0;
        self.greased = 0;
        self.first_byte = None;
        self.distinct_seen = false;
    }
}

impl MaybeQuic {
    /// Updates counts from one payload
    fn record(&mut self, data: &[u8]) {
        self.seen += 1;
        match classify(data) {
            Shape::ShortHeader | Shape::LongHeader => {
                self.quic_like += 1;
                match self.first_byte {
                    None => self.first_byte = Some(data[0]),
                    Some(b) if b != data[0] => self.distinct_seen = true,
                    _ => {}
                }
            }
            Shape::GreasedShortHeader => self.greased += 1,
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

    /// Resolves the current counts to a `FilterResult`
    fn decide(&self) -> FilterResult {
        if self.matches() >= MAYBE_QUIC_REQUIRED_MATCHES && self.distinct_seen {
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
            && self.distinct_seen
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
        for _ in 0..(MAYBE_QUIC_REQUIRED_MATCHES - 1) {
            f.record(&[0x41]);
        }
        assert!(matches!(f.decide(), FilterResult::Continue));
        f.record(&[0x52]);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn long_headers_count_toward_the_threshold() {
        // A capture that starts mid-handshake: the first datagrams are long
        // headers. These used to be scored against the connection, dropping it
        // at the second one.
        let mut f = MaybeQuic::new_for_test();
        for _ in 0..4 {
            f.record(&LONG_HDR_V1);
            assert!(matches!(f.decide(), FilterResult::Continue));
        }
        for b in [0x41, 0x52, 0x4a, 0x5c, 0x43, 0x50, 0x4f] {
            f.record(&[b]);
        }
        // 11 of 11 matched, several distinct first bytes.
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
    fn greased_packets_alone_are_not_evidence_of_quic() {
        // STUN pins its top two bits to `00`, and its messages are well over
        // the 1-RTT minimum. Without a real QUIC packet these earn nothing --
        // and they must not satisfy the distinct-byte test either.
        let mut f = MaybeQuic::new_for_test();
        let mut result = FilterResult::Continue;
        for b in [0x00, 0x01].into_iter().cycle().take(MAYBE_QUIC_WINDOW) {
            f.record(&greased(b));
            result = f.decide();
        }
        assert_eq!(f.greased, MAYBE_QUIC_WINDOW);
        assert_eq!(f.matches(), 0);
        assert!(!f.distinct_seen);
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
        for _ in 0..(MAYBE_QUIC_REQUIRED_MATCHES - 1) {
            f.record(&[0x41]);
        }
        assert!(matches!(
            f.unclaimed(&SessionProto::Null),
            FilterResult::Continue
        ));
        f.record(&[0x52]);
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
                first_byte: None,
                distinct_seen: false,
            }
        }
    }
}
