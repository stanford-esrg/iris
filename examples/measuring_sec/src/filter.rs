use iris_compiler::filter;
use iris_core::FiveTuple;
use iris_core::protocols::stream::{Session, SessionData};
use iris_core::subscription::FilterResult;
use lazy_static::lazy_static;

// TODO apply this per packet
#[filter("level=L4FirstPacket")]
pub fn drop_high_vol_conn(ft: &FiveTuple) -> FilterResult {
    let dst = ft.resp.port();
    if PORTS.contains(&dst) {
        return FilterResult::Drop;
    }
    FilterResult::Accept
}

#[filter("level=L7EndHdrs")]
pub fn drop_high_vol_sess(session: &Session) -> FilterResult {
    if let SessionData::Dns(dns) = &session.data {
        let domain = dns.query_domain();
        if !domain.is_empty() {
            if HIGH_VOL_DNS_SUBSTRINGS.iter().any(|d| domain.contains(d)) {
                return FilterResult::Drop;
            }
        }
    }
    if let SessionData::Http(http) = &session.data {
        let ua = http.user_agent();
        if !ua.is_empty() {
            if IOT_UAS.iter().any(|u| ua.contains(u)) {
                return FilterResult::Drop;
            }
        }
    }
    if !matches!(
        session.data,
        SessionData::Http(_) | SessionData::Tls(_) | SessionData::Quic(_)
    ) {
        return FilterResult::Accept;
    }
    let host = match &session.data {
        SessionData::Http(http) => http.host(),
        SessionData::Tls(tls) => tls.sni(),
        SessionData::Quic(quic) => quic.tls.sni(),
        _ => unreachable!(),
    };
    if host.is_empty() {
        return FilterResult::Accept;
    }

    match HIGH_VOL_SNI_SUBSTRINGS.iter().any(|h| host.contains(h)) {
        true => FilterResult::Drop,
        false => FilterResult::Accept,
    }
}

// Note that these are pretty arbitrary
lazy_static! {
    static ref HIGH_VOL_DNS_SUBSTRINGS: [&'static str; 6] = [
        "ssl.gstatic.com",
        "www.google.com",
        "mask.apple-dns.net",
        "clients6.google.com",
        ".stanford.edu",
        "captive.apple.com",
    ];

    static ref HIGH_VOL_SNI_SUBSTRINGS: [&'static str; 20] = [
        ".zoom.us",
        "teams.microsoft",
        "webex",
        "skype",
        "meet.goog",
        "turns.goog",
        "facetime.apple",
        ".primevideo",
        "media-amazon",
        "amazonvideo",
        ".youtube",
        "nflxvideo.net",
        ".hulu",
        "spotify",
        "google",
        "gstatic",
        "gateway.icloud.com",
        "bioontology.org",
        ".stanford.edu",
        "googleadservices.com",
    ];

    // Based on https://deviceatlas.com
    static ref IOT_UAS: [&'static str; 15] = [
        "AppleCoreMedia",
        "AppleTV",
        "Apple TV",

        "Fuchsia",
        "Roku",

        "NetCast",

        "Web0S",
        "WebOS",
        "WEBOS",

        "SmartTV",
        "SMART-TV",

        "Phillips",

        "Nintendo",
        "PlayStation",
        "Xbox",
    ];

    static ref PORTS: [u16; 17] = [
        1935,  // Twitch/legacy streaming
        3478,  // STUN
        19302, // WebRTC

        // Zoom
        8801,
        8802,
        8803,
        8804,
        8805,
        8806,
        8807,
        8808,
        8809,
        8810,

        // WebEx
        9000,
        5004,

        // VoIP
        5060,
        5061,
    ];
}
