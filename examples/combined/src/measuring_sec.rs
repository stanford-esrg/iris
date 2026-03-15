use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::SystemTime;

use iris_compiler::callback;
use iris_core::FiveTuple;
use iris_core::protocols::{packet::tcp::TCP_PROTOCOL, stream::SessionProto};

lazy_static::lazy_static! {
    static ref IPS: std::sync::Mutex<std::collections::HashSet<String>> =
        std::sync::Mutex::new(std::collections::HashSet::new());
    static ref PROTOS: std::sync::Mutex<std::collections::HashMap<String, usize>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
    static ref DST_PORTS: std::sync::Mutex<std::collections::HashMap<String, usize>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
}

static IPS_LAST_SEEN: OnceLock<Mutex<HashMap<u32, SystemTime>>> = OnceLock::new();
fn ips_record() -> &'static Mutex<HashMap<u32, SystemTime>> {
    IPS_LAST_SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

// Record the presence of an IP address on a network and port/protocol stats
#[callback("ipv4 and (tcp or udp),level=L4FirstPacket")]
pub fn record_ft(five_tuple: &FiveTuple) {
    // Record presence of source IP on network
    if let IpAddr::V4(v4) = five_tuple.orig.ip() {
        let ip = u32::from_be_bytes(v4.octets());
        let mut ip_map = ips_record().lock();
        ip_map.insert(ip, SystemTime::now());
    }
    // Record general destination port stats
    let proto = if five_tuple.proto == TCP_PROTOCOL {
        "TCP"
    } else {
        "UDP"
    };
    let port = format!("{}:{}", proto, five_tuple.resp.port());
    DST_PORTS
        .lock()
        .unwrap()
        .entry(port)
        .and_modify(|e| *e += 1)
        .or_insert(1);
}

// Record general stats about seen protocols
#[callback("tcp or udp,level=L7OnDisc")]
pub fn record_proto(session_proto: &SessionProto) {
    if matches!(session_proto, SessionProto::Null) {
        return;
    }
    // TODO record protocol in counter
    let proto = format!("{:?}", session_proto);
    PROTOS
        .lock()
        .unwrap()
        .entry(proto)
        .and_modify(|e| *e += 1)
        .or_insert(1);
}

pub fn write_stats() -> std::io::Result<()> {
    let fp = format!("{}_basic_stats.txt", OUTFILE_PREFIX);
    let mut writer = BufWriter::new(File::create(&fp).unwrap());

    writeln!(
        writer,
        "Observed {} unique source IPs\n",
        IPS.lock().unwrap().len()
    )?;

    writeln!(
        writer,
        "Observed {} session protocols:",
        PROTOS.lock().unwrap().len()
    )?;
    let protos = PROTOS.lock().unwrap();
    let mut protos = protos.iter().collect::<Vec<_>>();
    protos.sort_by_key(|&(_, v)| v);

    for (k, v) in protos.iter().rev() {
        writeln!(writer, "{}:{}", k, v)?;
    }
    writeln!(writer, "")?;

    writeln!(
        writer,
        "Observed {} destination ports:",
        DST_PORTS.lock().unwrap().len()
    )?;

    let ports = DST_PORTS.lock().unwrap();
    let mut ports = ports.iter().collect::<Vec<_>>();
    ports.sort_by_key(|&(_, v)| v);

    for (k, v) in ports.iter().rev() {
        writeln!(writer, "{}:{}", k, v)?;
    }
    Ok(())
}

use iris_compiler::filter;
use iris_core::protocols::stream::{Session, SessionData};
use iris_core::subscription::FilterResult;

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
lazy_static::lazy_static! {
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

use indexmap::IndexSet;
use iris_core::CoreId;
use iris_datatypes::*;

static USER_AGENTS: OnceLock<Mutex<HashMap<u32, Vec<String>>>> = OnceLock::new();
pub fn user_agents() -> &'static Mutex<HashMap<u32, Vec<String>>> {
    USER_AGENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

static SNIS: OnceLock<Mutex<IndexSet<String>>> = OnceLock::new();
pub fn snis() -> &'static Mutex<IndexSet<String>> {
    SNIS.get_or_init(|| Mutex::new(IndexSet::new()))
}

static DOMAINS: OnceLock<Mutex<IndexSet<String>>> = OnceLock::new();
pub fn domains() -> &'static Mutex<IndexSet<String>> {
    DOMAINS.get_or_init(|| Mutex::new(IndexSet::new()))
}

static URIS: OnceLock<Mutex<IndexSet<String>>> = OnceLock::new();
pub fn uris() -> &'static Mutex<IndexSet<String>> {
    URIS.get_or_init(|| Mutex::new(IndexSet::new()))
}

#[callback("ipv4 and tls and drop_high_vol_sess and drop_high_vol_conn")]
pub fn get_tls(tls: &TlsHandshake, five_tuple: &FiveTuple, core: &CoreId) {
    // let tls_str = format_tls(&*tls, false);
    if tls.sni().is_empty() {
        return;
    }
    let tls_str = format_tls_idx(tls.sni(), false);
    format_record(five_tuple, tls_str, core);
}

#[callback("ipv4 and quic and drop_high_vol_sess and drop_high_vol_conn")]
pub fn get_quic(quic: &QuicStream, five_tuple: &FiveTuple, core: &CoreId) {
    // let quic_str = format_tls(&quic.tls, true);
    if quic.tls.sni().is_empty() {
        return;
    }
    let quic_str = format_tls_idx(quic.tls.sni(), true);
    format_record(five_tuple, quic_str, core);
}

#[callback("ipv4 and http and drop_high_vol_sess and drop_high_vol_conn")]
pub fn get_http(http: &HttpTransaction, five_tuple: &FiveTuple, core: &CoreId) {
    if let IpAddr::V4(v4) = five_tuple.orig.ip() {
        let user_agent = http.user_agent();
        let mut ua_map = user_agents().lock();
        let entry = ua_map.entry(v4.into()).or_insert_with(Vec::new);
        if !user_agent.is_empty() && !entry.contains(&user_agent.into()) {
            entry.push(user_agent.into());
        }
    }

    let host = http.host();
    let uri = http.uri();
    if uri.is_empty() || host.is_empty() {
        return;
    }
    // let http_str = format!(
    //     "Proto:HTTP,Host:{}\nURI:{}",
    //     host, uri,
    // );
    let host_idx = {
        let mut doms = domains().lock();
        match doms.get_index_of(host) {
            Some(i) => i,
            None => {
                doms.insert(host.to_string());
                doms.len() - 1
            }
        }
    };
    let uri_idx = {
        let mut uris_lock = uris().lock();
        match uris_lock.get_index_of(uri) {
            Some(i) => i,
            None => {
                uris_lock.insert(uri.to_string());
                uris_lock.len() - 1
            }
        }
    };
    let http_str = format!("Proto:http,{}/{}", host_idx, uri_idx);
    format_record(five_tuple, http_str, core);
}

// Note - looks like they didn't really use DNS for fingerprints?
#[callback("dns and drop_high_vol_sess and drop_high_vol_conn")]
pub fn get_dns(dns: &DnsTransaction, five_tuple: &FiveTuple, core: &CoreId) {
    if dns.query.is_none()
        || dns.response.is_none()
        || dns.response.as_ref().unwrap().answers.is_empty()
    {
        return;
    }

    // Record expected destination IPs
    let mut resp_ips = vec![];
    for answer in dns.response.as_ref().unwrap().answers.iter() {
        resp_ips.push(match answer.data {
            iris_core::protocols::stream::dns::Data::A(record) => IpAddr::V4(record.0),
            iris_core::protocols::stream::dns::Data::Aaaa(record) => IpAddr::V6(record.0),
            _ => continue,
        });
    }

    // Record query domains
    let query = dns.query_domain();
    let domain_idx = {
        let mut doms = domains().lock();
        match doms.get_index_of(query) {
            Some(i) => i,
            None => {
                doms.insert(query.to_string());
                doms.len() - 1
            }
        }
    };
    let dns_str = format!("Proto:dns,{}={:?}", domain_idx, resp_ips);
    format_record(five_tuple, dns_str, core);
}

/* *** Helpers *** */

pub fn format_record(five_tuple: &FiveTuple, session_str: String, core_id: &CoreId) {
    let ft_str = format_ft(five_tuple);
    let s = format!(
        "[CONN: L3,L4={}\nSession={}\nts:{}]\n",
        ft_str,
        session_str,
        SystemTime::now().elapsed().unwrap().as_secs(),
    );
    write_result(s, core_id);
}

pub fn format_ft(five_tuple: &FiveTuple) -> String {
    let sport = five_tuple.orig.port();
    let dport = five_tuple.resp.port();
    format!(
        "{}:{}->{}:{} ({})\n",
        five_tuple.src_ip_str(),
        sport,
        five_tuple.dst_ip_str(),
        dport,
        five_tuple.transp_proto_str()
    )
}

pub fn format_tls_idx(sni: &str, quic: bool) -> String {
    let idx = {
        let mut snis = snis().lock();
        match snis.get_index_of(sni) {
            Some(i) => i,
            None => {
                snis.insert(sni.to_string());
                snis.len() - 1
            }
        }
    };
    format!("Proto:{},SNI:{}", if quic { "quic" } else { "tls" }, idx)
}

use array_init::array_init;
use std::sync::atomic::{AtomicPtr, Ordering};

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for results()
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core
const ARR_LEN: usize = NUM_CORES + 1;
// Temporary per-core files
pub const OUTFILE_PREFIX: &str = "sec_";

static RESULTS: OnceLock<[AtomicPtr<BufWriter<File>>; ARR_LEN]> = OnceLock::new();

fn results() -> &'static [AtomicPtr<BufWriter<File>>; ARR_LEN] {
    RESULTS.get_or_init(|| {
        let mut outp = vec![];
        for core_id in 0..ARR_LEN {
            let file_name = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
            let core_wtr = BufWriter::new(File::create(&file_name).unwrap());
            let core_wtr = Box::into_raw(Box::new(core_wtr));
            outp.push(core_wtr);
        }
        array_init(|i| AtomicPtr::new(outp[i]))
    })
}

pub fn init_files() {
    let _ = results();
}

pub fn write_result(value: String, core_id: &CoreId) {
    if value.is_empty() {
        return;
    }
    let ptr = results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    wtr.write_all(value.as_bytes()).unwrap();
}

pub fn dump_keys() {
    let fp = OUTFILE_PREFIX.to_owned() + "domains.txt";
    let mut writer = BufWriter::new(File::create(&fp).unwrap());
    let doms = domains().lock();
    for (i, d) in doms.iter().enumerate() {
        let s = format!("{}={}\n", i, d);
        writer.write_all(s.as_bytes()).unwrap();
    }

    let fp = OUTFILE_PREFIX.to_owned() + "uris.txt";
    let mut writer = BufWriter::new(File::create(&fp).unwrap());
    let uris = uris().lock();
    for (i, u) in uris.iter().enumerate() {
        let s = format!("{}={}\n", i, u);
        writer.write_all(s.as_bytes()).unwrap();
    }

    let fp = OUTFILE_PREFIX.to_owned() + "snis.txt";
    let mut writer = BufWriter::new(File::create(&fp).unwrap());
    let snis = snis().lock();
    for (i, s) in snis.iter().enumerate() {
        let s = format!("{}={}\n", i, s);
        writer.write_all(s.as_bytes()).unwrap();
    }

    let fp = OUTFILE_PREFIX.to_owned() + "user_agents.txt";
    let mut writer = BufWriter::new(File::create(&fp).unwrap());
    let uas = user_agents().lock();
    for (ip, ua) in uas.iter() {
        let s = format!("{}=[{}]\n", ip, ua.join(","));
        writer.write_all(s.as_bytes()).unwrap();
    }
}
