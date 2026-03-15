use indexmap::IndexSet;
use iris_compiler::*;
use iris_core::CoreId;
use iris_core::FiveTuple;
use iris_datatypes::*;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::SystemTime;

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
    super::to_file::write_result(s, core_id);
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

// #[allow(dead_code)]
// pub fn format_tls_full(tls: &Tls, quic: bool) -> String {
//     let sni = tls.sni();
//     if sni.is_empty() { return String::new(); }
//     let cversion = tls.client_version();
//     let sversion = tls.server_version();
//     let cciphers = tls.client_ciphers();
//     let ccompression = tls.client_compression_algs();
//     let calpn = tls.client_alpn_protocols();
//     let csigalgs = tls.client_signature_algs();
//     let proto = if quic { "quic" } else { "tls" };
//     format!(
//         "Proto:{}\nSNI:{}\nCVersion:{}\nSVersion:{}\nCCiphers:{:?}\nCCompression:{:?}\nCALPN:{:?}\nCSigAlgs:{:?}",
//         proto, sni, cversion, sversion, cciphers, ccompression, calpn, csigalgs
//     )
// }

// TODO fingerprints underspecified
// #[derive(Debug, Clone)]
// pub enum Software {
//     // "Risky" applications
//     AdobeFlashPlayer(String),
//     AdobeReader(String),
//     AdobeAir(String),
//     Java(String),
//
//     // Applications
//     ITunes(String),
//     Spotify(String),
//     Outlook(String),
//     GMail(String),
//
//     // Browsers with version
//     Tor(String),
//     Chrome(String),
//     Safari(String),
//     Firefox(String),
//
//     // Antivirus products with version
//     Bitdefender(String),
//     Norton(String),
//     MalwareBytes(String),
//     McAfee(String),
//     Sophos(String),
//
//     // OS with version
//     Windows(String),
//     Mac(String),
//     Linux(String),
//
//     // Password managers with version
//     OnePassword(String),
//     LastPass(String),
// }
