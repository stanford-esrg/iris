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
use lazy_static::lazy_static;

lazy_static! {
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
    let fp = format!("{}_basic_stats.txt", super::to_file::OUTFILE_PREFIX);
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
