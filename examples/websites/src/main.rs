use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use iris_core::config::load_config;
use iris_core::{stats::register_base_prometheus_registry, CoreId, Runtime};
use iris_datatypes::*;
use iris_compiler::{callback, iris_end_macros, input_files};

use clap::Parser;
use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

// Note: Using unbounded and high cardinality label set (like website field here) is bad practice
// and can lead to high memory and disk usage in Prometheus. This is just an example.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Labels {
    protocol: &'static str,
    website: String,
    core_id: u32,
}

static FAMILY: LazyLock<Family<Labels, Counter>> = LazyLock::new(Family::default);

fn init() {
    let mut r = Registry::default();
    r.register(
        "myapp_site_hits",
        "Number of callback calls per each website and protocol",
        FAMILY.clone(),
    );
    register_base_prometheus_registry(r);
}

fn write_result(protocol: &'static str, website: String, core_id: &CoreId) {
    if website.is_empty() {
        return;
    } // Would it be helpful to count these?
    FAMILY
        .get_or_create(&Labels {
            protocol,
            website,
            core_id: core_id.raw(),
        })
        .inc();
}

#[callback("dns")]
fn dns_cb(dns: &DnsTransaction, core_id: &CoreId) {
    let query_domain = (*dns).query_domain().to_string();
    write_result("dns", query_domain, core_id);
}

#[callback("http")]
fn http_cb(http: &HttpTransaction, core_id: &CoreId) {
    let uri = (*http).uri().to_string();
    write_result("http", uri, core_id);
}

#[callback("tls")]
fn tls_cb(tls: &TlsHandshake, core_id: &CoreId) {
    let sni = (*tls).sni().to_string();
    write_result("tls", sni, core_id);
}

#[callback("quic")]
fn quic_cb(quic: &QuicStream, core_id: &CoreId) {
    let sni = quic.tls.sni().to_string();
    write_result("quic", sni, core_id);
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
