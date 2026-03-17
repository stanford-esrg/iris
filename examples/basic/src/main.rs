use clap::Parser;
use iris_compiler::*;
use iris_core::subscription::{FilterResult, StreamingCallback, StreamingFilter};
use iris_core::StateTxData;
use iris_core::{config::load_config, L4Pdu, Runtime};
use iris_datatypes::{ConnRecord, PktCount, TlsHandshake};
use std::path::PathBuf;

/// Most examples specify a config file as a command line argument, allowing users to
/// easily run the same applications on multiple machines, test in offline and online mode,
/// and try out different configs (e.g., flow sampling, connection timeouts, mempool size).
#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
}

/// A basic callback that filters for "tls" connections and receives a
/// TLS handshake (provided in the iris-datatypes crate).
#[callback("tls")]
fn log_tls(tls: &TlsHandshake) {
    println!("Received TLS handshake: {:?}", tls);
}

/// Users who require more complex stateful filter logic can implement custom filters.
/// These can be stateful (like this one) or stateless functions.
/// All filter functions must return a `FilterResult`.
/// Any filters that maintain state must implement the `StreamingFilter` trait.
#[derive(Debug)]
#[filter]
#[allow(dead_code)]
struct ShortConnLen {
    len: usize,
}

impl StreamingFilter for ShortConnLen {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { len: 0 }
    }
    fn clear(&mut self) {}
}

#[allow(dead_code)]
impl ShortConnLen {
    /// Every filter function in an `impl` block must be tagged with this macro.
    /// In this case, we include the `level` to indicate when we want to receive updates.
    #[filter_fn("ShortConnLen,level=L4InPayload")]
    fn update(&mut self, _: &L4Pdu) -> FilterResult {
        self.len += 1;
        if self.len > 10 {
            return FilterResult::Drop;
        }
        FilterResult::Continue
    }

    #[filter_fn("ShortConnLen,level=L4Terminated")]
    fn terminated(&self) -> FilterResult {
        if self.len <= 10 {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }
}

/// An alternate implementation of `ShortConnLen` would use
/// the `PktCount` built-in data type. These are equivalent.
/// If another filter or callback also uses `PktCount`, the
/// same instance will be shared.
#[filter("level=L4InPayload")]
#[allow(dead_code)]
fn short_conn_len(packets: &PktCount) -> FilterResult {
    if packets.total() > 10 {
        return FilterResult::Drop;
    }
    FilterResult::Continue
}

/// You use a custom filter by referring to it in the callback filter.
/// Note: using `short_conn_len` or `ShortConnLen` are equivalent.
/// #[callback("tls and ShortConnLen,level=L4Terminated")]
#[callback("tls and short_conn_len,level=L4Terminated")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
}

/// Users can implement stateful callbacks as structs.
/// Each must implement the `StreamingCallback` trait.
/// This callback also takes an input file, which is a list of additional filter
/// predicates (one per line). This can be useful when users require a large number
/// of filter predicates that would be cumbersome to list inline.
#[derive(Debug)]
#[callback("tls and file=$IRIS_HOME/examples/basic/tls_snis.txt")]
struct TlsCbStreaming {
    in_payload: bool,
}

impl StreamingCallback for TlsCbStreaming {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { in_payload: false }
    }
    fn clear(&mut self) {}
}

impl TlsCbStreaming {
    /// Stateful callback functions in the `impl` block must use this macro.
    /// They must return a boolean value.
    /// These can return `false` to unsubscribe to a connection, i.e., to stop
    /// receiving updates for that connection. If one function in an `impl` block
    /// returns `false`, the entire callback is unsubscribed.
    #[callback_fn("TlsCbStreaming,level=L4InPayload")]
    fn update(&mut self, _: &L4Pdu) -> bool {
        true
    }

    #[callback_fn("TlsCbStreaming,level=L7EndHdrs")]
    fn state_tx(&mut self, tx: &StateTxData) -> bool {
        assert!(matches!(tx, StateTxData::L7EndHdrs(_)));
        self.in_payload = true;
        true
    }
}

/// Callbacks can also (statelessly) stream data within a connection.
/// These can return `false` to unsubscribe to a connection.
#[callback("tls,level=L4InPayload")]
fn tls_cb_streaming(tls: &TlsHandshake, record: &ConnRecord) -> bool {
    println!("Received update in L7InPayload: {:?} {:?}", tls, record);
    record.orig.nb_pkts < 100
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
