use clap::Parser;
use iris_compiler::*;
use iris_core::subscription::{FilterResult, StreamingCallback, StreamingFilter};
use iris_core::StateTxData;
use iris_core::{config::load_config, L4Pdu, Runtime};
use iris_datatypes::{ConnRecord, TlsHandshake};
use std::path::PathBuf;

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

#[derive(Debug)]
#[filter]
struct ShortConnLen {
    len: usize,
}

impl StreamingFilter for ShortConnLen {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { len: 0 }
    }
    fn clear(&mut self) {}
}

impl ShortConnLen {
    #[filter_group("ShortConnLen,level=L4InPayload")]
    fn update(&mut self, _: &L4Pdu) -> FilterResult {
        self.len += 1;
        if self.len > 10 {
            return FilterResult::Drop;
        }
        FilterResult::Continue
    }

    #[filter_group("ShortConnLen,level=L4Terminated")]
    fn terminated(&self) -> FilterResult {
        if self.len <= 10 {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }
}

#[callback("tls and ShortConnLen,level=L4Terminated")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
}

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
    #[callback_group("TlsCbStreaming,level=L4InPayload")]
    fn update(&mut self, _: &L4Pdu) -> bool {
        true
    }

    #[callback_group("TlsCbStreaming,level=L7EndHdrs")]
    fn state_tx(&mut self, tx: &StateTxData) -> bool {
        assert!(matches!(tx, StateTxData::L7EndHdrs(_)));
        self.in_payload = true;
        true
    }
}

#[callback("tls,level=L4InPayload")]
fn tls_cb_streaming(tls: &TlsHandshake, record: &ConnRecord) -> bool {
    println!("Received update in L7InPayload: {:?} {:?}", tls, record);
    record.orig.nb_pkts < 100
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
