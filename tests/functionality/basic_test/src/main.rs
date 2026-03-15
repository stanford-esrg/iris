use clap::Parser;
use iris_compiler::{callback, input_files, iris_main};
use iris_core::subscription::Tracked;
use iris_core::{config::load_config, FiveTuple, Runtime};
use iris_datatypes::{conn_fts::ByteCount, FromSession, StaticData, TlsHandshake};
use lazy_static::lazy_static;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// Count how many times the TLS callback is invoked
static TLS_CB_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./tests/functionality/basic_test/curr_output.jsonl"
    )]
    outfile: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
}

#[derive(Debug, serde::Serialize)]
struct TlsResult {
    sni: Option<String>,
    five_tuple: FiveTuple,
    byte_count: usize,
}

lazy_static! {
    static ref RESULTS: Mutex<Vec<TlsResult>> = Mutex::new(Vec::new());
}

#[callback("tls,level=L4Terminated")]
fn tls_cb(tls: &TlsHandshake, bytecount: &ByteCount, five_tuple: &FiveTuple) {
    TLS_CB_COUNT.fetch_add(1, Ordering::Relaxed);

    let result = TlsResult {
        sni: Some(tls.sni().to_string()),
        five_tuple: five_tuple.clone(),
        byte_count: bytecount.total(),
    };

    {
        let mut vec = RESULTS.lock().unwrap();
        vec.push(result);
    }
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    // Print results to stdout as pretty JSON
    if let Ok(results) = RESULTS.lock() {
        let json = serde_json::to_string_pretty(&*results).unwrap();
        println!("{}", json);
        let mut file = std::fs::File::create(&args.outfile).unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }
    println!("TLS Callback Count: {:?}", TLS_CB_COUNT);
}
