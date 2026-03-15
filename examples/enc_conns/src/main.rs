use clap::Parser;
use iris_compiler::{callback, datatype, datatype_group, input_files, iris_main};
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::Tracked;
use iris_core::StateTxData;
use iris_core::{config::load_config, L4Pdu, Runtime};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;

use lazy_static::lazy_static;

lazy_static! {
    static ref TOTAL_TCP: AtomicUsize = AtomicUsize::new(0);
    static ref BLOCKED_TCP: AtomicUsize = AtomicUsize::new(0);
}

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

/* Utilities for exemptions */

fn bit_length(data: &Vec<u8>) -> f64 {
    (data.len() * 8) as f64
}

fn bit_entropy(data: &Vec<u8>) -> f64 {
    data.iter().map(|&b| b.count_ones()).sum::<u32>() as f64 / bit_length(data)
}

fn pct_matching(data: &Vec<u8>, bytes: &[u8]) -> f64 {
    data.iter().filter(|&b| bytes.contains(b)).count() as f64 / bit_length(data)
}

fn first_n(data: &Vec<u8>, bytes: &[u8], n: usize) -> bool {
    if data.len() < n {
        return false;
    }
    data[..n].iter().all(|&b| bytes.contains(&b))
}

fn count_contiguous(data: &Vec<u8>, bytes: &[u8]) -> usize {
    data.iter()
        .fold(
            (0, 0), // Init counts at 0, 0
            |(max, curr), &b| {
                if bytes.contains(&b) {
                    // continue contiguous stream
                    (max, curr + 1)
                } else {
                    // end of contiguous stream; update `max`
                    (max.max(curr), 0)
                }
            },
        )
        .0
}

/* Datatype to extract first TCP packet with data */
#[datatype]
struct FirstPayloadPkt {
    pub(crate) payload: Option<Vec<u8>>,
}

impl Tracked for FirstPayloadPkt {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { payload: None }
    }

    #[datatype_group("FirstPayloadPkt,level=L4InPayload")]
    fn update(&mut self, pdu: &L4Pdu) {
        // Tracking TCP packets only
        if pdu.ctxt.proto != TCP_PROTOCOL {
            return;
        }
        // Not first
        if self.payload.is_some() {
            return;
        }
        // No data yet
        if pdu.length() == 0 {
            return;
        }

        // Store in `payload`
        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(pdu.offset(), pdu.length()) {
            self.payload = Some(data.to_vec());
        }
    }

    fn phase_tx(&mut self, _tx: &StateTxData) {}

    fn clear(&mut self) {
        self.payload = None;
    }
}

/* Callback to apply exemption rules */
#[callback("tcp,level=L4InPayload,parsers=http&tls")]
fn exempt(pkt: &FirstPayloadPkt, proto: &SessionProto) -> bool {
    if pkt.payload.is_none() || matches!(proto, SessionProto::Probing) {
        return true; // Continue
    }
    TOTAL_TCP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Ex5: exempt if protocol match
    if matches!(proto, SessionProto::Tls | SessionProto::Http) {
        return false;
    }
    let data = pkt
        .payload
        .as_ref()
        .expect("FirstPayloadPkt should have a payload if protocol ID'd");

    // Ex1: exempt if entropy within acceptable ranges
    let entr = bit_entropy(data);
    if entr <= 3.4 || entr >= 4.6 {
        return false;
    }

    // Ex2: exempt if first 6 bytes of pkt are [0x20, 0x7e]
    if first_n(data, &[0x20, 0x7e], 6) {
        return false;
    }

    // Ex3: exempt if more than 50% of bytes are [0x20, 0x7e]
    if pct_matching(data, &[0x20, 0x7e]) > 0.5 {
        return false;
    }

    // Ex4: exempt if more than 20 contiguous bytes are [0x20, 0x7e]
    if count_contiguous(data, &[0x20, 0x7e]) > 20 {
        return false;
    }

    BLOCKED_TCP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    false
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    let total = TOTAL_TCP.load(std::sync::atomic::Ordering::Relaxed);
    let blocked = BLOCKED_TCP.load(std::sync::atomic::Ordering::Relaxed);
    println!(
        "Total TCP conns: {}, Blocked TCP conns: {} ({:.4}% blocked)",
        total,
        blocked,
        (blocked as f64 / total as f64) * 100.0
    );
}
