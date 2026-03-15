mod ack_timer;
mod opcodes;
mod utils;

use anyhow::Result;
use std::sync::atomic::{AtomicUsize, Ordering};

use iris_compiler::*;
use iris_core::{Runtime, config::load_config};

use ack_timer::OpenVPNAcks;
use opcodes::OpenVPNOpcode;
use utils::{CRST_OPCODE, OPCODES, SRST_OPCODE};

lazy_static::lazy_static! {
    static ref CHECKED: AtomicUsize = AtomicUsize::new(0);

    static ref FLAGGED_ANY: AtomicUsize = AtomicUsize::new(0);
    static ref FLAGGED_ACK: AtomicUsize = AtomicUsize::new(0);
    static ref FLAGGED_OPS: AtomicUsize = AtomicUsize::new(0);

    static ref RAW_OPCODES: AtomicUsize = AtomicUsize::new(0);
}

/// S8 in original paper - recorded TCP and UDP flows
#[callback("tcp or udp,level=L4InPayload")]
fn callback(opcodes: &OpenVPNOpcode, acks: &OpenVPNAcks) -> bool {
    // Reset
    if opcodes.rst_in_payl {
        return false;
    }

    // Keep receiving data
    if acks.n_payload_pkts() < *utils::N_REQ_PKTS {
        return true;
    }

    // Time to fingerprint!
    CHECKED.fetch_add(1, Ordering::Relaxed);
    let op_id = opcodes.apply_opcode_fingerprint();
    let ack_id = acks.apply_ack_fingerprint();
    if op_id || ack_id {
        FLAGGED_ANY.fetch_add(1, Ordering::Relaxed);
    }
    if op_id {
        FLAGGED_OPS.fetch_add(1, Ordering::Relaxed);
        if opcodes.opcodes_tot.iter().all(|o| OPCODES.contains(&o))
            && opcodes.crst.unwrap() == CRST_OPCODE
            && opcodes.srst.unwrap() == SRST_OPCODE
        {
            RAW_OPCODES.fetch_add(1, Ordering::Relaxed);
        }
    }
    if ack_id {
        FLAGGED_ACK.fetch_add(1, Ordering::Relaxed);
    }

    false
}

#[iris_main]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    // let mut outfile = File::create(args.outfile)?;

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter)?;
    runtime.run();

    println!(
        "Done. Results: {} checked, {} flagged total.
        Flagged: {} ack fingerprint, {} opcode fingerprint.
        Of opcode fingerprint, {} raw opcodes",
        CHECKED.load(Ordering::Relaxed),
        FLAGGED_ANY.load(Ordering::Relaxed),
        FLAGGED_ACK.load(Ordering::Relaxed),
        FLAGGED_OPS.load(Ordering::Relaxed),
        RAW_OPCODES.load(Ordering::Relaxed)
    );

    Ok(())
}

use clap::Parser;
use std::path::PathBuf;

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "CONFIG_FILE")]
    config: PathBuf,
}
