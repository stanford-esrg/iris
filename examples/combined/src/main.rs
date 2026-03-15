use std::path::PathBuf;

use clap::Parser;

mod measuring_sec;
mod ml_qos;
mod openvpn;

use measuring_sec::*;
use ml_qos::*;
use openvpn::*;

use iris_compiler::*;
use iris_core::FiveTuple;
use iris_core::Runtime;
use iris_core::config::load_config;

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    measuring_sec::init_files();

    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    ml_qos::print();
    openvpn::print();
    measuring_sec::dump_keys();
    measuring_sec::write_stats().unwrap();
}

// Define command-line arguments.
#[derive(Parser, Debug)]
pub(crate) struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "CONFIG_FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "MODEL_FILE")]
    model_file: PathBuf,
    // #[clap(short, long, parse(from_os_str), value_name = "OUT_FILE")]
    // outfile: PathBuf,
}
