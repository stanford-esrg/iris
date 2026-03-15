use iris_compiler::*;
use iris_core::FiveTuple;
use iris_core::Runtime;
use iris_core::config::load_config;

use std::path::PathBuf;

use clap::Parser;

mod basic_stats;
mod filter;
mod process_sessions;
mod to_file;

use basic_stats::*;
use filter::*;
use process_sessions::*;
use to_file::*;

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
    // TODO outfile
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    env_logger::init();
    init_files();

    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    write_stats().unwrap();
    dump_keys();
}
