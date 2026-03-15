use ::welford::Welford;
use iris_compiler::*;
use iris_core::L4Pdu;
use iris_core::Runtime;
use iris_core::StateTxData;
use iris_core::config::load_config;
#[allow(unused_imports)]
use iris_core::rte_rdtsc;
use iris_core::subscription::StreamingCallback;
use iris_datatypes::StartTime;
use ml_qos::features::FeatureChunk;
use std::time::Instant;

use std::fs::File;
// use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use smartcore::linalg::basic::matrix::DenseMatrix;

// Interval between inference
const INTERVAL_TS: u64 = 10;
const START_INF_AFTER_TS: u64 = 60; // Start after 60s

#[callback("tls,level=L4InPayload")]
#[derive(Debug, Serialize)]
struct Predictor {
    labels: Vec<usize>,
    #[serde(skip)]
    last_calc: Option<Instant>,
}

impl StreamingCallback for Predictor {
    fn new(_first_pkt: &L4Pdu) -> Predictor {
        Self {
            labels: Vec::new(),
            last_calc: None,
        }
    }
    fn clear(&mut self) {
        self.labels.clear();
    }
}

impl Predictor {
    #[callback_group("Predictor,level=L4InPayload")]
    fn update(&mut self, tracked: &FeatureChunk, start: &StartTime) -> bool {
        if start.elapsed().as_secs() < START_INF_AFTER_TS {
            return true; // Not enough historical data to start inference
        }
        if let Some(last) = self.last_calc {
            if last.elapsed().as_secs() < INTERVAL_TS {
                return true; // Continue receiving data
            }
        }
        let feature_vec = tracked.to_feature_vec();
        if let Ok(instance) = DenseMatrix::new(1, feature_vec.len(), feature_vec, false) {
            #[cfg(feature = "timing")]
            let start = unsafe { rte_rdtsc() };
            let mut pred = CLF.predict(&instance).unwrap();
            #[cfg(feature = "timing")]
            {
                let elapsed = unsafe { rte_rdtsc() } - start;
                WELF.lock().push(elapsed as usize);
            }
            assert!(pred.len() == 1);
            self.labels.push(pred.pop().unwrap());
            N_PREDICTIONS.fetch_add(1, Ordering::Relaxed);
        }
        self.last_calc = Some(Instant::now());
        true
    }

    #[callback_group("Predictor,level=L4Terminated")]
    fn conn_done(&mut self, _tx: &StateTxData) -> bool {
        if !self.labels.is_empty() {
            N_CONNS.fetch_add(1, Ordering::Relaxed);
        }
        false
    }
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[input_files("$IRIS_HOME/examples/ml_qos/data.txt")]
#[iris_main]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    // let mut outfile = File::create(args.outfile)?;

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter)?;
    runtime.run();

    #[cfg(feature = "timing")]
    {
        println!(
            "Done. Processed {:?} connections, {:?} inference. Avg inf time: {} (stdev: {}) cycles",
            N_CONNS.load(Ordering::Relaxed),
            N_PREDICTIONS.load(Ordering::Relaxed),
            WELF.lock().mean().unwrap_or(0),
            (WELF.lock().var().unwrap_or(0) as f64).sqrt()
        );
    }
    #[cfg(not(feature = "timing"))]
    {
        println!(
            "Done. Processed {:?} connections, {:?} inference.",
            N_CONNS.load(Ordering::Relaxed),
            N_PREDICTIONS.load(Ordering::Relaxed),
        );
    }

    Ok(())
}

// Globals
lazy_static::lazy_static! {
    // Global classifier instance
    static ref CLF: RandomForestClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>> = {
        let args = Args::parse();
        let mut file = File::open(&args.model_file).expect("Failed to open model file");
        let clf: RandomForestClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>> =
            bincode::deserialize_from(&mut file).expect("Failed to deserialize model");
        clf
    };
    // Number of processed connections
    static ref N_CONNS: AtomicUsize = AtomicUsize::new(0);
    // Number of times predictions have been made
    static ref N_PREDICTIONS: AtomicUsize = AtomicUsize::new(0);

    static ref WELF: parking_lot::Mutex<Welford<usize>> = parking_lot::Mutex::new(Welford::<usize>::new());
    // Global list of results
    // static ref RESULTS: parking_lot::Mutex<Vec<usize>> = parking_lot::Mutex::new(Vec::new());
}

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "CONFIG_FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "MODEL_FILE")]
    model_file: PathBuf,
    // #[clap(short, long, parse(from_os_str), value_name = "OUT_FILE")]
    // outfile: PathBuf,
}
