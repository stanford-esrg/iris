use iris_compiler::*;
use iris_core::L4Pdu;
use iris_core::StateTxData;
use iris_core::subscription::{StreamingCallback, Tracked};
use iris_datatypes::StartTime;
use std::time::Instant;

use super::Args;

use std::fs::File;
// use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

use clap::Parser;
use serde::Serialize;

use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use smartcore::linalg::basic::matrix::DenseMatrix;

// Interval between inference
const INTERVAL_TS: u64 = 10;
const START_INF_AFTER_TS: u64 = 60;

#[callback("tls,level=L4InPayload")]
#[derive(Debug, Serialize)]
pub struct Predictor {
    pub labels: Vec<usize>,
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
    pub fn update(&mut self, tracked: &FeatureChunk, start: &StartTime) -> bool {
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
            let mut pred = CLF.predict(&instance).unwrap();
            assert!(pred.len() == 1);
            self.labels.push(pred.pop().unwrap());
            N_PREDICTIONS.fetch_add(1, Ordering::Relaxed);
        }
        self.last_calc = Some(Instant::now());
        true
    }

    #[callback_group("Predictor,level=L4Terminated")]
    pub fn conn_done(&mut self, _tx: &StateTxData) -> bool {
        if !self.labels.is_empty() {
            N_CONNS.fetch_add(1, Ordering::Relaxed);
        }
        false
    }
}

#[allow(dead_code)]
pub fn print() {
    println!(
        "Done. Processed {:?} connections, {:?} inference.",
        N_CONNS.load(Ordering::Relaxed),
        N_PREDICTIONS.load(Ordering::Relaxed)
    );
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
    // Global list of results
    // static ref RESULTS: parking_lot::Mutex<Vec<usize>> = parking_lot::Mutex::new(Vec::new());
}

#[allow(unused_imports)]
use iris_compiler::{cache_file, datatype, datatype_group};
use iris_core::protocols::stream::SessionProto;
use welford::Welford;

const NSEGS: usize = 10; // Segments before clearing "last 10" stats
// Features from Fig 8
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct FeatureChunk {
    /// Note - "All previous" refers to all segments seen since the
    /// start of the L7 payload (after the initial TLS/QUIC handshake).
    ///
    // Average segment size from start
    // In features: allprev_avg_chunksize
    pub all_prev_avg_seg_size: f64,
    /// Max segment size from start
    /// In features: allprev_max_chunksize
    pub all_prev_max_seg_size: f64,
    /// Stdev of segment size from start
    /// In features: allprev_std_chunksize
    pub all_prev_std_seg_size: f64,
    /// Cumsum segment size
    /// In features: cumsum_chunksizes
    pub all_prev_cumsum_seg_size: f64,
    /// Note - "Last 10" refers to the last 10 segments seen.
    /// I.e., this value is reset every 10 seconds.
    ///
    /// Minimum of the last ten segment sizes
    /// In features: 10_min_chunksize
    pub last_10_min_seg_size: f64,
    /// Stdev of last 10 segment sizes
    /// In features: 10_std_chunksize
    pub last_10_std_seg_size: f64,
    /// Max. of last 10 segment sizes
    /// In features: 10_max_chunksize
    pub last_10_max_seg_size: f64,
    /// Avg of last 10 segment sizes
    /// In features: 10_avg_chunksize
    pub last_10_avg_seg_size: f64,

    /* For calculating running stats */
    welford_seg_size_all: Welford<f64>,
    welford_seg_size_last_10: Welford<f64>,

    /* Number of segments processed since last `reset` */
    n_segs: usize,

    /* Current segment */
    // Segment tracker
    segment_tracker: SegmentTracker,
}

impl Tracked for FeatureChunk {
    fn new(_first_pkt: &L4Pdu) -> Self {
        FeatureChunk {
            all_prev_avg_seg_size: 0.0,
            all_prev_max_seg_size: 0.0,
            all_prev_std_seg_size: 0.0,
            all_prev_cumsum_seg_size: 0.0,
            last_10_min_seg_size: 0.0,
            last_10_std_seg_size: 0.0,
            last_10_max_seg_size: 0.0,
            last_10_avg_seg_size: 0.0,
            welford_seg_size_all: Welford::<f64>::new(),
            welford_seg_size_last_10: Welford::<f64>::new(),
            n_segs: 0,
            segment_tracker: SegmentTracker::new(),
        }
    }

    fn clear(&mut self) {
        // Reset all "last 10" features to 0
        self.last_10_min_seg_size = 0.0;
        self.last_10_std_seg_size = 0.0;
        self.last_10_max_seg_size = 0.0;
        self.last_10_avg_seg_size = 0.0;
        self.welford_seg_size_last_10 = Welford::<f64>::new();
    }

    fn phase_tx(&mut self, _tx: &StateTxData) {}
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("FeatureChunk,level=L4InPayload")
    )]
    fn update(&mut self, pdu: &L4Pdu) {
        self.new_packet(pdu);
    }
}

impl FeatureChunk {
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        // Wait until after initial handshake
        // if !self.start {
        //     return;
        // }
        // Update existing segment
        if let Some(seg_size) = self.segment_tracker.update(pdu) {
            // New video segment is done
            if self.n_segs >= NSEGS {
                // Reset "last 10"
                self.clear();
            }
            self.update_data(seg_size);
            self.n_segs += 1;
        }
    }

    /// Process new video segment
    pub fn update_data(&mut self, seg_size: f64) {
        self.welford_seg_size_all.push(seg_size);
        self.welford_seg_size_last_10.push(seg_size);

        // Running counters (all)
        self.all_prev_avg_seg_size = self.welford_seg_size_all.mean().unwrap();
        self.all_prev_max_seg_size = max_cmp(self.all_prev_max_seg_size, seg_size);
        self.all_prev_std_seg_size = match self.welford_seg_size_all.var() {
            Some(v) => v.sqrt(),
            None => 0.0,
        };
        self.all_prev_cumsum_seg_size += seg_size;

        // Running counters (last 10 segments)
        self.last_10_min_seg_size = if self.last_10_min_seg_size > 0.0 {
            min_cmp(self.last_10_min_seg_size, seg_size) as f64
        } else {
            seg_size
        };
        self.last_10_std_seg_size = match self.welford_seg_size_last_10.var() {
            Some(v) => v.sqrt(),
            None => 0.0,
        };
        self.last_10_max_seg_size = max_cmp(self.last_10_max_seg_size, seg_size);

        self.last_10_avg_seg_size = self.welford_seg_size_last_10.mean().unwrap();
    }

    /// Returns a vector in the order of training data:
    /// - allprev_avg_chunksize,
    /// - allprev_max_chunksize,
    /// - allprev_std_chunksize,
    /// - 10_min_chunksize,
    /// - cumsum_chunksizes,
    /// - 10_std_chunksize,
    /// - 10_max_chunksize,
    /// - 10_avg_chunksize
    pub fn to_feature_vec(&self) -> Vec<f64> {
        Vec::from([
            self.all_prev_avg_seg_size,
            self.all_prev_max_seg_size,
            self.all_prev_std_seg_size,
            self.last_10_min_seg_size,
            self.all_prev_cumsum_seg_size,
            self.last_10_std_seg_size,
            self.last_10_max_seg_size,
            self.last_10_avg_seg_size,
        ])
    }
}

fn min_cmp(a: f64, b: f64) -> f64 {
    if let Some(ordering) = a.partial_cmp(&b) {
        return match ordering {
            std::cmp::Ordering::Less => a,
            _ => b,
        };
    }
    panic!("{:?} or {:?} is NaN", a, b);
}

fn max_cmp(a: f64, b: f64) -> f64 {
    if min_cmp(a, b) == a { b } else { a }
}

pub const TLS_RECORD_HDR_SIZE: usize = 5;

/// Implements the segment tracking mechanism described in Bronzino et. al.
/// Note: these refer to "segments of video", not TCP segments.
pub struct SegmentTracker {
    /// Timestamp of the last-seen upstream packet with a non-zero payload.
    /// Note: for QUIC, this would be the last-seen upstream packet with a
    /// payload >150 bytes.
    pub last_seg_start: Option<Instant>,
    /// Count of the payload bytes seem in the subsequent downstream traffic,
    /// used to determine video segment sizes.
    pub curr_seg_size: usize,
    /// Identified app-layer protocol
    pub proto: SessionProto,
}

impl SegmentTracker {
    pub fn new() -> Self {
        SegmentTracker {
            last_seg_start: None,
            curr_seg_size: 0,
            proto: SessionProto::Tls, // tmp
        }
    }

    pub fn header_size(&mut self, _pdu: &L4Pdu) -> usize {
        match self.proto {
            SessionProto::Tls => TLS_RECORD_HDR_SIZE,
            SessionProto::Quic => panic!("QUIC unimplemented"),
            _ => panic!("Unsupported protocol"),
        }
    }

    pub fn threshold(&mut self) -> usize {
        match self.proto {
            SessionProto::Tls => 0,
            SessionProto::Quic => panic!("QUIC unimplemented"),
            _ => panic!("Unsupported protocol"),
        }
    }

    #[allow(dead_code)]
    pub fn set_protocol(&mut self, proto: SessionProto) {
        self.proto = proto;
    }

    pub fn new_segment(&mut self, pdu: &L4Pdu) -> Option<f64> {
        // Start of new segment
        self.last_seg_start = Some(pdu.ts);
        let seg_size = self.curr_seg_size as f64;
        self.curr_seg_size = 0;
        Some(seg_size)
    }

    pub fn update(&mut self, pdu: &L4Pdu) -> Option<f64> {
        match pdu.dir {
            true => {
                if pdu.length() > self.threshold() + self.header_size(pdu) {
                    return self.new_segment(pdu);
                }
            }
            false => {
                if self.last_seg_start.is_some() {
                    self.curr_seg_size += pdu.length() - self.header_size(pdu);
                }
            }
        }
        None
    }
}
