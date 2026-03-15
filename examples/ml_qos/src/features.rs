#[allow(unused_imports)]
use iris_compiler::{cache_file, datatype, datatype_group};
use iris_core::subscription::Tracked;
use iris_core::{L4Pdu, StateTxData, protocols::stream::SessionProto};
use std::time::Instant;
use welford::Welford;

const NSEGS: usize = 10; // Segments before clearing "last 10" stats

#[cfg_attr(
    not(feature = "skip_expand"),
    cache_file("$IRIS_HOME/examples/ml_qos/data.txt")
)]
fn _cache_file() {}

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
