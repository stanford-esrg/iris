/// Test streaming filters with different levels of callbacks
/// Also tests "FilterStr" data type
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

use iris_compiler::*;
use iris_core::subscription::{FilterResult, FilterStr, StreamingCallback, StreamingFilter};
use iris_core::{FiveTuple, L4Pdu};
use iris_core::{Runtime, config::default_config};
use iris_datatypes::{ConnRecord, TlsHandshake};

// --- Weird streaming and multi-level filters --- //

static INVOKED_1: AtomicUsize = AtomicUsize::new(0);
static INVOKED_2: AtomicUsize = AtomicUsize::new(0);
static INVOKED_3: AtomicUsize = AtomicUsize::new(0);
static INVOKED_4: AtomicUsize = AtomicUsize::new(0);
const EXP_INVOKED: usize = 424; // number of connections in small_flows.pcap

#[filter("level=InL4Conn")]
fn test_filter(conn: &ConnRecord) -> FilterResult {
    if conn.total_pkts() > 1 {
        FilterResult::Accept
    } else {
        FilterResult::Continue
    }
}

/// Should be equivalent to `test_filter`
#[derive(Debug)]
#[filter]
struct TestFilterStateful {}

impl StreamingFilter for TestFilterStateful {
    fn new(_: &L4Pdu) -> Self {
        Self {}
    }
    fn clear(&mut self) {}
}

impl TestFilterStateful {
    #[filter_fn("TestFilterStateful,level=InL4Conn")]
    fn test_filter_stateful(&mut self, conn: &ConnRecord) -> FilterResult {
        if conn.total_pkts() > 1 {
            FilterResult::Accept
        } else {
            FilterResult::Continue
        }
    }
}

#[callback("test_filter,level=InL4Conn")]
fn test_callback_1(_: &ConnRecord) -> bool {
    INVOKED_1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    false
}

#[callback("test_filter,level=InL4Conn")]
fn test_callback_2(_: &FiveTuple) -> bool {
    INVOKED_2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    false
}

#[callback("test_filter,level=InL4Conn")]
fn test_callback_3(_: &FiveTuple) -> bool {
    INVOKED_3.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    false
}

#[callback("TestFilterStateful,level=InL4Conn")]
fn test_callback_stateful_filter(_: &ConnRecord) -> bool {
    INVOKED_4.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    false
}

// --- `FilterStr` data type in callbacks --- //

lazy_static::lazy_static! {
    static ref TEST_CB_SNI: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

#[callback("file=$IRIS_HOME/tests/functionality/filter_test/snis.txt")]
fn test_callback_sni(s: &FilterStr, _: &TlsHandshake) -> bool {
    TEST_CB_SNI.lock().unwrap().insert(s.to_string());
    false
}

// Check that grouped CB is invoked once per unique pattern for connections that
// match more than one (e.g., "calendar.google.com" matches both).
static INVOKED_2X_FILTERSTR: AtomicUsize = AtomicUsize::new(0);
const EXP_INVOKED_2X_FILTERSTR: usize = 46;
#[derive(Debug)]
#[callback("tls.sni contains 'a' or tls.sni contains 'o'")]
struct FilterStrWrapper {
    matched: usize,
}

impl StreamingCallback for FilterStrWrapper {
    fn new(_: &L4Pdu) -> Self {
        Self { matched: 0 }
    }
    fn clear(&mut self) {}
}

impl FilterStrWrapper {
    #[callback_fn("FilterStrWrapper")]
    fn test_callback_sni_stateful(&mut self, s: &FilterStr) -> bool {
        self.matched += 1;
        // println!("[Matched: {}] Got pattern in stateful callback: {}", self.matched, s);
        if self.matched > 1 {
            INVOKED_2X_FILTERSTR.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        assert!(
            s.contains("tls.sni contains a") || s.contains("tls.sni contains o"),
            "Unknown pattern: {}",
            s
        );
        if self.matched > 2 {
            panic!("Matched more than 2 times for pattern:");
        }
        true
    }
}

// This should fail to compile: FilterStr not supported in streaming CB
// #[callback("tcp,level=InL4Conn")]
// fn test_tcp_filterstr(s: &FilterStr) -> bool {
//     true
// }

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    assert!(INVOKED_1.load(std::sync::atomic::Ordering::SeqCst) == EXP_INVOKED);
    assert!(INVOKED_2.load(std::sync::atomic::Ordering::SeqCst) == EXP_INVOKED);
    assert!(INVOKED_3.load(std::sync::atomic::Ordering::SeqCst) == EXP_INVOKED);
    assert!(INVOKED_4.load(std::sync::atomic::Ordering::SeqCst) == EXP_INVOKED);
    assert!(
        INVOKED_2X_FILTERSTR.load(std::sync::atomic::Ordering::SeqCst) == EXP_INVOKED_2X_FILTERSTR
    );
    assert!(TEST_CB_SNI.lock().unwrap().len() == 2);
}
