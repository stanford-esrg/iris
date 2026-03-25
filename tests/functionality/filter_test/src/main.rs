/// Test streaming filters with different levels of callbacks
use std::sync::atomic::AtomicUsize;

use iris_compiler::*;
use iris_core::subscription::FilterResult;
use iris_core::subscription::StreamingFilter;
use iris_core::{FiveTuple, L4Pdu};
use iris_core::{Runtime, config::default_config};
use iris_datatypes::ConnRecord;

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
}
