/// Iris must allow users to arbitrarily subscribe to data across layers.
/// This validates edge case behavior for cross-layer combinations of subscriptions.
use std::path::PathBuf;
use std::sync::Mutex;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use iris_compiler::{callback, callback_fn, filter, input_files, iris_end_macros};
use iris_core::config::default_config;
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_core::subscription::StreamingCallback;
use iris_core::{FiveTuple, protocols::stream::SessionProto};
use iris_core::{L4Pdu, Runtime, StateTransition, StateTxData};

lazy_static::lazy_static! {
    static ref SESSIONS: Mutex<HashMap<String, (usize, Vec<FiveTuple>)>> = Mutex::new(HashMap::new());
    static ref OUTFILE: PathBuf = PathBuf::from("sessions.jsonl");
    static ref HTTP: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref TLS: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref DNS: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref QUIC: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref SSH: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref HANDSHAKES_STRUCT: AtomicUsize = AtomicUsize::new(0);
    static ref HANDSHAKES_FN: AtomicUsize = AtomicUsize::new(0);
    static ref STATE_TX_FN: AtomicBool = AtomicBool::new(false);
}

// Need to explicitly register parsers
#[callback("tcp or udp,parsers=http&tls&dns&quic&ssh")]
#[derive(Debug)]
struct TcpUdpCallback {
    ft: FiveTuple,
    proto: Option<SessionProto>,
    invoked: usize,
    hshk: bool,
}

impl StreamingCallback for TcpUdpCallback {
    fn new(pdu: &L4Pdu) -> Self {
        Self {
            ft: FiveTuple::from_ctxt(&pdu.ctxt),
            proto: None,
            invoked: 0,
            hshk: false,
        }
    }

    fn clear(&mut self) {
        assert!(
            self.proto.is_some(),
            "Should have unsubscribed after identifying protocol"
        );
    }
}

impl TcpUdpCallback {
    #[callback_fn("TcpUdpCallback,level=InL4Conn")]
    fn update(&mut self, _: &L4Pdu) -> bool {
        self.invoked += 1;
        assert!(
            self.proto.is_none(),
            "Protocol set: {:?} ({:?})",
            self.proto,
            self.ft
        );
        true
    }

    #[callback_fn("TcpUdpCallback,level=L4EndHshk")]
    fn handshake(&mut self, _: &StateTxData) -> bool {
        assert!(self.hshk == false, "Two handshakes? {:?}", self.ft);
        self.hshk = true;
        assert!(self.ft.proto == TCP_PROTOCOL, "Not TCP: {:?}", self.ft);
        HANDSHAKES_STRUCT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        true
    }

    #[callback_fn("TcpUdpCallback,level=L7OnDisc")]
    fn update_proto(&mut self, proto: &SessionProto) -> bool {
        self.proto = Some(proto.clone());
        let mut sessions = SESSIONS.lock().unwrap();
        let entry = sessions.entry(format!("{:?}", proto)).or_default();
        entry.0 += 1;
        entry.1.push(self.ft.clone());
        false
    }

    #[callback_fn("TcpUdpCallback,level=L4Terminated")]
    fn never_invoked(&mut self, _: &StateTxData) -> bool {
        panic!(
            "L4Terminated invoked (should have unsubscribed): {:?}",
            self.ft
        );
    }

    #[callback_fn("TcpUdpCallback,level=L4FirstPacket&L7EndHdrs")]
    fn state_tx(&mut self, tx: &StateTransition) -> bool {
        assert!(matches!(tx, StateTransition::L4FirstPacket));
        // L7EndHdrs shouldn't have been invoked, since we unsubscribed at L7OnDisc
        STATE_TX_FN.store(true, std::sync::atomic::Ordering::SeqCst);
        true
    }
}

#[callback("http or tls or dns or quic or ssh")]
fn http_callback(ft: &FiveTuple, proto: &SessionProto) {
    match proto {
        SessionProto::Http => {
            let mut http = HTTP.lock().unwrap();
            http.0 += 1;
            http.1.push(ft.clone());
        }
        SessionProto::Tls => {
            let mut tls = TLS.lock().unwrap();
            tls.0 += 1;
            tls.1.push(ft.clone());
        }
        SessionProto::Dns => {
            let mut dns = DNS.lock().unwrap();
            dns.0 += 1;
            dns.1.push(ft.clone());
        }
        SessionProto::Quic => {
            let mut quic = QUIC.lock().unwrap();
            quic.0 += 1;
            quic.1.push(ft.clone());
        }
        SessionProto::Ssh => {
            let mut ssh = SSH.lock().unwrap();
            ssh.0 += 1;
            ssh.1.push(ft.clone());
        }
        _ => panic!("Unexpected protocol: {:?} for {:?}", proto, ft),
    }
}

#[filter("level=L4EndHshk")]
fn has_valid_handshake(_: &StateTxData) -> FilterResult {
    FilterResult::Accept
}

#[callback("has_valid_handshake")]
fn handshake_cb(ft: &FiveTuple) {
    assert!(ft.proto == TCP_PROTOCOL, "Not TCP: {:?}", ft);
    HANDSHAKES_FN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

// Dummy filter that will never match
#[filter("level=InL4Conn")]
fn random_data(pdu: &L4Pdu) -> FilterResult {
    if pdu.seq_no() % 10 == 0 {
        FilterResult::Drop
    } else {
        FilterResult::Continue
    }
}

#[callback("random_data")]
fn random_data_cb(_ft: &FiveTuple) {
    panic!("Random data callback invoked");
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    check_outputs();
}

fn check_outputs() {
    let sessions = SESSIONS.lock().unwrap();
    let http = HTTP.lock().unwrap();
    let tls = TLS.lock().unwrap();
    let dns = DNS.lock().unwrap();
    let quic = QUIC.lock().unwrap();
    let ssh = SSH.lock().unwrap();

    let hshks_struct = HANDSHAKES_STRUCT.load(std::sync::atomic::Ordering::SeqCst);
    let hshks_fn = HANDSHAKES_FN.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        hshks_struct == hshks_fn,
        "Handshake counts differ: struct {}, fn {}",
        hshks_struct,
        hshks_fn
    );
    assert!(hshks_struct > 0, "No handshakes?");

    assert!({
        let sessions = sessions.get("Http").expect("No HTTP Sessions");
        sessions.0 == http.0 && sessions.1 == http.1 && sessions.0 > 0
    });
    assert!({
        let sessions = sessions.get("Tls").expect("No TLS Sessions");
        sessions.0 == tls.0 && sessions.1 == tls.1 && sessions.0 > 0
    });
    assert!({
        let sessions = sessions.get("Dns").expect("No DNS Sessions");
        sessions.0 == dns.0 && sessions.1 == dns.1 && sessions.0 > 0
    });
    assert!({ sessions.get("Quic").is_none() && quic.0 == 0 && quic.1.is_empty() });
    assert!({ sessions.get("Ssh").is_none() && ssh.0 == 0 && ssh.1.is_empty() });
    assert!(
        STATE_TX_FN.load(std::sync::atomic::Ordering::SeqCst),
        "State transition callback not invoked"
    );
}
