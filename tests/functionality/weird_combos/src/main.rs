/// Validate behavior for weird combinations of subscriptions.
// Callback filter: ipv4 and tcp
// expl_level: Some(StateTransition::InL4Conn),
// datatypes: vec![FIRST_PKT.clone(), SESSION_PROTO.clone()],
use std::path::PathBuf;
use std::sync::Mutex;

use std::collections::HashMap;

use iris_compiler::{callback, callback_fn, input_files, iris_end_macros};
use iris_core::config::default_config;
use iris_core::subscription::StreamingCallback;
use iris_core::{FiveTuple, protocols::stream::SessionProto};
use iris_core::{L4Pdu, Runtime, StateTxData};

lazy_static::lazy_static! {
    static ref SESSIONS: Mutex<HashMap<String, (usize, Vec<FiveTuple>)>> = Mutex::new(HashMap::new());
    static ref OUTFILE: PathBuf = PathBuf::from("sessions.jsonl");
    static ref HTTP: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref TLS: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref DNS: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref QUIC: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
    static ref SSH: Mutex<(usize, Vec<FiveTuple>)> = Mutex::new((0, vec![]));
}

// Need to explicitly register parsers
#[callback("tcp or udp,parsers=http&tls&dns&quic&ssh")]
#[derive(Debug)]
struct TcpCallback {
    ft: FiveTuple,
    proto: Option<SessionProto>,
    invoked: usize,
}

impl StreamingCallback for TcpCallback {
    fn new(pdu: &L4Pdu) -> Self {
        Self {
            ft: FiveTuple::from_ctxt(&pdu.ctxt),
            proto: None,
            invoked: 0,
        }
    }

    fn clear(&mut self) {}
}

impl TcpCallback {
    #[callback_fn("TcpCallback,level=InL4Conn")]
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

    #[callback_fn("TcpCallback,level=L7OnDisc")]
    fn update_proto(&mut self, proto: &SessionProto) -> bool {
        self.proto = Some(proto.clone());
        let mut sessions = SESSIONS.lock().unwrap();
        let entry = sessions.entry(format!("{:?}", proto)).or_default();
        entry.0 += 1;
        entry.1.push(self.ft.clone());
        false
    }

    #[callback_fn("TcpCallback,level=L4Terminated")]
    fn never_invoked(&mut self, _: &StateTxData) -> bool {
        panic!(
            "L4Terminated invoked (should have unsubscribed): {:?}",
            self.ft
        );
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
}
