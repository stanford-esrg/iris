use iris_compiler::*;
use iris_core::FiveTuple;
use iris_core::L4Pdu;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::Tracked;
use iris_core::{Runtime, config::default_config};

#[derive(Debug)]
#[datatype("tracked")]
struct ConnData {
    ft: FiveTuple,
    proto: Option<SessionProto>,
}

impl Tracked for ConnData {
    fn new(pdu: &L4Pdu) -> Self {
        Self {
            ft: FiveTuple::from_ctxt(&pdu.ctxt),
            proto: None,
        }
    }

    fn clear(&mut self) {}
}

impl ConnData {
    #[datatype_fn("ConnData,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        assert!(!pdu.ctxt.reassembled);
        if let Some(proto) = &self.proto {
            assert!(
                matches!(proto, SessionProto::Tls),
                "Expected TLS, got {:?} {:?}",
                proto,
                self.ft
            );
        }
    }

    #[datatype_fn("ConnData,level=L7OnDisc")]
    fn on_disc(&mut self, proto: &SessionProto) {
        self.proto = Some(proto.clone());
    }
}

#[callback("tls,level=L4Terminated")]
fn tls_cb(conn: &ConnData) {
    assert!(
        matches!(conn.proto, Some(SessionProto::Tls)),
        "Expected TLS, got {:?} {:?}",
        conn.proto,
        conn.ft
    );
}

#[datatype]
struct ConnDataUntracked {
    ft: FiveTuple,
    proto: Option<SessionProto>,
}

impl Tracked for ConnDataUntracked {
    fn new(pdu: &L4Pdu) -> Self {
        Self {
            ft: FiveTuple::from_ctxt(&pdu.ctxt),
            proto: None,
        }
    }

    fn clear(&mut self) {}
}

impl ConnDataUntracked {
    #[datatype_fn("ConnDataUntracked,level=InL4Conn")]
    fn update(&mut self, _: &L4Pdu) {}

    #[datatype_fn("ConnDataUntracked,level=L7OnDisc")]
    fn on_disc(&mut self, proto: &SessionProto) {
        self.proto = Some(proto.clone());
    }
}

#[callback("http,level=L4Terminated")]
fn http_cb(conn: &ConnDataUntracked) {
    assert!(
        matches!(conn.proto, Some(SessionProto::Http)),
        "Expected HTTP, got {:?} {:?}",
        conn.proto,
        conn.ft
    );
}

#[iris_end_macros]
fn main() {
    env_logger::init();
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
