use crate::config::default_config;
use crate::conntrack::conn::conn_state::NUM_STATE_TRANSITIONS;
use crate::conntrack::*;
use crate::filter::FilterFactory;
use crate::lcore::CoreId;
use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::tcp::{SYN, TCP_PROTOCOL};
use crate::protocols::stream::ParserRegistry;
use crate::subscription::{Subscribable, Trackable};
use crate::L4Pdu;
use crate::Runtime;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

///// Dummy types /////

pub(crate) struct TestSubscribable;
impl Subscribable for TestSubscribable {
    type Tracked = TestTrackable;
}

pub(crate) struct TestTrackable {
    pub(crate) invoked: [usize; NUM_STATE_TRANSITIONS],
    pub(crate) state_tx: [usize; NUM_STATE_TRANSITIONS],
    pub(crate) packets: Vec<Mbuf>,
    pub(crate) core_id: CoreId,
}

impl Trackable for TestTrackable {
    type Subscribed = TestSubscribable;

    fn new(_first_pkt: &L4Pdu, core_id: CoreId) -> Self {
        Self {
            invoked: [0; NUM_STATE_TRANSITIONS],
            state_tx: [0; NUM_STATE_TRANSITIONS],
            packets: vec![],
            core_id,
        }
    }

    fn packets(&self) -> &Vec<Mbuf> {
        &self.packets
    }

    fn core_id(&self) -> &CoreId {
        &self.core_id
    }

    fn parsers() -> ParserRegistry {
        ParserRegistry::from_strings(vec!["tls"])
    }

    fn clear(&mut self) {
        self.packets.clear();
    }
}

fn filter() -> FilterFactory<TestTrackable> {
    fn packet_filter(_mbuf: &Mbuf, _core_id: &CoreId) -> bool {
        true
    }
    fn state_tx(conn: &mut ConnInfo<TestTrackable>, tx: &StateTransition) {
        if matches!(tx, StateTransition::L4FirstPacket) {
            conn.linfo.actions.active |= Actions::Update;
            conn.linfo.actions.active |= Actions::PassThrough;
            conn.layers[0].layer_info_mut().actions.active |= Actions::Update;
        }
    }
    fn update(conn: &mut ConnInfo<TestTrackable>, _pdu: &L4Pdu, state: DataLevel) -> bool {
        conn.tracked.invoked[state.as_usize()] += 1;
        conn.tracked.invoked[state.as_usize()] % 2 == 0
    }
    FilterFactory::new("", packet_filter, state_tx, update)
}

const MBUF: [u8; 1500] = [0; 1500];

fn tracker_config() -> TrackerConfig {
    TrackerConfig {
        max_connections: 100,
        max_out_of_order: 10,
        udp_inactivity_timeout: 60,
        tcp_inactivity_timeout: 60,
        tcp_establish_timeout: 30,
        timeout_resolution: 10,
    }
}

fn init_subscription() -> Subscription<TestSubscribable> {
    Subscription::new(filter())
}

fn init_ctxt() -> L4Context {
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 5000);
    L4Context {
        src,
        dst,
        proto: TCP_PROTOCOL,
        offset: 0,
        length: 0,
        seq_no: 0,
        ack_no: 0,
        flags: SYN,
        reassembled: false,
        app_offset: None,
    }
}

// Test must be run as `root`
#[test]
fn core_state_tx() {
    if !nix::unistd::Uid::effective().is_root() {
        println!("****This test must be run as root. Skipping.****");
        return;
    }
    // Shortcut for initializing DPDK layer
    let runtime_config = default_config();
    let runtime: Runtime<TestSubscribable> = Runtime::new(runtime_config, filter).unwrap();
    let mempool = runtime.offline.unwrap().get_mempool_raw();

    // Set up test
    let subscription = init_subscription();
    let config = tracker_config();
    let mut conntrack =
        ConnTracker::<TestTrackable>::new(config, TestTrackable::parsers(), CoreId(0));
    let mbuf = Mbuf::from_bytes(&MBUF, mempool).unwrap();
    let mut ctxt = init_ctxt();
    let conn_id = ConnId::new(ctxt.src, ctxt.dst, ctxt.proto);

    // Process TCP SYN
    conntrack.process(mbuf.clone(), ctxt, &subscription);
    assert!(
        conntrack.size() == 1,
        "ConnTracker should have one entry after processing a SYN packet."
    );
    {
        let entry = conntrack
            .table
            .get(&conn_id)
            .expect("Connection should exist");
        let info = &entry.info;
        assert!(
            info.linfo.state == LayerState::Payload,
            "ConnTracker should be in L4InPayload state after SYN packet."
        );
        assert!(
            info.linfo.actions.active == Actions::Update | Actions::PassThrough,
            "ConnTracker should have Update and PassThrough actions after first_packet filter."
        );
        let l7 = match info.layers.get(0).unwrap() {
            Layer::L7(layer) => layer,
        };
        assert!(l7.linfo.actions.active == Actions::Update);
    }

    // Process duplicate packet
    conntrack.process(mbuf.clone(), ctxt, &subscription);
    assert!(conntrack.size() == 1);
    {
        let entry = conntrack
            .table
            .get(&conn_id)
            .expect("Connection should exist");
        let info = &entry.info;
        assert!(
            info.tracked.invoked[DataLevel::L4InPayload(true).as_usize()] == 2,
            "Tracked should have invoked L4InPayload after duplicate SYN packet."
        );
        assert!(
            info.linfo.actions.active == Actions::Update | Actions::PassThrough,
            "ConnTracker should have Update and PassThrough actions after InUpdate filter."
        );
    }

    // Process new packet - make parser fail to match
    conntrack.clear_registry();
    ctxt.flags = 0;
    ctxt.seq_no = 1;
    conntrack.process(mbuf, ctxt, &subscription);
    {
        let entry = conntrack
            .table
            .get(&conn_id)
            .expect("Connection should exist");
        let info = &entry.info;
        assert!(info.tracked.invoked[DataLevel::L4InPayload(true).as_usize()] == 3);
        let l7 = match info.layers.get(0).unwrap() {
            Layer::L7(layer) => layer,
        };
        assert!(l7.linfo.drop()); // Parser should have failed to match
        assert!(
            info.tracked.state_tx[DataLevel::L7OnDisc.as_usize()] == 1,
            "Tracked should have state tx after parser failure."
        );
        // 3 packets observed total
        assert!(
            entry.flow_len(true).unwrap() == 3,
            "Observed flow length is {}; should be {}",
            entry.flow_len(true).unwrap(),
            3
        );
        assert!(
            entry.total_len().unwrap() == 3,
            "Observed total length is {}; should be {}",
            entry.total_len().unwrap(),
            3
        );
    }
}
