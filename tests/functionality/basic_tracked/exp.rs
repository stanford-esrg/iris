Parsed datatype: ConnDuration
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: PktCount
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ByteCount
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: InterArrivals
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ConnHistory
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ConnRecord
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: DnsTransaction
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: HttpTransaction
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: BidirPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: OrigPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: RespPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ZcFrame
Caching input in memory
Parsed datatype function: new
Caching input in memory
Parsed datatype: Payload
Caching input in memory
Parsed datatype function: new
Caching input in memory
Parsed datatype: QuicStream
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: SshHandshake
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: FiveTuple
Caching input in memory
Parsed datatype: AnonFiveTuple
Caching input in memory
Parsed datatype: ClearedFiveTuple
Caching input in memory
Parsed datatype: StartTime
Caching input in memory
Parsed datatype: EtherTCI
Caching input in memory
Parsed datatype: EthAddr
Caching input in memory
Parsed datatype: TlsHandshake
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Warning - clearing existing contents of file /home/tcr6/iris/datatypes/data.txt
GOT OUTPUT FILE NAME: /home/tcr6/iris/datatypes/data.txt
Parsed datatype: ConnData
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype function: on_disc
Caching input in memory
Parsed callback: "tls_cb"
Caching input in memory
Parsed datatype: ConnDataUntracked
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype function: on_disc
Caching input in memory
Parsed callback: "http_cb"
Caching input in memory
Done with macros - beginning code generation

Parsers: http, tls

Tree Per-Packet:
`- ethernet (0)
   |- ipv4 (1)
   |  `- tcp (2)
   `- ipv6 (3)
      `- tcp (4)

Tree L4FirstPacket
,`- 0: ethernet
   |- 1: ipv4
   |       Actions: L4:Update,PassThrough,Track->(L7OnDisc,L4Terminated); L7:Parse->(L7OnDisc,L4Terminated)
   `- 2: ipv6 x
           Actions: L4:Update,PassThrough,Track->(L7OnDisc,L4Terminated); L7:Parse->(L7OnDisc,L4Terminated)

Tree InL4Conn
,`- 0: ethernet
   |- 1: L7=Discovery
   |       Actions: L4:PassThrough->(L7OnDisc,L4Terminated); L7:Parse->(L7OnDisc,L4Terminated)
   |       Data: ConnData->(L7OnDisc,L4Terminated)
   `- 2: L7>=Headers
      |- 3: http  Actions: L4:Update,Track->(L7OnDisc,L4Terminated); L7:-
      `- 4: tls x
              Actions: L4:Update,Track->(L7OnDisc,L4Terminated); L7:-
              Data: ConnData->(L7OnDisc,L4Terminated)

Tree L7OnDisc
,`- 0: ethernet
   |- 1: http  Actions: L4:Update,Track->(L4Terminated); L7:-
   `- 2: tls x  Actions: L4:Update,Track->(L4Terminated); L7:-  Data: ConnData->(L4Terminated)

Tree L4Terminated
,`- 0: ethernet
   |- 1: http  Invoke: http_cb
   `- 2: tls x  Invoke: tls_cb  Data: ConnData

#![feature(prelude_import)]
extern crate std;
#[prelude_import]
use std::prelude::rust_2024::*;
use iris_compiler::*;
use iris_core::FiveTuple;
use iris_core::L4Pdu;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::Tracked;
use iris_core::{Runtime, config::default_config};
struct ConnData {
    ft: FiveTuple,
    proto: Option<SessionProto>,
}
#[automatically_derived]
impl ::core::fmt::Debug for ConnData {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "ConnData",
            "ft",
            &self.ft,
            "proto",
            &&self.proto,
        )
    }
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
    fn update(&mut self, pdu: &L4Pdu) {
        if !!pdu.ctxt.reassembled {
            ::core::panicking::panic("assertion failed: !pdu.ctxt.reassembled")
        }
        if let Some(proto) = &self.proto {
            if !#[allow(non_exhaustive_omitted_patterns)]
            match proto {
                SessionProto::Tls => true,
                _ => false,
            } {
                {
                    ::core::panicking::panic_fmt(
                        format_args!("Expected TLS, got {0:?} {1:?}", proto, self.ft),
                    );
                }
            }
        }
    }
    fn on_disc(&mut self, proto: &SessionProto) {
        self.proto = Some(proto.clone());
    }
}
fn tls_cb(conn: &ConnData) {
    if !#[allow(non_exhaustive_omitted_patterns)]
    match conn.proto {
        Some(SessionProto::Tls) => true,
        _ => false,
    } {
        {
            ::core::panicking::panic_fmt(
                format_args!("Expected TLS, got {0:?} {1:?}", conn.proto, conn.ft),
            );
        }
    }
}
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
    fn update(&mut self, _: &L4Pdu) {}
    fn on_disc(&mut self, proto: &SessionProto) {
        self.proto = Some(proto.clone());
    }
}
fn http_cb(conn: &ConnDataUntracked) {
    if !#[allow(non_exhaustive_omitted_patterns)]
    match conn.proto {
        Some(SessionProto::Http) => true,
        _ => false,
    } {
        {
            ::core::panicking::panic_fmt(
                format_args!("Expected HTTP, got {0:?} {1:?}", conn.proto, conn.ft),
            );
        }
    }
}
use iris_core::subscription::{Trackable, Subscribable};
use iris_core::conntrack::{TrackedActions, ConnInfo};
use iris_core::protocols::stream::ParserRegistry;
use iris_core::StateTransition;
use iris_core::subscription::*;
use iris_datatypes::*;
pub struct SubscribedWrapper;
impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
}
pub struct TrackedWrapper {
    packets: Vec<iris_core::Mbuf>,
    core_id: iris_core::CoreId,
    conndata: iris_core::subscription::data::TrackedDataWrapper<ConnData>,
    conndatauntracked: ConnDataUntracked,
}
impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;
    fn new(first_pkt: &iris_core::L4Pdu, core_id: iris_core::CoreId) -> Self {
        Self {
            packets: Vec::new(),
            core_id,
            conndata: iris_core::subscription::data::TrackedDataWrapper::<
                ConnData,
            >::new(first_pkt),
            conndatauntracked: ConnDataUntracked::new(first_pkt),
        }
    }
    fn packets(&self) -> &Vec<iris_core::Mbuf> {
        &self.packets
    }
    fn core_id(&self) -> &iris_core::CoreId {
        &self.core_id
    }
    fn parsers() -> ParserRegistry {
        ParserRegistry::from_strings(Vec::from(["http", "tls"]))
    }
    fn clear(&mut self) {
        self.packets.clear();
    }
}
pub fn filter() -> iris_core::filter::FilterFactory<TrackedWrapper> {
    fn packet_filter(mbuf: &iris_core::Mbuf, core_id: &iris_core::CoreId) -> bool {
        if let Ok(ethernet) = &iris_core::protocols::packet::Packet::parse_to::<
            iris_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            if let Ok(ipv4) = &iris_core::protocols::packet::Packet::parse_to::<
                iris_core::protocols::packet::ipv4::Ipv4,
            >(ethernet) {
                if let Ok(tcp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::tcp::Tcp,
                >(ipv4) {
                    return true;
                }
            } else if let Ok(ipv6) = &iris_core::protocols::packet::Packet::parse_to::<
                iris_core::protocols::packet::ipv6::Ipv6,
            >(ethernet) {
                if let Ok(tcp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::tcp::Tcp,
                >(ipv6) {
                    return true;
                }
            }
            return false;
        }
        false
    }
    fn state_tx(conn: &mut ConnInfo<TrackedWrapper>, tx: &iris_core::StateTransition) {
        match tx {
            StateTransition::L4FirstPacket => tx_l4firstpacket(conn, &tx),
            StateTransition::InL4Conn => tx_inl4conn(conn, &tx),
            StateTransition::L7OnDisc => tx_l7ondisc(conn, &tx),
            StateTransition::L4Terminated => tx_l4terminated(conn, &tx),
            _ => {}
        }
    }
    fn tx_l4firstpacket(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        conn.tracked.conndata.start_state_tx(&tx);
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if let Ok(ipv4) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::Ipv4CData,
        >(&conn.cdata) {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(13),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(13),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(13),
                        ],
                    },
                );
            layer0_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(2),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(2),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(2),
                        ],
                    },
                );
        } else if let Ok(ipv6) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::Ipv6CData,
        >(&conn.cdata) {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(13),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(13),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(13),
                        ],
                    },
                );
            layer0_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(2),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(2),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(2),
                        ],
                    },
                );
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
        conn.tracked.conndata.end_state_tx();
    }
    fn tx_inl4conn(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        conn.tracked.conndata.start_state_tx(&tx);
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if conn.layers[0].layer_info().state
            == iris_core::conntrack::LayerState::Discovery
        {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(4),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(4),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(4),
                        ],
                    },
                );
            layer0_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(2),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(2),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(2),
                        ],
                    },
                );
            conn.tracked.conndata.set_active_until(80u8);
        }
        if conn.layers[0].layer_info().state >= iris_core::conntrack::LayerState::Headers
        {
            if let iris_core::protocols::stream::SessionData::Http(http) = &conn
                .layers[0]
                .last_session()
                .data
            {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(9),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(9),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(9),
                            ],
                        },
                    );
            } else if let iris_core::protocols::stream::SessionData::Tls(tls) = &conn
                .layers[0]
                .last_session()
                .data
            {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(9),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(9),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(9),
                            ],
                        },
                    );
                conn.tracked.conndata.set_active_until(80u8);
            }
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
        conn.tracked.conndata.end_state_tx();
    }
    fn tx_l7ondisc(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        conn.tracked.conndata.start_state_tx(&tx);
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if conn.tracked.conndata.is_active() {
            conn.tracked.conndata.data.on_disc(&conn.layers[0].last_protocol());
        }
        conn.tracked.conndatauntracked.on_disc(&conn.layers[0].last_protocol());
        if #[allow(non_exhaustive_omitted_patterns)]
        match conn.layers[0].last_protocol() {
            iris_core::protocols::stream::SessionProto::Http => true,
            _ => false,
        } {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        } else if #[allow(non_exhaustive_omitted_patterns)]
        match conn.layers[0].last_protocol() {
            iris_core::protocols::stream::SessionProto::Tls => true,
            _ => false,
        } {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
            conn.tracked.conndata.set_active_until(64u8);
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
        conn.tracked.conndata.end_state_tx();
    }
    fn tx_l4terminated(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        conn.tracked.conndata.start_state_tx(&tx);
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if let iris_core::protocols::stream::SessionData::Http(http) = &conn
            .layers[0]
            .last_session()
            .data
        {
            http_cb(&conn.tracked.conndatauntracked);
        } else if let iris_core::protocols::stream::SessionData::Tls(tls) = &conn
            .layers[0]
            .last_session()
            .data
        {
            tls_cb(&conn.tracked.conndata.data);
            conn.tracked.conndata.set_active_until(0u8);
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
        conn.tracked.conndata.end_state_tx();
    }
    fn update(
        conn: &mut ConnInfo<TrackedWrapper>,
        pdu: &iris_core::L4Pdu,
        state: iris_core::StateTransition,
    ) -> bool {
        let mut ret = false;
        match state {
            StateTransition::InL4Conn => {
                if conn.tracked.conndata.is_active() {
                    conn.tracked.conndata.data.update(pdu);
                }
                conn.tracked.conndatauntracked.update(pdu);
            }
            _ => {}
        }
        ret
    }
    iris_core::filter::FilterFactory::new(
        "((ipv4) and (tcp)) or ((ipv6) and (tcp))",
        packet_filter,
        state_tx,
        update,
    )
}
fn main() {
    env_logger::init();
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
