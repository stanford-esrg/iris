use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::{ConnInfo, ConnTracker, StateTransition};
use crate::filter::*;
use crate::lcore::CoreId;
use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use crate::protocols::stream::ParserRegistry;
use crate::stats::{StatExt, TCP_BYTE, TCP_PKT, UDP_BYTE, UDP_PKT};

pub mod data;
pub mod filter;
pub use data::FilterStr;
pub use data::Tracked;
pub use filter::StreamingFilter;
pub mod callback;
pub use callback::StreamingCallback;

#[cfg(feature = "timing")]
use crate::timing::timer::Timers;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterResult {
    Continue,
    Drop,
    Accept,
}

pub trait Subscribable {
    type Tracked: Trackable<Subscribed = Self>;
}

pub trait Trackable {
    type Subscribed: Subscribable<Tracked = Self>;

    /// Create a new struct for tracking connection data for user delivery
    fn new(first_pkt: &L4Pdu, core_id: CoreId) -> Self;

    /// Get reference to stored packets (those buffered for delivery)
    fn packets(&self) -> &Vec<Mbuf>;

    /// Return the core ID that this tracked conn. is on
    fn core_id(&self) -> &CoreId;

    /// Parsers needed by all datatypes
    /// Parsers needed by filter are generated on program startup
    fn parsers() -> ParserRegistry;

    /// Clear all internal data
    fn clear(&mut self);
}

pub struct Subscription<S>
where
    S: Subscribable,
{
    packet_filter: PacketFilterFn,
    state_tx_filter: StateTxFn<S::Tracked>,
    update_fn: UpdateFn<S::Tracked>,
    #[cfg(feature = "timing")]
    pub(crate) timers: Timers,
}

impl<S> Subscription<S>
where
    S: Subscribable,
{
    pub fn new(factory: FilterFactory<S::Tracked>) -> Self {
        Subscription {
            packet_filter: factory.packet_filter,
            state_tx_filter: factory.state_tx,
            update_fn: factory.update_fn,
            #[cfg(feature = "timing")]
            timers: Timers::new(),
        }
    }

    pub fn process_packet(&self, mbuf: Mbuf, conn_tracker: &mut ConnTracker<S::Tracked>) {
        if let Ok(ctxt) = L4Context::new(&mbuf) {
            match ctxt.proto {
                TCP_PROTOCOL => {
                    TCP_PKT.inc();
                    TCP_BYTE.inc_by(mbuf.data_len() as u64);
                }
                UDP_PROTOCOL => {
                    UDP_PKT.inc();
                    UDP_BYTE.inc_by(mbuf.data_len() as u64);
                }
                _ => {}
            }
            conn_tracker.process(mbuf, ctxt, self);
        }
    }
    /// Invokes the software packet filter.
    /// Used for each packet to determine
    /// forwarding to conn. tracker.
    ///
    /// NICE-TO-HAVE: we'd ideally have a configuration option that, at compile time,
    /// tells Iris to construct this initial packet filter using what the NIC supports.
    /// As it is, this packet filter is likely to apply filter predicates already applied in HW.
    /// (This needs to be a config option in case, e.g., we're compiling on a different machine.)
    pub fn filter_packet(&self, mbuf: &Mbuf, core_id: &CoreId) -> bool {
        (self.packet_filter)(mbuf, core_id)
    }

    /// Called on any StateTransition.
    /// Updates actions and invokes filters.
    ///
    /// Note: the only state TX for which pdu is not None is on first packet
    /// (the first packet in the connection is passed through).
    pub fn state_tx<T: Trackable>(
        &self,
        conn: &mut ConnInfo<S::Tracked>,
        tx: &StateTransition,
        pdu: Option<&L4Pdu>,
    ) {
        (self.state_tx_filter)(conn, tx, pdu)
    }

    /// Invoke "update" API, returning `true` if Actions may need
    /// to be refreshed (i.e., a subscription has gone out of scope).
    pub fn update(
        &self,
        conn: &mut ConnInfo<S::Tracked>,
        pdu: &L4Pdu,
        state: StateTransition,
    ) -> bool {
        (self.update_fn)(conn, pdu, state)
    }
}
