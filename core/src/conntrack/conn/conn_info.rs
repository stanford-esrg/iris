// Consume_PDU [invoked on first pkt and UDP [in update], + via reassembled TCP]
// Update [invoked on non-first pkt]
// Must now store actions
// Terminate handler
// Probe, parse, etc.

use super::conn_actions::TrackedActions;
use crate::lcore::CoreId;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::stream::{ConnData, ParserRegistry};
use crate::subscription::{Subscription, Trackable};
use crate::FiveTuple;
use crate::L4Pdu;

use super::{conn_layers::*, conn_state::*};

/// Per-connection struct. Tracks all subscription-requested
/// datatypes (`tracked` data). Maintains the State of the connection
/// at each layer, including the `Actions` to execute when new
/// packets are received.
/// This must be public in order to be accessible by generated filter
/// and update code.
#[derive(Debug)]
pub struct ConnInfo<T>
where
    T: Trackable,
{
    /// Actions and state from the perspective of L4.
    /// Valid states are Payload or None.
    pub linfo: LayerInfo,
    /// Connection five-tuple for filtering and determining directionality
    /// of future packets.
    pub cdata: ConnData,
    /// Additional Layers that the L4 conn. should pass
    /// data to.
    pub layers: [Layer; NUM_LAYERS],
    /// Subscription data (for delivering)
    pub tracked: T,
}

impl<T> ConnInfo<T>
where
    T: Trackable,
{
    pub(super) fn new(pdu: &L4Pdu, core_id: CoreId) -> Self {
        let five_tuple = FiveTuple::from_ctxt(pdu.ctxt);
        ConnInfo {
            linfo: LayerInfo {
                state: if pdu.ctxt.proto == TCP_PROTOCOL {
                    LayerState::Headers // Pre-TCP handshake
                } else {
                    LayerState::Payload
                },
                actions: TrackedActions::new(),
            },
            cdata: ConnData::new(five_tuple),
            layers: [Layer::L7(L7Session::new())],
            tracked: T::new(pdu, core_id),
        }
    }

    /// Initializes actions at all layers when first packet
    /// in L4 connection is observed.
    pub(crate) fn filter_first_packet(&mut self, subscription: &Subscription<T::Subscribed>) {
        subscription.state_tx::<T>(self, &StateTransition::L4FirstPacket);
    }

    /// Update tracked data when new packet is observed.
    /// For TCP connections, this is invoked either pre-reassembly OR post-
    /// reassembly (not both). The L4Pdu will be marked with the `reassembled`
    /// flag if it has passed through the TCP reassembly module.
    pub(crate) fn new_packet(&mut self, pdu: &L4Pdu, subscription: &Subscription<T::Subscribed>) {
        if self.linfo.actions.needs_update() {
            if subscription.update(self, pdu, DataLevel::L4InPayload(pdu.ctxt.reassembled)) {
                self.exec_state_tx(
                    StateTransition::L4InPayload(pdu.ctxt.reassembled),
                    subscription,
                );
            }
        }
    }

    /// Invoked by reassembly infrastructure when the TCP handshake is completed.
    pub(super) fn handshake_done(&mut self, subscription: &Subscription<T::Subscribed>) {
        self.linfo.state = LayerState::Payload;
        self.exec_state_tx(StateTransition::L4EndHshk, subscription);
    }

    /// Invoked by transport layer to update data for encapsulated layers.
    /// This is invoked in reassembled order for TCP and received order for UDP.
    pub(crate) fn consume_stream(
        &mut self,
        pdu: &mut L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        // Pass to next layer(s) if applicable for parsing
        if self.layers[0].needs_stream() {
            let tx = self.layers[0].process_stream(pdu, registry);
            self.exec_state_tx(tx, subscription);
            if self.layers[0].needs_process(tx, pdu) {
                let tx = self.layers[0].process_stream(pdu, registry);
                self.exec_state_tx(tx, subscription);
            }
        }

        // Update if needed (can be in payload)
        if self.layers[0].layer_info().actions.needs_update() {
            for update in self.layers[0].needs_update_at(pdu) {
                if subscription.update(self, pdu, update) {
                    self.exec_state_tx(update, subscription);
                }
            }
        }

        // Update tracked data
        // This should happen after after stream processing so that `update`
        // functions see the most up-to-date connection data (e.g.,
        // parsed sessions).
        self.new_packet(pdu, subscription);
    }

    /// Drop the connection, e.g. due to timeout
    pub(crate) fn exec_drop(&mut self) {
        self.linfo.state = LayerState::None
    }

    /// Returns true if the connection should be dropped
    pub(crate) fn drop(&self) -> bool {
        self.linfo.state == LayerState::None
    }

    /// Invoked when the connection has terminated (by timeout or TCP FIN/ACK sequence)
    /// Delivers any "end of connection" data.
    pub(crate) fn handle_terminate(&mut self, subscription: &Subscription<T::Subscribed>) {
        while let Some(tx) = self.layers[0].handle_terminate() {
            self.exec_state_tx(tx, subscription);
        }
        self.exec_state_tx(StateTransition::L4Terminated, subscription);
    }

    /// Update subscription data and current state, including actions,
    /// upon state transition.
    fn exec_state_tx(&mut self, tx: StateTransition, subscription: &Subscription<T::Subscribed>) {
        if tx == StateTransition::Packet {
            return;
        }

        // Nothing to do at all layers
        if self.linfo.actions.skip_tx(&tx)
            && self
                .layers
                .iter()
                .all(|l| l.layer_info().actions.skip_tx(&tx))
        {
            return;
        }
        self.linfo.actions.start_state_tx(tx);
        for layer in self.layers.iter_mut() {
            layer.layer_info_mut().actions.start_state_tx(tx);
        }
        match tx {
            StateTransition::L7EndPayload => unimplemented!(),
            StateTransition::L4FirstPacket | StateTransition::Packet => {}
            _ => subscription.state_tx::<T>(self, &tx),
        }
        for layer in &mut self.layers {
            layer.end_state_tx();
        }
        if self.linfo.drop() && self.layers.iter().all(|l| l.drop()) {
            self.exec_drop();
        } else {
            if self.layers.iter().any(|l| !l.drop()) {
                self.linfo.actions.set_next_layer();
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.tracked.clear();
    }

    pub(crate) fn needs_reassembly(&self) -> bool {
        self.linfo.actions.needs_parse() || self.layers.iter().any(|l| l.needs_stream())
    }
}
