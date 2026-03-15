// Additional traffic layers built on top of the L4 base transport layer.

use super::conn_actions::TrackedActions;
use super::conn_state::{LayerState, StateTransition};
use crate::conntrack::Actions;
use crate::protocols::stream::{
    ConnParser, ParseResult, ParserRegistry, ParsingState, ProbeRegistryResult, SessionData,
    SessionProto,
};
use crate::protocols::Session;
use crate::L4Pdu;

lazy_static! {
    static ref DEFAULT_SESSION: Session = Session {
        data: SessionData::Null,
        id: 0,
    };
}

/// "Layers" that can be built on top of the transport layer (L4).
/// Each associated datatype must implement LayerInfo API (see below)
#[derive(Debug)]
pub enum Layer {
    /// L6/L7 Session
    L7(L7Session),
}
pub const NUM_LAYERS: usize = 1;

/// Convenience enum to be used at compile-time.
/// Should correspond to the transport layer plus `Layer` variants.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Ord, PartialOrd, Hash)]
#[repr(usize)]
pub enum SupportedLayer {
    L4,
    L7,
}

/// Trait implemented for each Layer variant
pub(crate) trait TrackableLayer {
    /// Ingest the next packet in the stream (reassembled, if TCP).
    /// Returns State transition(s) triggered.
    /// If multiple state transitions are triggered, the "Streaming" (InX)
    /// should be returned first. This will invoke methods on `T` based
    /// on the Layer and current State.
    fn process_stream(&mut self, pdu: &mut L4Pdu, registry: &ParserRegistry) -> StateTransition;

    /// Should be checked directly after a state transition to see
    /// if process_stream needs to be called again.
    /// For example, the packet used to "discover" a protocol will
    /// also be part of its header.
    fn needs_process(&self, tx: StateTransition, pdu: &L4Pdu) -> bool;

    /// No actions are active and, if applicable, no sub-layers have
    /// active actions.
    fn drop(&self) -> bool;

    /// "Consume_stream" must be called by the transport layer.
    /// TCP reassemly is expected if applicable.
    fn needs_stream(&self) -> bool;

    /// "State" that should be passed into an `update` function.
    /// May have two if the PDU includes data from, e.g., both header and payload.
    /// Should be called AFTER process_stream.
    fn needs_update_at(&self, pdu: &L4Pdu) -> [StateTransition; 2];

    /// Used to remove any actions that are invalid at this layer.
    /// For example: an L4 Update may trigger an L7 "parse" action, which
    /// would be invalid once in payload if another session is not expected.
    fn end_state_tx(&mut self);

    /// Indicate that the connection has terminated.
    /// Should be invoked repeatedly until it returns None
    fn handle_terminate(&mut self) -> Option<StateTransition>;
}

impl Layer {
    /// Accessors for LayerInfo
    pub fn layer_info_mut(&mut self) -> &mut LayerInfo {
        match self {
            Layer::L7(session) => &mut session.linfo,
        }
    }

    pub fn layer_info(&self) -> &LayerInfo {
        match self {
            Layer::L7(session) => &session.linfo,
        }
    }

    /// Push an action
    pub fn extend_actions(&mut self, action: &TrackedActions) {
        self.layer_info_mut().actions.extend(&action)
    }

    /// Accessors
    pub fn last_session(&self) -> &Session {
        match self {
            Layer::L7(session) => match session.sessions.last() {
                Some(s) => s,
                None => &DEFAULT_SESSION,
            },
        }
    }

    pub fn drain_sessions(&mut self) -> Vec<Session> {
        match self {
            Layer::L7(session) => session.parser.drain_sessions(),
        }
    }

    pub fn first_session(&self) -> &Session {
        match self {
            Layer::L7(session) => match session.sessions.first() {
                Some(s) => s,
                None => &DEFAULT_SESSION,
            },
        }
    }

    pub fn sessions(&self) -> &Vec<Session> {
        match self {
            Layer::L7(session) => &session.sessions,
        }
    }

    pub fn last_protocol(&self) -> SessionProto {
        match self {
            Layer::L7(session) => session.get_protocol(),
        }
    }
}

impl TrackableLayer for Layer {
    fn process_stream(&mut self, pdu: &mut L4Pdu, registry: &ParserRegistry) -> StateTransition {
        match self {
            Layer::L7(session) => session.process_stream(pdu, registry),
        }
    }

    fn needs_process(&self, tx: StateTransition, pdu: &L4Pdu) -> bool {
        match self {
            Layer::L7(session) => session.needs_process(tx, pdu),
        }
    }

    fn drop(&self) -> bool {
        match self {
            Layer::L7(session) => session.drop(),
        }
    }

    fn needs_stream(&self) -> bool {
        match self {
            Layer::L7(session) => session.needs_stream(),
        }
    }

    fn needs_update_at(&self, pdu: &L4Pdu) -> [StateTransition; 2] {
        match self {
            Layer::L7(session) => session.needs_update_at(pdu),
        }
    }

    fn end_state_tx(&mut self) {
        match self {
            Layer::L7(session) => session.end_state_tx(),
        }
    }

    fn handle_terminate(&mut self) -> Option<StateTransition> {
        match self {
            Layer::L7(session) => session.handle_terminate(),
        }
    }
}

/// Stored for each Layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerInfo {
    pub state: LayerState,
    pub actions: TrackedActions,
}

impl LayerInfo {
    pub fn new() -> Self {
        Self {
            state: LayerState::Discovery,
            actions: TrackedActions::new(),
        }
    }

    pub(crate) fn drop(&self) -> bool {
        self.state == LayerState::None || self.actions.drop()
    }
}

/// L6/L7 parsing infrastructure
#[derive(Debug)]
pub struct L7Session {
    /// Layer management
    pub linfo: LayerInfo,
    /// Stateful protocol parser (once identified, or None)
    pub parser: ConnParser,
    /// Parsed sessions, if applicable
    pub sessions: Vec<Session>,
    /// Sessions seen on terminate that are not fully parsed
    pub pending_sessions: Vec<Session>,
    // Further encapsulated layers could go here.
}

// TODO revisit visibility
impl L7Session {
    /// Initialize infrastructure for probing, parsing, and tracking
    /// L6/L7 (application-layer) sessions.
    pub fn new() -> Self {
        Self {
            linfo: LayerInfo::new(),
            parser: ConnParser::Unknown,
            sessions: Vec::new(),
            pending_sessions: Vec::new(),
        }
    }

    /// Accessor for Protocol
    pub fn get_protocol(&self) -> SessionProto {
        match self.linfo.state {
            LayerState::Discovery => SessionProto::Probing,
            _ => self.parser.protocol(),
        }
    }
}

impl TrackableLayer for L7Session {
    fn end_state_tx(&mut self) {
        // Nothing to parse if in payload and no more sessions expected
        if self.linfo.actions.needs_parse()
            && matches!(self.linfo.state, LayerState::Payload)
            && !matches!(
                self.parser.session_parsed_state(),
                ParsingState::Parsing | ParsingState::Probing
            )
        {
            self.linfo.actions.clear(&Actions::Parse);
        }
    }

    fn needs_process(&self, tx: StateTransition, pdu: &L4Pdu) -> bool {
        if self.linfo.state == LayerState::None {
            return false;
        }
        (tx == StateTransition::L7OnDisc && pdu.length() > 0)
            || (tx == StateTransition::L7EndHdrs && pdu.ctxt.app_offset.is_some())
    }

    fn drop(&self) -> bool {
        self.linfo.drop()
    }

    fn needs_stream(&self) -> bool {
        self.linfo.actions.needs_parse()
    }

    fn needs_update_at(&self, pdu: &L4Pdu) -> [StateTransition; 2] {
        match self.linfo.state {
            LayerState::None | LayerState::Discovery => [StateTransition::Packet; 2],
            LayerState::Headers => [StateTransition::L7InHdrs, StateTransition::Packet],
            LayerState::Payload => match pdu.app_body_offset() {
                Some(_) => [
                    StateTransition::L7InHdrs,
                    StateTransition::L7InPayload(false),
                ],
                None => [StateTransition::L7InPayload(false), StateTransition::Packet],
            },
        }
    }

    /// If some subscription is waiting for sessions, drain
    /// pending (not yet fully parsed) sessions from the parser.
    /// Move these sessions one-by-one to `self.sessions` until
    /// none are left. This should be invoked until it returns None.
    fn handle_terminate(&mut self) -> Option<StateTransition> {
        if !self.linfo.actions.needs_parse() {
            return None;
        }
        if matches!(self.linfo.state, LayerState::None | LayerState::Discovery) {
            return None;
        }
        if self.pending_sessions.is_empty() {
            self.pending_sessions = self.parser.drain_sessions();
        }
        if self.pending_sessions.is_empty() {
            return None;
        }
        self.sessions.push(self.pending_sessions.pop().unwrap());
        Some(StateTransition::L7EndHdrs)
        // L7EndPayload not yet supported
    }

    fn process_stream(&mut self, pdu: &mut L4Pdu, registry: &ParserRegistry) -> StateTransition {
        match self.linfo.state {
            LayerState::Discovery => {
                match registry.probe_all(pdu) {
                    ProbeRegistryResult::Some(conn_parser) => {
                        // Application-layer protocol known
                        self.parser = conn_parser;
                        self.linfo.state = LayerState::Headers;
                        return StateTransition::L7OnDisc;
                    }
                    ProbeRegistryResult::None => {
                        // All relevant parsers have failed to match
                        self.linfo.state = LayerState::None;
                        return StateTransition::L7OnDisc;
                    }
                    ProbeRegistryResult::Unsure => { /* skip */ }
                }
            }
            LayerState::Headers => {
                match self.parser.parse(pdu) {
                    ParseResult::HeadersDone(id) => {
                        if let Some(session) = self.parser.remove_session(id) {
                            self.sessions.push(session);
                        }
                        if let Some(offset) = self.parser.body_offset() {
                            pdu.ctxt.app_offset = Some(offset);
                        }
                        self.linfo.state = LayerState::Payload;
                        return StateTransition::L7EndHdrs;
                    }
                    ParseResult::None => {
                        self.linfo.state = LayerState::None;
                        return StateTransition::L7EndHdrs;
                    }
                    ParseResult::Done(id) => {
                        if let Some(session) = self.parser.remove_session(id) {
                            self.sessions.push(session);
                        }
                        self.linfo.state = LayerState::None;
                        return StateTransition::L7EndHdrs;
                    }
                    _ => { /* continue */ }
                }
            }
            LayerState::Payload => {
                pdu.ctxt.app_offset = Some(0);
                if self.linfo.actions.needs_parse() {
                    match self.parser.session_parsed_state() {
                        ParsingState::Probing => {
                            // TODO unimplemented: nested sessions
                        }
                        ParsingState::Parsing => {
                            // TODO unimplemented: pipelined sessions
                        }
                        _ => {}
                    }
                }
                // TODO - add API for parser to consume payload
                // if applicable and return when session is "done"
            }
            LayerState::None => {
                // Do nothing
            }
        }
        StateTransition::Packet
    }
}
