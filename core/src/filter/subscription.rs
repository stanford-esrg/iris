use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use crate::conntrack::conn::conn_layers::{SupportedLayer, NUM_LAYERS};
use crate::conntrack::conn::conn_state::StateTxOrd;
use crate::conntrack::{Actions, DataLevel, LayerState, StateTransition, TrackedActions};

use super::ast::Predicate;
use super::pattern::FlatPattern;

/// The Actions to be tracked for any subset of subscription components
/// at a filter layer if some filter pattern matches (fully or partially).
///
/// The complete set of Actions for a Subscription at a PNode must be built up
/// by adding datatypes, filter predicates, and callback levels using the
/// NodeActions (see below). The NodeActions support (1) different actions
/// for different layer states and (2) APIs for adding the `refresh_at`
/// components of actions.
///
/// **One of these must be built for every filter pattern
///   (i.e., root-to-node path) due to potential differences in
///   filter predicate needs.**
///
/// TODO ideally we'd use the LayerState predicate type more effectively.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct DataActions {
    /// Optional conditional: these actions are only applied if layer is in
    /// one of the listed states.
    pub if_matches: Option<(SupportedLayer, LayerState)>,
    /// Tracked Actions at the transport layer
    pub transport: TrackedActions,
    /// Tracked Actions at encapsulated layers
    pub layers: [TrackedActions; NUM_LAYERS],
}

impl std::fmt::Display for DataActions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut pref = "";
        if let Some(if_matches) = self.if_matches {
            write!(f, "{:?}:{:?}", if_matches.0, if_matches.1)?;
            pref = "- ";
        }
        write!(f, "{}L4: {} ", pref, self.transport)?;
        write!(f, "{}L7: {}", pref, self.layers[0])?;
        Ok(())
    }
}

impl DataActions {
    pub(crate) fn new() -> Self {
        DataActions {
            if_matches: None,
            transport: TrackedActions::new(),
            layers: [TrackedActions::new(); NUM_LAYERS],
        }
    }

    pub(crate) fn merge(&mut self, peer: &DataActions) {
        self.transport.extend(&peer.transport);
        self.layers[0].extend(&peer.layers[0]);
    }

    pub fn drop(&self) -> bool {
        self.transport.drop() && self.layers[0].drop()
    }

    /// Clear the actions that intersect with `peer`
    pub(crate) fn clear_intersection(&mut self, peer: &DataActions) {
        if self.if_matches != peer.if_matches {
            return;
        }
        self.transport.clear_intersection(&peer.transport);
        self.layers[0].clear_intersection(&peer.layers[0]);
    }

    // Get the actions associated with a matching `pred`.
    pub(crate) fn from_stream_pred(
        pred: &Predicate,
        next_preds: Vec<StateTransition>,
        filter_layer: StateTransition,
        curr_state_pred: &Option<Predicate>,
    ) -> DataActions {
        if let Predicate::Custom {
            name,
            levels,
            matched,
        } = pred
        {
            assert!(!*matched);
            let spec = DataLevelSpec {
                updates: levels.into_iter().cloned().flatten().collect(),
                name: name.clone().0,
            };
            let actions = spec.to_actions(filter_layer);
            let curr_state = match curr_state_pred {
                Some(p) => match p {
                    Predicate::LayerState { layer, state, .. } => Some((*layer, *state)),
                    _ => panic!("State predicate is {}", p),
                },
                None => None,
            };
            for mut a in actions.actions {
                if a.if_matches == curr_state {
                    for p in next_preds {
                        a.transport.refresh_at[p.as_usize()] |= a.transport.active;
                        a.layers[0].refresh_at[p.as_usize()] |= a.layers[0].active;
                    }
                    return a;
                }
            }
            return DataActions::new();
        }
        panic!("From_stream_pred called on {:?}", pred);
    }

    // --PSEUDOCODE-- for what the actual code will look like
    // \TODO - this means that Predicate::LayerState won't be required
    // pub(crate) fn to_tokens(&self) -> proc_macro2::TokenStream {
    //     let l7_idx = SupportedLayer::L7 as usize - 1;
    //     // Insert check for state if applicable.
    //     // TODO - maybe these should be extracted into PTree nodes instead
    //     let mut conditional = quote! {};
    //     if let Some((layer, states)) = &self.if_matches {
    //         let linfo = match layer {
    //             SupportedLayer::L4 => quote! { conn_info.linfo },
    //             SupportedLayer::L7 => quote! { conn_info.layers[#l7_idx] },
    //         };
    //         conditional = quote! {
    //             if conn_info.layers[#l7_idx] == #state
    //         };
    //         for idx in 1..states.len() {
    //             let state = states[idx].to_tokens();
    //             conditional = quote! {#conditional || #linfo.state == #state };
    //         }
    //     }
    //     // Body: code to update working list of actions
    //     let mut body = quote! {};
    //     if !self.transport.drop() {
    //         let actions = self.transport.to_tokens();
    //         body = quote! {
    //             conn_info.linfo.actions.update(#actions);
    //         };
    //     }
    //     if !self.layers[l7_idx].drop() {
    //         let actions = self.layers[l7_idx].to_tokens();
    //         body = quote! {
    //             #body
    //             conn_info.layers[#l7_idx].actions.update(#actions);
    //         };
    //     }
    //
    //     quote! {
    //         #conditional {
    //             #body
    //         }
    //     }
    // }
}

/// Actions for a single subscription that will be stored at a node in a PTree.
/// This must be built up by first adding `datatypes` and custom filters and then
/// adding `next predicates` or `streaming callbacks` to determine when the node's
/// actions could potentially be updated.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeActions {
    /// Essentially, there will be multiple elements here if there are different
    /// branches depending on some layer's state.
    /// TODO shouldn't need this in future - use LayerState pred.
    pub actions: Vec<DataActions>,
    /// Set to `true` the first time a filter predicate or streaming callback level
    /// is added to ensure that no further datatypes are added afterwards.
    pub(crate) end_datatypes: bool,
    /// The state transition PTree that this Node is part of.
    pub(crate) filter_layer: StateTransition,
}

impl std::fmt::Display for NodeActions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for d in &self.actions {
            write!(f, "{}", d)?;
        }
        Ok(())
    }
}

impl NodeActions {
    pub(crate) fn new(filter_layer: StateTransition) -> Self {
        Self {
            actions: vec![],
            end_datatypes: false,
            filter_layer,
        }
    }

    /// Add `new` to `actions` by either:
    /// - Appending it, or
    /// - Updating an existing action that has the same preconditions
    pub(crate) fn push_action(&mut self, new: DataActions) {
        let curr = self
            .actions
            .iter_mut()
            .find(|a| (**a).if_matches == new.if_matches);
        match curr {
            Some(curr) => {
                curr.transport.extend(&new.transport);
                curr.layers[0].extend(&new.layers[0]);
            }
            None => self.actions.push(new),
        }
    }

    /// Update actions with an additional datatype.
    pub(crate) fn add_datatype(&mut self, spec: &DataLevelSpec) {
        assert!(
            !self.end_datatypes,
            "Cannot add new datatypes after adding filter predicates."
        );
        let actions = spec.to_actions(self.filter_layer);
        for a in actions.actions {
            self.push_action(a);
        }
    }

    /// Must be added after full NodeActions for a specific subscription has been built up,
    /// including the datatypes required for filters.
    /// Updates Actions to be "refreshed" at the next layer where new relevant information
    /// might be available (i.e., next filter predicate can be evaluated).
    pub(crate) fn push_filter_pred(&mut self, next_pred: &StateTransition) {
        self.end_datatypes = true;
        for a in self.actions.iter_mut() {
            a.transport.refresh_at[next_pred.as_usize()] |= a.transport.active;
            a.layers[0].refresh_at[next_pred.as_usize()] |= a.layers[0].active;
        }
    }

    /// Manually indicate that we're done adding new data
    pub(crate) fn end_datatypes(&mut self) {
        self.end_datatypes = true;
    }

    /// Must be added after full subscription spec has been built up with all datatypes,
    /// including the datatypes required for filters.
    /// `level` should indicate the level at which the callback could unsubscribe.
    /// Updates subscription Actions to be "refreshed" at this point.
    pub(crate) fn push_cb(&mut self, level: StateTransition) {
        self.push_filter_pred(&level);
    }

    /// Merge two NodeActions together.
    /// This is typically needed when a Node already has actions
    /// accumulated and another subscription (sub-)pattern terminates
    /// at the node.
    #[allow(dead_code)]
    pub(crate) fn merge(&mut self, peer: &NodeActions) {
        assert!(
            self.end_datatypes && peer.end_datatypes || self.actions.len() == 0,
            "SELF: {}\nPEER: {}",
            self,
            peer
        );
        assert!(self.filter_layer == peer.filter_layer);
        for a in &peer.actions {
            self.push_action(a.clone());
        }
        self.end_datatypes = true;
    }

    /// Returns `true` if no actions
    #[allow(dead_code)]
    pub(crate) fn drop(&self) -> bool {
        self.actions.len() == 0 || self.actions.iter().all(|a| a.transport.drop())
    }
}

/// Compile-time struct for representing a datatype required for a callback
/// or custom filter predicate.
/// Might also be used to represent a stateful custom filter predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataLevelSpec {
    /// Updates: streaming updates and state transitions requested.
    pub updates: Vec<DataLevel>,
    /// The name of the datatype as a string
    pub name: String,
}

impl DataLevelSpec {
    /// From a filter predicate
    pub(crate) fn from_pred(pred: &Predicate) -> Option<Self> {
        // Predicates that have already matched don't need add'l actions
        if pred.is_custom() && !pred.is_matching() {
            return None;
        }
        Some(Self {
            updates: pred.levels().clone(),
            name: format!("{}", pred),
        })
    }

    /// For a given filter layer (state transition), return the actions that the
    /// datatype requires.
    ///
    /// Example: A TLS handshake requires a "headers parsed" state TX. We must generate
    /// the actions that will allow that state transition to execute. The
    /// framework must (1) 'pass through' at the transport layer (to L7) and (2) parse
    /// at L7, and it must continue doing this _until_ the L7 headers are parsed or
    /// we fail to identify the protocol.
    /// If the filter layer is guaranteed to execute before the end
    /// of the L7 headers, then we can proceed with these actions. If the layer is
    /// guaranteed to execute after the end of the L7 headers, we should do nothing.
    /// If the layers are not comparable (may happen in any order), then the actions
    /// taken depend on the L7 state.
    pub(crate) fn to_actions(&self, filter_layer: StateTransition) -> NodeActions {
        let mut actions = NodeActions::new(filter_layer);
        if filter_layer == StateTransition::L4Terminated {
            return actions;
        }
        let l7_idx = SupportedLayer::L7 as usize - 1;
        for level in &self.updates {
            let cmp = filter_layer.compare(level);
            let mut a = DataActions::new();
            match level {
                DataLevel::L4FirstPacket => {
                    // Nothing required.
                    // Datatype can be delivered or cached on first packet filter.
                    continue;
                }
                DataLevel::L4EndHshk => {
                    match cmp {
                        StateTxOrd::Less | StateTxOrd::Unknown => {
                            // Detecting the handshake requires invoking reassembly
                            a.transport.active |= Actions::Parse;
                            // ...until the handshake has been parsed
                            a.transport.refresh_at[level.as_usize()] |= Actions::Parse;
                            // Only if pre-handshake
                            if matches!(cmp, StateTxOrd::Unknown) {
                                a.if_matches = Some((SupportedLayer::L4, LayerState::Headers));
                            }
                            actions.push_action(a);
                        }
                        _ => continue,
                    }
                }
                DataLevel::L4InPayload(reassembled) => {
                    // "In" suggests an update is required
                    // InPayload datatype by itself can't "unsubscribe"
                    a.transport.active |= Actions::Update;
                    if *reassembled {
                        // Require reassembly if requested
                        a.transport.active |= Actions::Parse;
                    }
                    actions.push_action(a);
                }
                DataLevel::L7OnDisc => {
                    match cmp {
                        StateTxOrd::Equal | StateTxOrd::Greater | StateTxOrd::Any => continue,
                        StateTxOrd::Less | StateTxOrd::Unknown => {
                            // Must pass to subsequent layer.
                            // Note this will implicitly reassemble.
                            a.transport.active |= Actions::PassThrough;
                            a.transport.refresh_at[level.as_usize()] |= Actions::PassThrough;
                            // "Parse" at L7 in order to identify protocol, until protocol identified
                            // (or all protocols ruled out).
                            a.layers[l7_idx].active |= Actions::Parse;
                            a.layers[l7_idx].refresh_at[level.as_usize()] |= Actions::Parse;
                            if matches!(cmp, StateTxOrd::Unknown) {
                                a.if_matches = Some((SupportedLayer::L7, LayerState::Discovery));
                            }
                            actions.push_action(a);
                        }
                    }
                }
                DataLevel::L7InHdrs => {
                    match cmp {
                        StateTxOrd::Greater | StateTxOrd::Any => continue,
                        StateTxOrd::Equal | StateTxOrd::Less | StateTxOrd::Unknown => {
                            // Must pass to L7 and parse
                            // - If before protocol discovery: to get to start of L7 headers
                            // - If at or in headers: to update and (eventually) identify end of headers
                            a.transport.active |= Actions::PassThrough;
                            a.transport.refresh_at[DataLevel::L7EndHdrs.as_usize()] |=
                                Actions::PassThrough;
                            // Parse to get to end of headers
                            if matches!(cmp, StateTxOrd::Less | StateTxOrd::Equal) {
                                a.layers[l7_idx].active |= Actions::Parse;
                                a.layers[l7_idx].refresh_at
                                    [StateTransition::L7EndHdrs.as_usize()] |= Actions::Parse;
                            }
                            // Update at start of and in headers
                            if matches!(
                                filter_layer,
                                StateTransition::L7OnDisc | StateTransition::L7InHdrs
                            ) {
                                a.layers[l7_idx].active |= Actions::Update;
                                a.layers[l7_idx].refresh_at
                                    [StateTransition::L7EndHdrs.as_usize()] |= Actions::Update;
                            }
                            if matches!(cmp, StateTxOrd::Unknown) {
                                a.if_matches = Some((SupportedLayer::L7, LayerState::Headers));
                            }
                            actions.push_action(a);
                        }
                    }
                }
                DataLevel::L7EndHdrs => match cmp {
                    StateTxOrd::Equal | StateTxOrd::Greater | StateTxOrd::Any => continue,
                    StateTxOrd::Less | StateTxOrd::Unknown => {
                        a.transport.active |= Actions::PassThrough;
                        a.transport.refresh_at[level.as_usize()] |= Actions::PassThrough;
                        a.layers[l7_idx].active |= Actions::Parse;
                        a.layers[l7_idx].refresh_at[level.as_usize()] |= Actions::Parse;
                        if matches!(cmp, StateTxOrd::Unknown) {
                            // Differentiate between L7 Disc, Headers
                            a.if_matches = Some((SupportedLayer::L7, LayerState::Discovery));
                            actions.push_action(a.clone());
                            a.if_matches = Some((SupportedLayer::L7, LayerState::Headers));
                        }
                        actions.push_action(a);
                    }
                },
                DataLevel::L7InPayload(reassembled) => {
                    if matches!(cmp, StateTxOrd::Greater | StateTxOrd::Any) {
                        continue;
                    }

                    // Case 1: at beginning of or in payload.
                    let mut in_payload = DataActions::new();
                    in_payload.transport.active |= Actions::PassThrough;
                    in_payload.layers[l7_idx].active |= Actions::Update;
                    if *reassembled {
                        in_payload.layers[l7_idx].active |= Actions::Parse;
                    }

                    // Case 2: before end of L7 headers.
                    let mut pre_payload = DataActions::new();
                    pre_payload.transport.active |= Actions::PassThrough;
                    pre_payload.transport.refresh_at[StateTransition::L7EndHdrs.as_usize()] |=
                        Actions::PassThrough;
                    pre_payload.layers[l7_idx].active |= Actions::Parse;
                    pre_payload.layers[l7_idx].refresh_at[StateTransition::L7EndHdrs.as_usize()] |=
                        Actions::Parse;

                    // Beginning of or in payload: update
                    if cmp == StateTxOrd::Equal || filter_layer == StateTransition::L7EndHdrs {
                        actions.push_action(in_payload);
                    }
                    // Pre-payload (L7OnDisc, InHdrs)
                    else if cmp == StateTxOrd::Less {
                        actions.push_action(pre_payload);
                    }
                    // Different layer: depends on L7 state
                    else if cmp == StateTxOrd::Unknown {
                        pre_payload.if_matches = Some((SupportedLayer::L7, LayerState::Discovery));
                        actions.push_action(pre_payload.clone());
                        pre_payload.if_matches = Some((SupportedLayer::L7, LayerState::Headers));
                        actions.push_action(pre_payload);
                        in_payload.if_matches = Some((SupportedLayer::L7, LayerState::Payload));
                        actions.push_action(in_payload);
                    }
                }
                DataLevel::L7EndPayload => {
                    // L7 payload parsing not yet implemented. Use L4Terminated instead.
                    unimplemented!();
                }
                DataLevel::L4Terminated => {
                    let mut a = DataActions::new();
                    a.transport.active |= Actions::Track;
                    a.transport.refresh_at[level.as_usize()];
                    actions.push_action(a);
                }
                // No actions
                DataLevel::Packet => continue,
            }
        }
        actions
    }
}

/// Structure representing a single callback function.
///
/// If a subscription specifies multiple callback functions (i.e.,
/// on a struct), one of these must be created for each function.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CallbackSpec {
    /// If the callback explicitly specifies when to be invoked
    pub expl_level: Option<DataLevel>,
    /// Datatype inputs to the callback
    pub datatypes: Vec<DataLevelSpec>,
    /// This callback cannot be optimized out.
    /// Typically true if ``FilterStr`` (i.e., information
    /// about the specific filter matched) is a parameter.
    pub must_deliver: bool,
    /// The framework must track when it has invoked this callback
    /// in order to ensure it is invoked at most once.
    /// Typically required if the associated filter includes a
    /// streaming predicate but the callback is stateless
    /// and not streaming.
    pub invoke_once: bool,
    /// The name of the callback function (excluding parameters).
    /// Also excludes the struct for stateful callbacks, if applicable.
    pub as_str: String,
    /// Subscription string representation
    /// This should be the name of the callback struct (for stateful CBs)
    /// or the name of the callback function for ungrouped CBs.
    pub subscription_id: String,
    /// "Expensive" tracked datatypes (by name)
    /// Used to indicate that a tree should track the match state of the
    /// datatype in order to `clear` it if it goes out of scope.
    /// This may limit filter optimizations.
    pub tracked_data: Vec<String>,
}

impl Hash for CallbackSpec {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str.hash(state);
        self.subscription_id.hash(state);
    }
}

impl CallbackSpec {
    pub(super) fn get_datatypes(&self) -> Vec<DataLevelSpec> {
        let mut datatypes: Vec<_> = self.datatypes.iter().cloned().collect();
        if let Some(expl_level) = self.expl_level {
            // Requires streaming `updates` or the level cannot be
            // inferred from the datatype alone
            datatypes.push(DataLevelSpec {
                updates: vec![expl_level],
                name: self.as_str.clone(),
            });
        }
        datatypes
    }

    pub fn is_streaming(&self) -> bool {
        match self.expl_level {
            Some(l) => l.is_streaming(),
            None => false,
        }
    }

    pub fn is_grouped(&self) -> bool {
        self.as_str != self.subscription_id
    }
}

#[doc(hidden)]
/// Utility for tracking, for a subscription pattern*, the Levels needed to
/// correctly apply (1) all filter predicates, (2) all datatype updates,
/// and (3), if applicable, updates to a streaming callback.
///
/// *For each subscription, one of these structs is needed for each end-to-end
/// filter pattern (i.e., root-to-leaf predicate tree path).
#[derive(Debug, Clone)]
pub struct SubscriptionLevel {
    /// Levels at which datatype updates need to happen
    pub datatypes: HashSet<DataLevel>,
    /// Levels at which a new filter predicate needs to be applied
    pub filter_preds: HashSet<DataLevel>,
    /// If the callback explicitly requests to be delivered at a level
    pub callback: Option<DataLevel>,
}

impl SubscriptionLevel {
    pub fn new(data: &Vec<DataLevelSpec>, preds: &FlatPattern, cb: Option<DataLevel>) -> Self {
        let mut ret = Self::empty();
        for d in data {
            ret.add_datatype(d);
        }
        for p in &preds.predicates {
            ret.add_filter_pred(&p.levels());
        }
        ret.add_callback(cb);
        ret
    }

    /// Can the callback be invoked or CB timer started at `curr` state tx?
    /// Delivery can kick off if the current state transition is
    /// _not less than_ any of the predicates and it is _equal_ to at least one
    /// of the predicates (i.e., this may be the first state TX where the "not less than"
    /// bound is true). This must be true for all filter and datatype predicates.
    pub fn can_deliver(&self, curr: &StateTransition) -> bool {
        // Only deliver callback at explicitly-specified level.
        // Note that the connection tracker invokes `update` AFTER
        // parsing and applying state transitions. For example, an `L4InPayload`
        // update will be invoked after an `L7OnDisc` state transition, if the
        // same PDU triggers both.
        // - TODO this could change if we add an `update` before reassembly.
        if let Some(expl_level) = &self.callback {
            // E.g., L4OnTerminated, L4FirstPacket
            if !expl_level.is_streaming() {
                return curr == expl_level;
            }
            // Streaming callbacks will be delivered in `update` and only
            // need to be delivered here if this is the first time they CAN
            // be delivered (the corresponding `update` would have already passed).
        }
        // Create iterator over all filter and datatype predicates
        let mut iter = self.datatypes.iter().chain(self.filter_preds.iter());
        iter.clone()
            .all(|l| !matches!(curr.compare(l), StateTxOrd::Less))
            && iter.any(|l| curr.compare(l) == StateTxOrd::Equal)
    }

    /// Can the pattern of predicates be skipped at this state transition layer?
    /// That is, is this subscription guaranteed to have terminated at a level
    /// that is strictly less than (before) the current level?
    pub fn can_skip(&self, curr: &StateTransition) -> bool {
        let cb_done = match self.callback {
            Some(cb) => curr.compare(&cb) == StateTxOrd::Greater,
            None => false,
        };
        // All datatype and filter predicate levels are strictly less than `curr`
        cb_done
            && self
                .datatypes
                .iter()
                .chain(self.filter_preds.iter())
                .all(|l| curr.compare(l) == StateTxOrd::Greater)
    }

    /// -- utilities for iteratively building up a spec --

    pub(crate) fn empty() -> Self {
        Self {
            datatypes: HashSet::new(),
            filter_preds: HashSet::new(),
            callback: None,
        }
    }

    /// Add the Level of the streaming callback (e.g., "In L4 payload")
    pub(crate) fn add_callback(&mut self, level: Option<DataLevel>) {
        self.callback = level;
    }

    /// Add a datatype requested in a callback
    pub(crate) fn add_datatype(&mut self, data: &DataLevelSpec) {
        for d in &data.updates {
            self.datatypes.insert(*d);
        }
    }

    /// Add a filter predicate
    pub(crate) fn add_filter_pred(&mut self, pred: &Vec<DataLevel>) {
        for d in pred {
            self.filter_preds.insert(*d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    lazy_static::lazy_static!(
        // L7 headers, e.g., TLS handshake, HTTP headers, DNS txn
        static ref l7_header: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L7EndHdrs],
            name: "l7_header".into(),
        };
        // L7 headers with a customized fingerprint that requires
        // analyzing payload metadata.
        static ref l7_fingerprint: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L4InPayload(false), DataLevel::L7EndHdrs],
            name: "l7_fingerprint".into(),
        };
        // Basic connection metadata, delivered at end of connection
        static ref conn_data: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L4InPayload(false), DataLevel::L4Terminated],
            name: "conn_data".into(),
        };
        // Basic connection metadata, delivered in streaming fashion.
        // Also requests update when handshake completes.
        static ref conn_streamdata: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L4InPayload(false), DataLevel::L4EndHshk],
            name: "conn_streamdata".into(),
        };
    );

    // Actions for session header (e.g., TLS handshake)
    #[test]
    fn core_data_actions_l7() {
        // Initial state: should parse until end of headers
        let actions = l7_header.to_actions(StateTransition::L4FirstPacket).actions;
        assert!(actions.len() == 1);
        assert!(actions[0].if_matches == None);
        assert!(actions[0].transport.has_next_layer() && actions[0].layers[0].needs_parse());
        for tx in StateTransition::iter() {
            if matches!(tx, StateTransition::L7EndHdrs) {
                assert!(
                    actions[0].transport.refresh_at[tx.as_usize()] != 0,
                    "{:?} has value: {:?}",
                    tx,
                    actions[0].transport.refresh_at[tx.as_usize()]
                );
            } else if tx != StateTransition::Packet {
                assert!(
                    actions[0].transport.refresh_at[tx.as_usize()] == 0,
                    "{:?} has value: {:?}",
                    tx,
                    actions[0].transport.refresh_at[tx.as_usize()]
                );
            }
        }
        // Everything should be dropped after headers
        let actions = l7_header.to_actions(StateTransition::L7EndHdrs).actions;
        assert!(actions.len() == 0);
    }

    // Actions for datatype that requires both L4 and L7 data
    #[test]
    fn core_data_actions_l7_l4() {
        // Initial state: pre-payload
        let actions = l7_fingerprint
            .to_actions(StateTransition::L4FirstPacket)
            .actions;
        assert!(actions.len() == 1);
        assert!(actions[0].transport.has_next_layer() && actions[0].transport.needs_update());
        for tx in StateTransition::iter() {
            // At end of headers, expect DataLevel::L7EndHdrs done.
            if tx == StateTransition::L7EndHdrs {
                assert!(
                    actions[0].transport.refresh_at[tx.as_usize()] == Actions::PassThrough,
                    "{:?} has value: {:?}",
                    tx,
                    actions[0].transport.refresh_at[tx.as_usize()]
                );
            } else if tx != StateTransition::Packet {
                assert!(
                    actions[0].transport.refresh_at[tx.as_usize()] == 0,
                    "{:?} has value: {:?}",
                    tx,
                    actions[0].transport.refresh_at[tx.as_usize()]
                );
            }
        }

        // Ambiguous: may be pre- or post-payload
        let actions = l7_fingerprint
            .to_actions(StateTransition::L4InPayload(false))
            .actions;
        // Added "nodes" for LayerState checks: L7 disc, headers, payload
        assert!(actions.len() == 3);
        assert!(actions[0].if_matches.is_some() || actions[1].if_matches.is_some());
    }

    #[test]
    fn core_sub_actions() {
        let mut node = NodeActions::new(StateTransition::L4FirstPacket);
        node.add_datatype(&l7_header);
        node.add_datatype(&conn_data);
        // Expecting: no StateTransition conditionals
        assert!(node.actions.len() == 1);
        // Expecting: Update and Track (connection-level subscription), parse (L7 Headers)
        assert!(
            node.actions[0].transport.active
                == Actions::Update | Actions::PassThrough | Actions::Track
        );

        // Add in (e.g.) "tls" filter
        node.push_filter_pred(&StateTransition::L7OnDisc);
        assert!(
            node.actions[0].transport.refresh_at[StateTransition::L7OnDisc.as_usize()]
                == Actions::Update | Actions::PassThrough | Actions::Track
        );
        // Indicate that this will be in a streaming callback
        node.push_cb(StateTransition::L4InPayload(false));
        assert!(
            node.actions[0].transport.refresh_at[StateTransition::L4InPayload(false).as_usize()]
                == Actions::Update | Actions::PassThrough | Actions::Track
        );
    }
}
