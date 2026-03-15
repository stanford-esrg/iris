use core::fmt;
use std::cmp::{Ordering, PartialOrd};
use std::collections::HashSet;

use crate::conntrack::{DataLevel, StateTransition};
use crate::filter::subscription::DataActions;

use super::{
    ast::{Predicate, ProtocolName},
    pattern::FlatPattern,
    subscription::{CallbackSpec, NodeActions, SubscriptionLevel},
};

// A node representing a predicate in the tree
#[derive(Debug, Clone)]
pub struct PNode {
    // Predicate represented by this PNode
    pub pred: Predicate,

    // Child PNodes
    pub children: Vec<PNode>,

    // Predicate is mutually exclusive with the
    // predicate in the node preceding it in child list
    pub if_else: bool,

    // `Actions` struct for this node.
    pub actions: DataActions,

    // Subscriptions that can be invoked at this node.
    // That is, all for which `can_deliver` on its `SubscriptionLevel``
    // returned true.
    pub deliver: HashSet<CallbackSpec>,

    // Extra tracker of subscriptions that need timers started
    // (i.e., set_active) at this node, but cannot yet be invoked.
    // That is, a pattern has terminally matched for a streaming
    // subscription.
    // TODO this is a temporary workaround. In the future, we should
    // have a different method for CBs in this state
    // vs. just "try_set_active" (e.g., "try_set_matched"?).
    // We should only set_active (and the accompanying actions)
    // for callbacks that are actually ready to be delivered
    pub matched: HashSet<CallbackSpec>,

    // Datatypes that remain "in scope" at this node
    // Only tracked for "expensive" datatypes
    // TODO - this is currently dead code - not implemented yet
    pub datatypes: HashSet<String>,

    // Identifier
    pub id: usize,
}

impl PNode {
    fn new(pred: Predicate, id: usize) -> Self {
        PNode {
            pred,
            children: vec![],
            if_else: false,
            actions: DataActions::new(),
            deliver: HashSet::new(),
            matched: HashSet::new(),
            datatypes: HashSet::new(),
            id,
        }
    }

    /// -- Utilities for comparing predicates when inserting nodes -- //

    // Utility to check whether a descendant exists
    // Helper for `get_descendant`, which must be invoked in an `if` block
    // due to borrow checker
    fn has_descendant(&self, pred: &Predicate, state: &Option<Predicate>) -> bool {
        if &self.pred == pred {
            return true;
        }
        for n in &self.children {
            if n.pred.is_state() && Some(&n.pred) != state.as_ref() {
                return false;
            }
            if n.pred.is_callback() && &n.pred != pred {
                // Stop at callbacks
                return false;
            }
            if &n.pred == pred {
                return true;
            }
            if pred.is_child(&n.pred) && n.has_descendant(pred, state) {
                return true;
            }
        }
        false
    }

    // See above
    fn get_descendant(&mut self, pred: &Predicate) -> Option<&mut PNode> {
        if &self.pred == pred {
            return Some(self);
        }
        for n in &mut self.children {
            // found exact match
            if &n.pred == pred {
                return Some(n);
            }
            // node is a parent - keep descending
            if pred.is_child(&n.pred) {
                if let Some(c) = n.get_descendant(pred) {
                    return Some(c);
                }
            }
        }
        None
    }

    // Returns true if `self` has `pred` as a direct child
    fn has_child(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| &n.pred == pred)
    }

    // See above
    fn get_child(&mut self, pred: &Predicate) -> &mut PNode {
        self.children.iter_mut().find(|n| &n.pred == pred).unwrap()
    }

    // True if `self` has children that should be (more specific)
    // children of `pred`
    fn has_children_of(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| n.pred.is_child(pred))
    }

    // Returns all of the PNodes that should be children of `pred`,
    // while retaining in `self.children` the nodes that are
    // not children of `pred`
    fn get_children_of(&mut self, pred: &Predicate) -> Vec<PNode> {
        let new;
        let children = std::mem::take(&mut self.children);

        (new, self.children) = children.into_iter().partition(|p| p.pred.is_child(pred));

        new
    }

    // Returns a reference to a PNode that is a child of `self`
    // that can act as "parent" of `pred`.
    fn get_parent_candidate(&mut self, pred: &Predicate) -> Option<&mut PNode> {
        self.children.iter_mut().find(|n| pred.is_child(&n.pred))
    }

    // Returns true if (1) both `self` and `peer` have equal node-to-leaf paths
    // and (2) actions/CB/tracked datatypes are the same.
    // This is useful for marking nodes as mutually exclusive even
    // if there predicates are not mutually exclusive.
    fn outcome_eq(&self, peer: &PNode) -> bool {
        if self != peer {
            return false;
        }
        (self.children.is_empty() && peer.children.is_empty()) || self.all_paths_eq(peer)
    }

    // True if there is a PNode that can act as parent of `pred`.
    fn has_parent(&self, pred: &Predicate) -> bool {
        for n in &self.children {
            if pred.is_child(&n.pred) {
                return true;
            }
        }
        false
    }

    // Returns a node that can act as a parent to `pred`, or None.
    // The most "narrow" parent condition will be returned if multiple exist.
    fn get_parent(
        &mut self,
        pred: &Predicate,
        tree_size: usize,
        state: &Option<Predicate>,
    ) -> Option<&mut PNode> {
        // This is messy, but directly iterating through children or
        // recursing will raise flags with the borrow checker.
        let mut node = self;
        for _ in 0..tree_size {
            // Stop traversing if hit a state dependency
            if node.pred.is_state() && (state.is_none() || Some(&node.pred) != state.as_ref()) {
                return None;
            }
            // Checked for `Some` on last iteration
            let next = node.get_parent_candidate(pred)?;
            if next.get_parent_candidate(pred).is_none() {
                // `next` is the last possible parent at this stage
                return Some(next);
            } else {
                // There are more potential parents
                node = next;
            }
        }
        None
    }

    // Returns `true` if a condition cannot be removed from the filter due to
    // its role extracting data needed for a subsequent condition.
    // For example, getting `ipv4` is necessary for checking `ipv4.src_addr`.
    fn extracts_protocol(&self, filter_layer: DataLevel) -> bool {
        // Filters that parse raw packets are special case
        // Need upper layers to extract inner from mbuf
        // E.g.: need ipv4 header to parse tcp
        if matches!(filter_layer, DataLevel::L4FirstPacket)
            && self.pred.is_unary()
            && self.children.iter().any(|n| n.pred.is_unary())
        {
            return true;
        }
        self.pred.is_unary()
            && self
                .children
                .iter()
                .any(|n| self.pred.get_protocol() == n.pred.get_protocol() && n.pred.is_binary())
    }

    fn has_op(&self) -> bool {
        !self.actions.drop()
            || !self.deliver.is_empty()
            || !self.matched.is_empty()
            || !self.datatypes.is_empty()
    }

    // Populates `paths` with all root-to-leaf paths originating
    // at node `self`.
    fn get_paths(&self, curr_path: &mut Vec<String>, paths: &mut Vec<String>) {
        if self.children.is_empty() && !curr_path.is_empty() {
            paths.push(curr_path.join(","));
        } else {
            for c in &self.children {
                curr_path.push(format!("{}", c));
                c.get_paths(curr_path, paths);
            }
        }
        curr_path.pop();
    }

    // Returns true if all root-to-leaf paths originating at `self`
    // are the same as all root-to-leaf paths originating at `other`.
    // This is applied to determine if two nodes have the same outcome
    // (subsequent conditions, actions, delivery) if predicate is `true`.
    fn all_paths_eq(&self, other: &PNode) -> bool {
        if self.children.is_empty() && other.children.is_empty() {
            return true;
        }
        let mut paths = vec![];
        let mut curr = vec![];
        self.get_paths(&mut curr, &mut paths);
        let mut peer_paths = vec![];
        curr = vec![];
        other.get_paths(&mut curr, &mut peer_paths);
        peer_paths == paths
    }
}

impl fmt::Display for PNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pred)?;
        if !self.actions.drop() {
            write!(f, " -- Actions: {}", self.actions)?;
        }
        if !self.deliver.is_empty() {
            write!(f, " Invoke: ")?;
            write!(f, "( ")?;
            for d in &self.deliver {
                write!(f, "{}, ", d.as_str)?;
            }
            write!(f, ")")?;
        }
        if !self.matched.is_empty() {
            write!(f, " Active: ")?;
            write!(f, "( ")?;
            for m in &self.matched {
                write!(f, "{}, ", m.as_str)?;
            }
            write!(f, ")")?;
        }
        if !self.datatypes.is_empty() {
            write!(f, " Data: ")?;
            write!(f, "( ")?;
            for d in &self.datatypes {
                write!(f, "{}", d)?;
            }
            write!(f, ")")?;
        }
        if self.if_else {
            write!(f, " x")?;
        }
        Ok(())
    }
}

// Compares the contents of the nodes, ignoring children
// To consider children, use outcome_eq
impl PartialEq for PNode {
    fn eq(&self, other: &PNode) -> bool {
        self.pred == other.pred
            && self.actions == other.actions
            && self.deliver == other.deliver
            && self.matched == other.matched
            && self.datatypes == other.datatypes
    }
}

impl Eq for PNode {}

impl PartialOrd for PNode {
    fn partial_cmp(&self, other: &PNode) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Used for ordering nodes by protocol and field
// Does NOT consider contents of the node
impl Ord for PNode {
    fn cmp(&self, other: &PNode) -> Ordering {
        if let Predicate::Binary {
            protocol: proto,
            field: field_name,
            op: _op,
            value: _val,
        } = &self.pred
        {
            if let Predicate::Binary {
                protocol: peer_proto,
                field: peer_field_name,
                op: _peer_op,
                value: _peer_val,
            } = &other.pred
            {
                // Same protocol; sort fields
                if proto == peer_proto {
                    return field_name.name().cmp(peer_field_name.name());
                }
            }
        }

        // If either has a protocol name, sort by that
        // This also will put all ProtocolName::none predicates
        // (i.e., LayerState or user-defined) next to each other
        if self.pred.get_protocol() != ProtocolName::none()
            || other.pred.get_protocol() != ProtocolName::none()
        {
            return self
                .pred
                .get_protocol()
                .name()
                .cmp(other.pred.get_protocol().name());
        }

        // Both predicates are custom filters, callbacks, or state checks;
        // compare their string representations
        format!("{}", self.pred).cmp(&format!("{}", other.pred))
    }
}

// A n-ary tree representing a Filter.
// Paths from root to leaf represent a pattern for data to match.
// Filter returns action(s) or delivers data.
#[derive(Debug, Clone)]
pub struct PTree {
    // Root node
    pub root: PNode,

    // Number of nodes in tree
    pub size: usize,

    // Which filter this PTree represents
    pub filter_layer: StateTransition,

    // Has `collapse` been applied?
    // Use to ensure no filters are applied after `collapse`
    collapsed: bool,

    // All actions, callbacks, tracked datatypes across all nodes in the tree
    pub actions: NodeActions,
    pub deliver: HashSet<CallbackSpec>,
    pub matched: HashSet<CallbackSpec>,
    pub datatypes: HashSet<String>,
}

impl PTree {
    pub fn new_empty(filter_layer: StateTransition) -> Self {
        Self {
            root: PNode::new(Predicate::default_pred(), 0),
            size: 1,
            filter_layer,
            collapsed: false,
            actions: NodeActions::new(filter_layer),
            deliver: HashSet::new(),
            matched: HashSet::new(),
            datatypes: HashSet::new(),
        }
    }

    pub fn add_subscription(
        &mut self,
        // Filter patterns
        patterns: &[FlatPattern],
        // Individual callbacks; each has datatypes
        callbacks: &Vec<CallbackSpec>,
        // String identifier
        id: &String,
    ) {
        if self.collapsed {
            panic!("Cannot add filter to tree after collapsing");
        }
        assert!(
            patterns.len() > 0 || patterns.iter().all(|p| p.predicates.is_empty()),
            "Empty filter pattern must have default predicate."
        );
        log::trace!("{}: Adding subscription with id: {}", self.filter_layer, id);
        if patterns.is_empty() {
            self.add_pattern(
                &FlatPattern {
                    predicates: vec![Predicate::default_pred()],
                },
                callbacks,
                id,
            );
            return;
        }

        let ext_patterns = self.split_custom(patterns);
        for pattern in patterns.iter().chain(ext_patterns.iter()) {
            self.add_pattern(pattern, callbacks, id);
        }
    }

    // Add patterns for non-terminal matches on streaming filters
    // TODO may not always need this (if no correctness issues?)
    fn split_custom(&self, patterns: &[FlatPattern]) -> Vec<FlatPattern> {
        let mut split_patterns = vec![];
        if matches!(self.filter_layer, StateTransition::L4Terminated) {
            return split_patterns;
        }
        for pattern in patterns {
            split_patterns.extend(pattern.split_custom());
        }
        split_patterns
    }

    fn add_pattern(
        &mut self,
        pattern_: &FlatPattern,
        callbacks: &Vec<CallbackSpec>,
        cb_id: &String,
    ) {
        let mut pattern = pattern_;

        // Pattern may have predicates that need to be annotated with
        // L7 State checks (e.g., only check TLS if L7 >= Headers)
        let mut pattern_tmp;
        if self.filter_layer.is_streaming() && self.filter_layer.in_transport() {
            pattern_tmp = pattern.with_l7_state();
            pattern = &pattern_tmp;
        }
        // Extend with callback predicates if this callback will be stateful
        // (multiple functions or streaming).
        // If a subscription previously had the opportunity to unsubscribe,
        // we need to check if it did
        if !matches!(
            self.filter_layer,
            StateTransition::L4FirstPacket | StateTransition::L4Terminated
        ) && (callbacks.len() > 1
            || callbacks.iter().any(|c| match c.expl_level {
                Some(l) => l.is_streaming(),
                None => false,
            }))
        {
            pattern_tmp = pattern.with_streaming_cb(cb_id);
            pattern = &pattern_tmp;
        }

        // Extract required datatypes in filter pattern
        let mut datatypes = pattern.get_datatypes();
        // Add datatypes required by callbacks
        for callback in callbacks {
            datatypes.extend(callback.get_datatypes().into_iter());
        }
        // Construct node actions
        let mut node_actions = NodeActions::new(self.filter_layer);
        // Actions required for all datatypes (including filters)
        for spec in &datatypes {
            node_actions.add_datatype(spec);
        }
        // Update `refresh_at` based on where next filter predicate(s)
        // may be applied.
        node_actions.end_datatypes();
        for next_pred in pattern.next_pred(self.filter_layer) {
            node_actions.push_filter_pred(&next_pred);
        }

        // Allow callback to `unsubscribe`
        for callback in callbacks {
            if let Some(cb_level) = &callback.expl_level {
                node_actions.push_cb(*cb_level);
            }
        }

        let contains_nonterminal = pattern.contains_nonterminal();
        let mut full_pattern_added = false;

        // Add dependencies separately
        for action in &node_actions.actions {
            let mut pattern_ref = pattern;
            let subpattern: FlatPattern;
            let mut truncated = contains_nonterminal;

            // Need to insert this as a unique pattern with the relevant L7 state checks
            if let Some(if_matches) = action.if_matches {
                subpattern = pattern.get_subpattern(if_matches.0, if_matches.1);
                // Subpattern should have added a predicate (L7 state check)
                truncated = truncated || subpattern.predicates.len() < pattern.predicates.len() + 1;
                pattern_ref = &subpattern;
            }

            // If all patterns get (retroactively) truncated, we'll need to
            // make sure (at the end) that callbacks are delivered if possible.
            full_pattern_added |= !truncated;

            // Add pattern for each callback
            for callback in callbacks {
                self.add_pattern_int(pattern_ref, action, callback, truncated);
            }
        }
        if !contains_nonterminal && (!full_pattern_added || node_actions.actions.is_empty()) {
            for callback in callbacks {
                let level =
                    SubscriptionLevel::new(&callback.datatypes, pattern, callback.expl_level);
                if level.can_deliver(&self.filter_layer) {
                    self.add_pattern_int(
                        pattern,
                        &DataActions::new(),
                        callback,
                        contains_nonterminal,
                    );
                }
            }
        }
    }

    fn add_pattern_int(
        &mut self,
        full_pattern: &FlatPattern,
        actions: &DataActions,
        callback: &CallbackSpec,
        // `full_pattern` was truncated
        mut truncated: bool,
    ) {
        let level = SubscriptionLevel::new(&callback.datatypes, full_pattern, callback.expl_level);
        if level.can_skip(&self.filter_layer) {
            return;
        }
        let mut state_pred = None;

        let pattern = FlatPattern {
            predicates: full_pattern
                .predicates
                .iter()
                .filter(|p| !p.is_next_layer(self.filter_layer))
                .cloned()
                .collect(),
        };
        assert!(pattern.predicates.len() <= full_pattern.predicates.len());
        if pattern.predicates.len() < full_pattern.predicates.len() {
            assert!(
                !level.can_deliver(&self.filter_layer),
                "Ensure that {} explicit level {:?} is compatible with filter string {}",
                callback.as_str,
                callback.expl_level,
                full_pattern
            );
            truncated = true;
        }

        log::trace!(
            "{}: Adding pattern {} with actions {} and callback {}",
            self.filter_layer,
            pattern,
            actions,
            callback.as_str
        );

        let mut node = &mut self.root;
        for predicate in pattern.predicates.iter() {
            // Case 1: Predicate is already present
            if node.has_descendant(predicate, &state_pred) {
                node = node.get_descendant(predicate).unwrap();
                continue;
            }
            // Case 2: Predicate should be added as child of existing node
            if node.has_parent(predicate) {
                node = node.get_parent(predicate, self.size, &state_pred).unwrap();
            }
            // Case 3: Children of curr node should be children of new node
            let children = match node.has_children_of(predicate) {
                true => node.get_children_of(predicate),
                false => {
                    vec![]
                }
            };
            // Create new node
            if !node.has_child(predicate) {
                node.children.push(PNode::new(predicate.clone(), self.size));
                self.size += 1;
            }
            // Move on, pushing any new children if applicable
            node = node.get_child(predicate);
            node.children.extend(children);

            // Maintain streaming filter if still `matching` regardless of
            // later predicate state
            // TODO do we need this?
            // TODO avoid additional lookups
            if node.pred.is_custom() && node.pred.is_matching() {
                node.actions.merge(&DataActions::from_stream_pred(
                    &node.pred,
                    full_pattern.next_pred(self.filter_layer),
                    self.filter_layer,
                    &state_pred,
                ));
            }

            if node.pred.is_state() {
                // Used to determine when we can/can't "skip ahead"
                // TODO may not need this - may just be able to stop traversing in opts if
                // any state pred is hit
                state_pred = Some(node.pred.clone());
            }
        }
        if !truncated && level.can_deliver(&self.filter_layer) {
            node.deliver.insert(callback.clone());
            self.deliver.insert(callback.clone());
        } else if !truncated
            && (callback.is_streaming() || callback.is_grouped())
            && pattern.is_first_match(&self.filter_layer)
        {
            // Can't deliver, but this might be the first time this pattern
            // has matched, so we need to mark the callback as active
            node.matched.insert(callback.clone());
            self.matched.insert(callback.clone());
        }
        node.actions.merge(actions);
        node.datatypes.extend(callback.tracked_data.iter().cloned());
        self.actions.push_action(actions.clone());
        self.datatypes.extend(callback.tracked_data.iter().cloned());
    }

    // modified from https://vallentin.dev/2019/05/14/pretty-print-tree
    fn pprint(&self) -> String {
        fn pprint(s: &mut String, node: &PNode, prefix: String, last: bool) {
            let prefix_current = if last { "`- " } else { "|- " };

            let s_next = format!("{}{}{}: {}\n", prefix, prefix_current, node.id, node);
            s.push_str(&s_next);

            let prefix_child = if last { "   " } else { "|  " };
            let prefix = prefix + prefix_child;

            if !node.children.is_empty() {
                let last_child = node.children.len() - 1;

                for (i, child) in node.children.iter().enumerate() {
                    pprint(s, child, prefix.to_string(), i == last_child);
                }
            }
        }

        let mut s = String::new();
        pprint(&mut s, &self.root, "".to_string(), true);
        s
    }

    // Returns a copy of the subtree rooted at Node `id`
    pub fn get_subtree(&self, id: usize) -> Option<PNode> {
        fn get_subtree(id: usize, node: &PNode) -> Option<PNode> {
            if node.id == id {
                return Some(node.clone());
            }
            for child in node.children.iter() {
                if let Some(node) = get_subtree(id, child) {
                    return Some(node);
                }
            }
            None
        }
        get_subtree(id, &self.root)
    }

    fn contains_term_filters(&self) -> bool {
        fn contains_term_filters(node: &PNode) -> bool {
            if node
                .pred
                .levels()
                .iter()
                .any(|l| matches!(l, DataLevel::L4Terminated))
            {
                return true;
            }
            node.children.iter().any(|c| contains_term_filters(c))
        }
        contains_term_filters(&self.root)
    }

    // Sorts the PTree according to predicates
    // Useful as a pre-step for marking mutual exclusion; places
    // conditions with the same protocols/fields next to each other.
    fn sort(&mut self) {
        fn sort(node: &mut PNode) {
            for child in node.children.iter_mut() {
                sort(child);
            }
            node.children.sort();
        }
        sort(&mut self.root);
    }

    // Best-effort to give the filter generator hints as to where an "else"
    // statement can go between two predicates. That is, if branches A and B
    // are mutually exclusive, we want the runtime to take at most one of them.
    fn mark_mutual_exclusion(&mut self) {
        fn mark_mutual_exclusion(node: &mut PNode) {
            for idx in 0..node.children.len() {
                // Recurse for children/descendants
                mark_mutual_exclusion(&mut node.children[idx]);
                if idx == 0 {
                    continue;
                }
                // Look for mutually exclusive predicates in direct children
                if node.children[idx]
                    .pred
                    .is_excl(&node.children[idx - 1].pred)
                {
                    node.children[idx].if_else = true;
                }
                // If the result is equivalent (e.g., same actions)
                // for child nodes, then we can safely use first match.
                // (Similar to "early return.")
                if node.children[idx].outcome_eq(&node.children[idx - 1]) {
                    node.children[idx].if_else = true;
                }
            }
        }
        mark_mutual_exclusion(&mut self.root);
    }

    // After collapsing the tree, make sure node IDs and sizes are correct.
    fn update_size(&mut self) {
        fn count_nodes(node: &mut PNode, id: &mut usize) -> usize {
            node.id = *id;
            *id += 1;
            let mut count = 1;
            for child in &mut node.children {
                count += count_nodes(child, id);
            }
            count
        }
        let mut id = 0;
        self.size = count_nodes(&mut self.root, &mut id);
    }

    // Removes some patterns that are covered by others
    fn prune_branches(&mut self) {
        fn prune(
            node: &mut PNode,
            on_path_actions: &DataActions,
            on_path_deliver: &HashSet<String>,
            on_path_matched: &HashSet<String>,
        ) {
            // 1. Remove callbacks that would have already been invoked on this path
            let mut my_deliver = on_path_deliver.clone();
            let mut new_ids = HashSet::new();
            for i in &node.deliver {
                if !my_deliver.contains(&i.as_str) {
                    my_deliver.insert(i.as_str.clone());
                    new_ids.insert(i.clone());
                } else if i.must_deliver {
                    new_ids.insert(i.clone());
                }
            }
            node.deliver = new_ids;

            // 2. Do the same for actions
            let mut my_actions = on_path_actions.clone();
            if !node.actions.drop() {
                node.actions.clear_intersection(&my_actions);
                my_actions.merge(&node.actions);
            }

            // 3. Do the same for callbacks that need to be marked `matched`
            let mut my_matched = on_path_matched.clone();
            let mut new_ids = HashSet::new();
            for i in &node.matched {
                if !my_matched.contains(&i.as_str) {
                    my_matched.insert(i.as_str.clone());
                    new_ids.insert(i.clone());
                }
            }
            node.matched = new_ids;

            // 4. Repeat for each child
            node.children
                .iter_mut()
                .for_each(|child| prune(child, &my_actions, &my_deliver, &my_matched));

            // 5. Remove empty children
            let children = std::mem::take(&mut node.children);
            node.children = children
                .into_iter()
                .filter(|child| child.has_op() || !child.children.is_empty())
                .collect();
        }

        let on_path_actions = DataActions::new();
        let on_path_deliver = HashSet::new();
        let on_path_matched = HashSet::new();
        prune(
            &mut self.root,
            &on_path_actions,
            &on_path_deliver,
            &on_path_matched,
        );
    }

    // Avoid re-checking packet-level conditions that, on the basis of previous
    // filters, are guaranteed to be already met.
    // For example, if all subscriptions filter for "tcp", then all non-tcp
    // connections will have been filtered out at the PacketContinue layer.
    // We only do this for packet-level conditions, as connection-level
    // conditions are needed to extract sessions.
    fn prune_packet_conditions(&mut self) {
        fn prune_packet_conditions(node: &mut PNode, filter_layer: DataLevel, can_prune: bool) {
            if !node.pred.on_packet() {
                return;
            }
            // Can only safely remove children if
            // current branches are mutually exclusive
            let can_prune_next = node
                .children
                .windows(2)
                .all(|w| w[0].pred.is_excl(&w[1].pred));
            for child in &mut node.children {
                prune_packet_conditions(child, filter_layer, can_prune_next);
            }
            if !can_prune {
                return;
            }
            // Tree layer is only drop/keep (i.e., one condition),
            // and condition checked at prev. layer
            while node.children.len() == 1 && node.children[0].pred.on_packet() {
                // If the protocol needs to be extracted, can't remove node
                // Look for unary predicate (e.g., `ipv4`) and child with
                // binary predicate of same protocol (e.g., `ipv4.addr = ...`)
                let child = &mut node.children[0];
                if child.extracts_protocol(filter_layer)
                    || child.pred.is_state()
                    || child.pred.is_callback()
                {
                    break;
                }
                node.actions.merge(&child.actions);
                node.deliver.extend(child.deliver.iter().cloned());
                node.matched.extend(child.matched.iter().cloned());
                node.children = std::mem::take(&mut child.children);
            }
        }

        let can_prune_next = self
            .root
            .children
            .windows(2)
            .all(|w| w[0].pred.is_excl(&w[1].pred));
        prune_packet_conditions(&mut self.root, self.filter_layer, can_prune_next);
    }

    // Avoid applying conditions that (1) are not needed for filtering *out*
    // (i.e., would have already been checked by prev layer), and (2) end in
    // the same result.
    // Example: two different IP addresses in a packet filter followed by
    // a TCP/UDP disambiguation.
    fn prune_redundant_branches(&mut self) {
        fn prune_redundant_branches(node: &mut PNode, filter_layer: DataLevel, can_prune: bool) {
            if !node.pred.is_prev_layer(filter_layer) {
                return;
            }

            // Can only safely remove children if
            // current branches are mutually exclusive
            let can_prune_next = node
                .children
                .windows(2)
                .all(|w| w[0].pred.is_excl(&w[1].pred));

            for child in &mut node.children {
                prune_redundant_branches(child, filter_layer, can_prune_next);
            }
            if !can_prune {
                return;
            }

            let (must_keep, could_drop): (Vec<PNode>, Vec<PNode>) =
                node.children.iter().cloned().partition(|child| {
                    child.has_op()
                        || !child.pred.is_prev_layer(filter_layer)
                        || child.extracts_protocol(filter_layer)
                        || child.pred.is_state()
                });
            let mut new_children = vec![];
            for child in &could_drop {
                // Can "upgrade" descendants if all children in a layer
                // have the same descendant conditions.
                if node.children.iter().all(|c| child.all_paths_eq(c)) {
                    new_children.extend(child.children.clone());
                } else {
                    new_children.push(child.clone());
                }
            }

            new_children.extend(must_keep);
            new_children.sort();
            new_children.dedup();
            node.children = new_children;
        }
        let can_prune_next = self
            .root
            .children
            .windows(2)
            .all(|w| w[0].pred.is_excl(&w[1].pred));
        prune_redundant_branches(&mut self.root, self.filter_layer, can_prune_next);
    }

    // Apply all filter tree optimizations.
    // This must only be invoked AFTER the tree is completely built.
    pub fn collapse(&mut self) {
        if matches!(self.filter_layer, DataLevel::L4Terminated) {
            self.collapsed = true;
            // Shouldn't have another filter stage here unless there may
            // be something to deliver
            assert!(self.deliver.len() >= 1);

            // The delivery filter will only be invoked if a previous filter
            // determined that delivery is needed at the corresponding stage.
            // If disambiguation is not needed (i.e., only one possible delivery
            // outcome), then no filter condition is needed.
            // The exception is if there is a filter that we still need to apply.
            // --> TODO can we relax this requirement?
            if self.deliver.len() == 1 {
                if !self.contains_term_filters() {
                    self.root
                        .deliver
                        .insert(self.deliver.iter().next().unwrap().clone());
                    self.root.children.clear();
                    self.update_size();
                    return;
                }
            }
        }
        self.prune_redundant_branches();
        self.prune_packet_conditions();
        self.prune_branches();
        self.sort();
        self.mark_mutual_exclusion(); // Must be last
        self.update_size();
    }
}

impl fmt::Display for PTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tree {:?}\n,{}", &self.filter_layer, self.pprint())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{conntrack::Actions, filter::subscription::DataLevelSpec, filter::Filter};

    use super::*;

    lazy_static! {

        static ref TLS_DATATYPE: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L7EndHdrs],
            name: "TlsHandshake".into(),
        };

        // fn basic_tls(tls: &TlsHandshake) { ... }
        static ref TLS_SUB: Vec<CallbackSpec> = vec![CallbackSpec {
            expl_level: None,
            datatypes: vec![TLS_DATATYPE.clone()],
            must_deliver: false,
            invoke_once: false,
            as_str: "basic_tls".into(),
            subscription_id: String::new(),
            tracked_data: vec![],
        }];
    }

    #[test]
    fn test_ptree_basic() {
        let filter = Filter::new("tls", &vec![]).unwrap();
        let patterns = filter.get_patterns_flat();

        let mut tree = PTree::new_empty(DataLevel::L4FirstPacket);
        // On first packet: set up parsing
        tree.add_subscription(&patterns, &TLS_SUB, &TLS_SUB[0].as_str);
        assert!(tree.size == 5, "Tree size is: {}", tree.size);
        let node = tree.get_subtree(2).unwrap();
        assert!(!node.actions.drop());
        assert!(node.actions.transport.has_next_layer());
        assert!(
            node.actions.transport.refresh_at[DataLevel::L7OnDisc.as_usize()]
                == Actions::PassThrough
        );
        assert!(node.actions.layers[0].needs_parse());
        assert!(
            node.actions.layers[0].refresh_at[DataLevel::L7OnDisc.as_usize()] == Actions::Parse
        );

        // On protocol discovery: continue parsing until end of headers
        let mut tree = PTree::new_empty(DataLevel::L7OnDisc);
        tree.add_subscription(&patterns, &TLS_SUB, &TLS_SUB[0].as_str);
        assert!(tree.size == 7); // + 2 TLS nodes
        let node = tree.get_subtree(3).unwrap(); // TLS node
        assert!(
            node.actions.transport.refresh_at[DataLevel::L7EndHdrs.as_usize()]
                == Actions::PassThrough
        );

        // Inlined delivery
        let mut tree = PTree::new_empty(DataLevel::L7EndHdrs);
        tree.add_subscription(&patterns, &TLS_SUB, &TLS_SUB[0].as_str);
        assert!(tree.size == 7);
        let node = tree.get_subtree(3).unwrap();
        assert!(node.actions.drop());
        assert!(node.deliver.len() == 1);

        // "Maintenance"
        let mut tree = PTree::new_empty(DataLevel::L4InPayload(false));
        tree.add_subscription(&patterns, &TLS_SUB, &TLS_SUB[0].as_str);
        // eth
        // -> ipv4 -> tcp
        // --> L7=Disc{actions}
        // --> L7>=Headers -> tls -> L7=Headers{actions}
        // -> ipv6 ...
        assert!(tree.size == 13);
        let node = tree.get_subtree(3).unwrap(); // L7=Discovery
        assert!(matches!(node.pred, Predicate::LayerState { .. }));
        let node = tree.get_subtree(5).unwrap(); // tls
        assert!(node.pred.get_protocol() == &protocol!("tls"));

        // Nothing to do
        let mut tree = PTree::new_empty(DataLevel::L7InPayload(false));
        tree.add_subscription(&patterns, &TLS_SUB, &TLS_SUB[0].as_str);
        assert!(tree.size == 1); // Just root; no actions
    }

    lazy_static! {
        static ref CUSTOM_FILTERS: Vec<Predicate> = vec![Predicate::Custom {
            name: filterfunc!("my_filter"),
            levels: vec![vec![DataLevel::L4InPayload(false)]],
            matched: true,
        }];
        static ref SESS_RECORD_DATATYPE: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L4InPayload(false), DataLevel::L7EndHdrs],
            name: "ConnAndSession".into(),
        };
        static ref STREAMING_SUB: Vec<CallbackSpec> = vec![CallbackSpec {
            expl_level: Some(DataLevel::L4InPayload(false)),
            datatypes: vec![TLS_DATATYPE.clone(), SESS_RECORD_DATATYPE.clone()],
            must_deliver: false,
            invoke_once: false,
            as_str: "basic_streaming".into(),
            subscription_id: String::new(),
            tracked_data: vec![],
        }];
    }

    #[test]
    fn test_with_streaming() {
        let filter = Filter::new("tls and my_filter", &CUSTOM_FILTERS).unwrap();
        let patterns = filter.get_patterns_flat();

        // On first packet: set up parsing, streaming
        // Refresh at: L4InPayload (my_filter) and L7OnDisc ("tls")
        let mut tree = PTree::new_empty(DataLevel::L4FirstPacket);
        tree.add_subscription(&patterns, &STREAMING_SUB, &STREAMING_SUB[0].as_str);
        let node = tree.get_subtree(2).unwrap(); // "tcp" node
        assert!(node.actions.transport.active == Actions::PassThrough | Actions::Update);
        let l7_actions = &node.actions.layers[0];
        assert!(
            l7_actions.refresh_at[DataLevel::L4InPayload(false).as_usize()] == Actions::Parse
                && l7_actions.refresh_at[DataLevel::L7OnDisc.as_usize()] == Actions::Parse
        );

        // On L7 Headers Parsed
        // Done with TLS filter and with parsing TLS handshake
        let mut tree = PTree::new_empty(DataLevel::L7EndHdrs);
        tree.add_subscription(&patterns, &STREAMING_SUB, &STREAMING_SUB[0].as_str);
        // println!("{}", tree);
        // Note - splits out my_filter (matched) and (matching)
        // Adds node(s) to re-check the CB
        assert!(tree.size == 15);
        let node = tree.get_subtree(5).unwrap(); // callback node
        assert!(node.actions.transport.needs_update() && !node.actions.transport.has_next_layer());
    }

    lazy_static! {
        static ref FIVETUPLE_DATATYPE: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L4FirstPacket],
            name: "FiveTuple".into(),
        };
        static ref FIVETUPLE_SUB: Vec<CallbackSpec> = vec![CallbackSpec {
            expl_level: None,
            datatypes: vec![FIVETUPLE_DATATYPE.clone()],
            must_deliver: false,
            invoke_once: false,
            as_str: "basic_static".into(),
            subscription_id: String::new(),
            tracked_data: vec![],
        }];
    }

    #[test]
    fn test_multi() {
        let filter = Filter::new("tls", &vec![]).unwrap();
        let patterns_1 = filter.get_patterns_flat();
        let filter = Filter::new("tls and my_filter", &CUSTOM_FILTERS).unwrap();
        let patterns_2: Vec<FlatPattern> = filter.get_patterns_flat();
        let filter = Filter::new("ipv4 and tcp.port = 80", &vec![]).unwrap();
        let patterns_3 = filter.get_patterns_flat();

        // - First packet: check optimizations
        let mut tree = PTree::new_empty(DataLevel::L4FirstPacket);
        tree.add_subscription(&patterns_1, &TLS_SUB, &TLS_SUB[0].as_str);
        tree.add_subscription(&patterns_2, &STREAMING_SUB, &STREAMING_SUB[0].as_str);
        println!("{}", tree);
        assert!(tree.size == 5);
        let mut collapsed_tree = tree.clone();
        collapsed_tree.collapse();
        // "tcp" optimized out - `tcp` would have been filtered out at initial packet filter
        assert!(collapsed_tree.size == 3);

        tree.add_subscription(&patterns_3, &FIVETUPLE_SUB, &FIVETUPLE_SUB[0].as_str);
        let mut collapsed_tree = tree.clone();
        collapsed_tree.collapse();
        // Can't optimize tcp anymore for ipv4, but still can for ipv6
        assert!(
            collapsed_tree.size == 6,
            "Actual value: {}",
            collapsed_tree.size
        );
    }

    #[test]
    fn test_ptree_parse() {
        let filter = Filter::new("ipv4 and tls and my_filter", &CUSTOM_FILTERS).unwrap();
        let patterns = filter.get_patterns_flat();

        let mut tree = PTree::new_empty(DataLevel::L4InPayload(false));
        tree.add_subscription(&patterns, &FIVETUPLE_SUB, &FIVETUPLE_SUB[0].as_str);
        tree.collapse(); // Remove ipv4/tcp
                         // eth -> my filter (matched) -> L7 Disc (Actions - parse)
                         //                            -> L7 >= Headers -> tls (Deliver)
                         //     -> my filter (matching) (Actions - update) -> L7 Disc (Actions - parse)
        assert!(tree.size == 7);

        let filter =
            Filter::new("ipv4 and tls.sni = \'abc\' and my_filter", &CUSTOM_FILTERS).unwrap();
        let patterns = filter.get_patterns_flat();
        let mut tree = PTree::new_empty(DataLevel::L4InPayload(false));
        tree.add_subscription(&patterns, &FIVETUPLE_SUB, &FIVETUPLE_SUB[0].as_str);
        tree.collapse();
        // Similar to above. Added:
        // Under "my_filter (matched)": +L7=Headers (A), +L7>=Payload, +tls.sni (D)
        // Under "my_filter (matching)": +L7>=Headers, +tls, +L7=Headers (A)
        assert!(tree.size == 13);
    }

    lazy_static! {
        static ref CUSTOM_FILTERS_GROUPED: Vec<Predicate> = vec![Predicate::Custom {
            name: filterfunc!("GroupedFil"),
            levels: vec![
                vec![DataLevel::L4InPayload(false)],
                vec![DataLevel::L7EndHdrs]
            ],
            matched: true,
        }];
        static ref CUSTOM_FILTERS_GROUPED_TERM: Vec<Predicate> = vec![Predicate::Custom {
            name: filterfunc!("GroupedFil"),
            levels: vec![
                vec![DataLevel::L4InPayload(false)],
                vec![DataLevel::L4Terminated]
            ],
            matched: true,
        }];
        static ref TERM_SUB: Vec<CallbackSpec> = vec![CallbackSpec {
            expl_level: Some(DataLevel::L4Terminated),
            datatypes: vec![],
            must_deliver: false,
            invoke_once: false,
            as_str: "basic_term".into(),
            subscription_id: String::new(),
            tracked_data: vec![],
        }];
    }

    #[test]
    fn test_ptree_grouped() {
        let filter = Filter::new("ipv4 and tls and GroupedFil", &CUSTOM_FILTERS_GROUPED).unwrap();
        let patterns = filter.get_patterns_flat();
        let mut tree = PTree::new_empty(DataLevel::L4InPayload(false));
        tree.add_subscription(&patterns, &FIVETUPLE_SUB, &FIVETUPLE_SUB[0].as_str);
        tree.collapse();
        assert!(tree.size == 10, "Action size: {}", tree.size);
        // GroupedFil(matched), GroupedFil(matching)
        assert!(
            tree.root.children.len() == 2,
            "Actual len: {}",
            tree.root.children.len()
        );
        let node = tree.get_subtree(5).unwrap(); // "Matching" GroupedFilter
        assert!(node.pred.is_custom(), "Actual pred: {}", node.pred);
        assert!(node.actions.transport.needs_update());
        assert!(node.children.len() == 2 && node.children[0].pred.is_state()); // L7=Disc, L7>=Headers
        let node = tree.get_subtree(2).unwrap(); // L7=Disc
        assert!(node.actions.layers[0].needs_parse());

        let filter =
            Filter::new("ipv4 and tls and GroupedFil", &CUSTOM_FILTERS_GROUPED_TERM).unwrap();
        let patterns = filter.get_patterns_flat();
        let mut tree = PTree::new_empty(DataLevel::L4Terminated);
        tree.add_subscription(&patterns, &TERM_SUB, &TERM_SUB[0].as_str);
        tree.collapse();
        assert!(tree.size == 2, "Actual length: {}", tree.size);
    }

    lazy_static! {
        static ref TERM_SUB_STREAM: Vec<CallbackSpec> = vec![CallbackSpec {
            expl_level: Some(DataLevel::L4Terminated),
            datatypes: vec![SESS_RECORD_DATATYPE.clone()],
            must_deliver: false,
            invoke_once: false,
            as_str: "term_streaming".into(),
            subscription_id: String::new(),
            tracked_data: vec![],
        }];
    }

    #[test]
    fn test_ptree_term() {
        let filter = Filter::new("ipv4 and tls", &CUSTOM_FILTERS_GROUPED_TERM).unwrap();
        let patterns = filter.get_patterns_flat();
        let mut tree = PTree::new_empty(DataLevel::L4Terminated);
        tree.add_subscription(&patterns, &TERM_SUB_STREAM, &TERM_SUB_STREAM[0].as_str);
        tree.collapse();
        assert!(tree.root.deliver.len() == 1);
        // println!("{}", tree);

        let mut tree = PTree::new_empty(DataLevel::L7EndHdrs);
        tree.add_subscription(&patterns, &TERM_SUB_STREAM, &TERM_SUB_STREAM[0].as_str);
        tree.collapse();
        assert!(tree
            .actions
            .actions
            .get(0)
            .unwrap()
            .transport
            .needs_update());
        // println!("{}", tree);
    }

    lazy_static! {
        static ref FIRST_PKT: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L4FirstPacket],
            name: "FirstPacket".into(),
        };
        static ref SESSION_PROTO: DataLevelSpec = DataLevelSpec {
            updates: vec![DataLevel::L7OnDisc],
            name: "SessionProto".into(),
        };
        static ref SESSION_PROTO_SUB: Vec<CallbackSpec> = vec![CallbackSpec {
            expl_level: Some(DataLevel::L4InPayload(false)),
            datatypes: vec![FIRST_PKT.clone(), SESSION_PROTO.clone()],
            must_deliver: false,
            invoke_once: false,
            as_str: "callback".into(),
            subscription_id: "callback".into(),
            tracked_data: vec![],
        }];
    }

    #[test]
    fn test_ptree_proto_stream() {
        let filter = Filter::new("ipv4 and tcp", &CUSTOM_FILTERS_GROUPED_TERM).unwrap();
        let patterns = filter.get_patterns_flat();
        let mut tree = PTree::new_empty(DataLevel::L4InPayload(false));
        tree.add_subscription(&patterns, &SESSION_PROTO_SUB, &SESSION_PROTO_SUB[0].as_str);
        tree.collapse();
        let node = tree.get_subtree(1).unwrap(); // checks if CB is active
        assert!(node.pred.is_callback() && !node.actions.drop());

        // TODO - CB not being set as active
        // - Also make a helper for PNode "is no-op" to centralize that logic
        let mut tree = PTree::new_empty(DataLevel::L4FirstPacket);
        tree.add_subscription(&patterns, &SESSION_PROTO_SUB, &SESSION_PROTO_SUB[0].as_str);
        tree.collapse();
        // Note that in collapse, we expect `ipv4 -> tcp` to get taken away, since any traffic
        // that's not ipv4 -> tcp would have been filtered out at the previous stage.
        assert!(tree.size == 1);
        assert!(tree.root.matched.len() == 1);
    }
}
