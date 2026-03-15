// PTree that only tracks predicates (no actions).
// We assume that this is used for the packet tree (filter
// applied to every packet that hits software) and to parse
// flat patterns from filters.

use super::ast::*;
use super::pattern::{FlatPattern, LayeredPattern};
use super::subscription::CallbackSpec;
use crate::conntrack::DataLevel;

use std::collections::HashSet;
use std::fmt;

// A node representing a predicate in the tree
#[derive(Debug, Clone)]
pub struct PredPNode {
    // ID of node
    pub id: usize,

    // Predicate represented by this PredPNode
    pub pred: Predicate,

    // This node terminates an end-to-end pattern
    pub is_terminal: bool,

    // Child PredPNodes
    pub children: Vec<PredPNode>,

    // Packet-level subscriptions that may need to be invoked
    pub deliver: HashSet<CallbackSpec>,
}

impl PredPNode {
    fn new(pred: Predicate, id: usize) -> Self {
        PredPNode {
            id,
            pred,
            is_terminal: false,
            children: vec![],
            deliver: HashSet::new(),
        }
    }

    fn has_child(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| &n.pred == pred)
    }

    fn get_child(&mut self, pred: &Predicate) -> &mut PredPNode {
        self.children.iter_mut().find(|n| &n.pred == pred).unwrap()
    }

    // Returns `true` if a node or any of its children invoke a callback
    fn delivers(&self) -> bool {
        if !self.deliver.is_empty() {
            return false;
        }
        self.children.iter().any(|n| n.delivers())
    }
}

impl fmt::Display for PredPNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pred)?;
        if !self.deliver.is_empty() {
            write!(f, " D: ")?;
            write!(f, "( ")?;
            for d in &self.deliver {
                write!(f, "{}, ", d.as_str)?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

// A n-ary tree representing a boolean (drop/keep) filter.
// This is used only for installing hardware filters and
// for validating filter syntax.
// Paths from root to leaf represent a pattern for a frame to match.
#[derive(Debug)]
pub struct PredPTree {
    // Root node
    pub root: PredPNode,

    // Number of nodes in tree
    pub size: usize,

    // Deliver
    pub deliver: HashSet<CallbackSpec>,

    // Skip adding non-packet-level predicates
    pub packet_only: bool,
}

impl PredPTree {
    // Creates a new predicate tree from a slice of FlatPatterns
    pub fn new(patterns: &[FlatPattern], packet_only: bool) -> Self {
        let mut ptree = Self::new_empty(packet_only);
        ptree.build_tree(patterns, &vec![]);
        ptree
    }

    pub fn new_empty(packet_only: bool) -> Self {
        let root = PredPNode {
            id: 0,
            pred: Predicate::Unary {
                protocol: protocol!("ethernet"),
            },
            is_terminal: false,
            children: vec![],
            deliver: HashSet::new(),
        };
        PredPTree {
            root,
            size: 1,
            deliver: HashSet::new(),
            packet_only,
        }
    }

    // Converts PTree to vector of FlatPatterns (all root->leaf paths).
    // Useful for using the PTree to prune redundant branches then
    // converting back to FlatPatterns
    pub fn to_flat_patterns(&self) -> Vec<FlatPattern> {
        fn build_pattern(
            patterns: &mut Vec<FlatPattern>,
            predicates: &mut Vec<Predicate>,
            node: &PredPNode,
        ) {
            if *node.pred.get_protocol() != protocol!("ethernet") {
                predicates.push(node.pred.to_owned());
            }
            if node.is_terminal {
                patterns.push(FlatPattern {
                    predicates: predicates.to_vec(),
                });
            } else {
                for child in node.children.iter() {
                    build_pattern(patterns, predicates, child);
                }
            }
            predicates.pop();
        }
        let mut patterns = vec![];
        let mut predicates = vec![];

        build_pattern(&mut patterns, &mut predicates, &self.root);
        patterns
    }

    // Converts PTree to vector of LayeredPatterns (all root->leaf paths).
    // Useful for using the PTree to prune redundant branches then
    // converting back to LayeredPatterns
    pub(crate) fn to_layered_patterns(&self) -> Vec<LayeredPattern> {
        let flat_patterns = self.to_flat_patterns();
        let mut layered = vec![];
        for pattern in flat_patterns.iter() {
            layered.extend(pattern.to_fully_qualified().expect("fully qualified"));
        }
        layered
    }

    pub fn build_tree(&mut self, patterns: &[FlatPattern], callbacks: &Vec<CallbackSpec>) {
        // Check for packet-level subscription
        let callback = if callbacks.len() == 1
            && callbacks[0].datatypes.iter().all(|dt| {
                dt.updates.len() == 1
                    && matches!(dt.updates[0], DataLevel::Packet | DataLevel::L4FirstPacket)
            }) {
            match callbacks[0].expl_level {
                Some(DataLevel::Packet) => Some(callbacks[0].clone()),
                None => Some(callbacks[0].clone()),
                _ => None,
            }
        } else {
            None
        };
        // add each pattern to tree
        for pattern in patterns {
            self.add_pattern(pattern, &callback);
        }

        // TODO: maybe remove this to distinguish terminating a user-specified pattern
        if self.root.children.is_empty() {
            self.root.is_terminal = true;
        }
    }

    pub(crate) fn add_pattern(&mut self, pattern: &FlatPattern, callback: &Option<CallbackSpec>) {
        let mut node = &mut self.root;
        let mut terminates_full_pattern = true;
        for predicate in pattern.predicates.iter() {
            if self.packet_only && !predicate.on_packet() {
                // More predicates that haven't been applied
                terminates_full_pattern = false;
                break;
            }
            if !node.has_child(predicate) {
                node.children
                    .push(PredPNode::new(predicate.clone(), self.size));
                self.size += 1;
            }
            node = node.get_child(predicate);
        }

        node.is_terminal = true;
        if terminates_full_pattern {
            // Packet-level pattern and packet-level CB
            if let Some(cb) = callback {
                node.deliver.insert(cb.clone());
                self.deliver.insert(cb.clone());
            }
        }
    }

    // Returns a copy of the subtree rooted at Node `id`
    pub fn get_subtree(&self, id: usize) -> Option<PredPNode> {
        fn get_subtree(id: usize, node: &PredPNode) -> Option<PredPNode> {
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

    // Removes some patterns that are covered by others, but not all.
    // (e.g. "ipv4 or ipv4.src_addr = 1.2.3.4" will remove "ipv4.src_addr = 1.2.3.4")
    pub fn prune_branches(&mut self) {
        fn prune(node: &mut PredPNode) {
            if node.is_terminal && !node.delivers() {
                node.children.clear();
            }
            for child in node.children.iter_mut() {
                prune(child);
            }
        }
        prune(&mut self.root);
    }

    // Displays the conditions in the PTree as a filter string
    pub fn to_filter_string(&self) -> String {
        fn to_filter_string(p: &PredPNode, all: &mut Vec<String>, curr: String) {
            let mut curr = curr;
            if curr.is_empty() {
                curr.push('(');
            } else {
                curr.push_str(&format!("({})", p.pred));
            }
            if p.children.is_empty() {
                let mut path_str = curr.clone();
                path_str.push(')');
                all.push(path_str);
            } else {
                if curr != "(" {
                    curr.push_str(" and ");
                }
                for child in &p.children {
                    to_filter_string(child, all, curr.clone());
                }
            }
        }

        let mut all_filters = Vec::new();
        let curr_filter = String::new();
        if self.root.children.is_empty() {
            return "".into();
        }
        to_filter_string(&self.root, &mut all_filters, curr_filter);
        all_filters.join(" or ")
    }

    // modified from https://vallentin.dev/2019/05/14/pretty-print-tree
    fn pprint(&self) -> String {
        fn pprint(s: &mut String, node: &PredPNode, prefix: String, last: bool) {
            let prefix_current = if last { "`- " } else { "|- " };
            s.push_str(format!("{}{}{} ({})\n", prefix, prefix_current, node, node.id).as_str());
            if !node.deliver.is_empty() {
                s.push_str(" D: (");
                for d in &node.deliver {
                    s.push_str(format!("{}, ", d.as_str).as_str());
                }
                s.push_str(")");
            }

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
}

impl fmt::Display for PredPTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tree Per-Packet:\n{}", self.pprint())?;
        Ok(())
    }
}
