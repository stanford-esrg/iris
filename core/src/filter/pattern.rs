use super::ast::*;
use super::subscription::DataLevelSpec;

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use hashlink::LinkedHashMap;
use petgraph::algo;
use petgraph::graph::NodeIndex;

use crate::conntrack::conn::conn_layers::SupportedLayer;
use crate::conntrack::conn::conn_state::StateTxOrd;
use crate::conntrack::LayerState;
use crate::port::Port;
use crate::{conntrack::StateTransition, filter::FilterError};

use anyhow::{bail, Result};

// TODO predicate ordering in patterns, in general, isn't optimal

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlatPattern {
    pub predicates: Vec<Predicate>,
}

impl FlatPattern {
    // Returns true if pattern is empty
    pub(super) fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    // Returns true if self is a fully qualified FlatPattern
    pub(super) fn is_fully_qualified(&self) -> bool {
        let (layers, labels) = (&*LAYERS, &*NODE_BIMAP);

        let mut ret = true;
        let mut prev_header = unwrap_or_ret_false!(labels.get_by_right(&protocol!("ethernet")));

        for predicate in self.predicates.iter() {
            match predicate {
                Predicate::Unary { protocol } => {
                    let cur_header = unwrap_or_ret_false!(labels.get_by_right(protocol));
                    ret = ret && layers.contains_edge(*cur_header, *prev_header);
                    prev_header = cur_header;
                }
                Predicate::Binary { protocol, .. } => {
                    let cur_header = unwrap_or_ret_false!(labels.get_by_right(protocol));
                    ret = ret && (*cur_header == *prev_header)
                }
                _ => continue,
            }
        }
        ret
    }

    // Returns a vector of fully qualified patterns from self
    // TODO can rethink ordering here
    pub(super) fn to_fully_qualified(&self) -> Result<Vec<LayeredPattern>> {
        if self.is_empty()
            || (self.predicates.len() == 1
                && self.predicates[0].get_protocol() == &protocol!("ethernet"))
        {
            return Ok(Vec::new());
        }

        let (layers, labels) = (&*LAYERS, &*NODE_BIMAP);

        let mut node_paths: HashSet<Vec<NodeIndex>> = HashSet::new();
        let headers = self
            .predicates
            .iter()
            .filter(|c| c.get_protocol() != ProtocolName::none())
            .map(|c| c.get_protocol())
            .collect::<HashSet<_>>();
        for header in headers.iter() {
            match labels.get_by_right(header) {
                Some(node) => {
                    let ethernet = labels
                        .get_by_right(&protocol!("ethernet"))
                        .expect("Ethernet not defined.");
                    let node_path: HashSet<Vec<NodeIndex>> =
                        algo::all_simple_paths(&layers, *node, *ethernet, 0, None).collect();
                    node_paths.extend(node_path.iter().map(|p| p.to_vec()));
                }
                None => panic!("Predicate header invalid: {}", header),
            }
        }

        // all possible fully qualified paths from predicated headers
        let mut fq_paths = HashSet::new();
        for node_path in node_paths {
            let mut fq_path = node_path
                .iter()
                .map(|n| labels.get_by_left(n).unwrap().to_owned())
                .collect::<Vec<_>>();
            fq_path.remove(fq_path.len() - 1); // remove ethernet
            fq_path.reverse();
            fq_paths.insert(fq_path);
        }

        // build fully qualified patterns (could have multiple per non-fully-qualified pattern)
        let mut fq_patterns = vec![];
        for fq_path in fq_paths {
            let fq_headers: HashSet<&ProtocolName> = fq_path.iter().clone().collect();
            if headers.is_subset(&fq_headers) {
                let mut fq_pattern = LayeredPattern::new();
                for protocol in fq_path.iter() {
                    let proto_predicates = self
                        .predicates
                        .iter()
                        .filter(|c| c.get_protocol() == protocol && c.is_binary())
                        .map(|c| c.to_owned())
                        .collect::<HashSet<_>>();

                    let mut proto_predicates = proto_predicates.into_iter().collect::<Vec<_>>();
                    proto_predicates.sort();

                    assert!(fq_pattern.add_protocol(protocol.to_owned(), proto_predicates));
                }
                fq_patterns.push(fq_pattern);
            }
        }

        // Get all custom filters that don't belong to a protocol, validate
        // that they are valid custom filters, and insert each at the end of
        // each end-to-end pattern.
        let custom_preds = self
            .predicates
            .iter()
            .filter(|c| c.is_custom())
            .map(|c| c.to_owned())
            .collect::<HashSet<_>>();
        if !custom_preds.is_empty() {
            // Add custom filter predicate to end of all patterns
            for pattern in fq_patterns.iter_mut() {
                pattern.extend_patterns(&custom_preds);
            }
            // ...or as standalone pattern
            if fq_patterns.is_empty() {
                fq_patterns.push(LayeredPattern::new());
                fq_patterns
                    .last_mut()
                    .unwrap()
                    .extend_patterns(&custom_preds);
            }
        }

        if fq_patterns.is_empty() {
            // This happens when the headers provided do not have a directed path to ethernet node
            // and no custom filters are provided.
            bail!(FilterError::InvalidPatternLayers(self.to_owned()));
        }
        Ok(fq_patterns)
    }

    // Validate and populate DataLevels for the custom predicates
    // When building a filter from a string, only the name of the custom filter is available.
    // To populate needed data, we need to correlate these names with the information parsed
    // at compile-time from the defined custom filters.
    pub(super) fn handle_custom_predicates(&mut self, valid_preds: &Vec<Predicate>) -> Result<()> {
        // "Empty" custom predicate with just the name populated
        for p_empty in &mut self.predicates {
            if p_empty.is_custom() {
                let p = valid_preds
                    .iter()
                    .find(|p| p.get_name() == p_empty.get_name())
                    .ok_or(FilterError::InvalidCustomFilter(p_empty.get_name().clone()))?;
                *p_empty = p.clone();
                p_empty.set_matched(true); // Set default value
            }
        }
        // empty unary "none" predicates may have been added during parsing
        self.predicates
            .retain(|p| !p.is_unary() || p.get_protocol() != ProtocolName::none());
        Ok(())
    }

    // Get the subset of patterns that can be applied if [layer] is in [state]
    pub(super) fn get_subpattern(&self, layer: SupportedLayer, state: LayerState) -> FlatPattern {
        let mut predicates: Vec<_> = self
            .predicates
            .iter()
            .cloned()
            .filter(|x| x.is_compatible(layer, state))
            .collect();
        predicates.push(Predicate::LayerState {
            layer,
            state,
            op: BinOp::Eq,
        });
        Self { predicates }
    }

    // Inserts a Callback predicate
    // The callback predicate MUST be the last predicate in a pattern.
    pub(super) fn with_streaming_cb(&self, name: &String) -> Self {
        let mut pat = self.clone();
        pat.predicates.push(Predicate::Callback {
            name: filterfunc!(name.clone()),
        });
        pat
    }

    // Some custom streaming filters can be `matched` or `continuing`.
    // We need to distinguish between these at runtime.
    // Split patterns by streaming filter match state: `matched` vs. `continue`
    // Note - this could be done more efficiently
    pub(super) fn split_custom(&self) -> Vec<Self> {
        if self.predicates.iter().all(|p| !p.is_custom()) {
            return vec![];
        }
        let mut all_patterns: Vec<Self> = vec![Self { predicates: vec![] }];
        for pred in &self.predicates {
            // For each predicate, either add 1x to each partial or split
            // patterns by custom streaming/non-custom streaming
            // This applies to custom filters that either:
            // - Have multiple separate functions
            // - Or have any streaming functions
            if pred.is_custom()
                && (pred.is_streaming()
                    || if let Predicate::Custom { levels, .. } = pred {
                        levels.len() > 1 // TODO could do pairwise inequality here?
                    } else {
                        unreachable!()
                    })
            {
                let mut new_pats = vec![];
                for partial in &all_patterns {
                    // Original pattern with matched=true
                    let mut term_pat = partial.clone();
                    term_pat.predicates.push(pred.clone());

                    // New pattern with matched=false
                    let mut nonterm_pat = partial.clone();
                    let mut pred = pred.clone();
                    if let Predicate::Custom { matched, .. } = &mut pred {
                        *matched = false;
                    }
                    nonterm_pat.predicates.push(pred);

                    new_pats.push(term_pat);
                    new_pats.push(nonterm_pat);
                }
                all_patterns = new_pats;
            } else {
                // Push new predicates
                for partial in &mut all_patterns {
                    partial.predicates.push(pred.clone());
                }
            }
        }
        // Filter out the original pattern: all custom patterns have `matched=true`,
        // which is covered by the original pattern
        // That is, retain those for which ANY custom predicate has !matched
        all_patterns.retain(|pat| {
            pat.predicates
                .iter()
                .any(|pred| pred.is_custom() && pred.is_matching())
        });
        all_patterns
    }

    // `true` if this filter contains a custom filter that may not have
    // fully matched
    pub(super) fn contains_nonterminal(&self) -> bool {
        self.predicates
            .iter()
            .any(|p| p.is_custom() && p.is_matching())
    }

    // This layer is the first time that this could match
    pub(super) fn is_first_match(&self, filter_layer: &StateTransition) -> bool {
        for pred in self.predicates.iter().rev() {
            let levels = pred.levels();
            if pred.is_state() {
                continue;
            }
            for level in &levels {
                // Predicates are ordered. This indicates that we hit a
                // predicate that could have been applied at an earlier layer
                // BEFORE hitting a predicate that must be applied at this layer.
                if level.compare(filter_layer) == StateTxOrd::Less {
                    return false;
                }
                // Return true if any predicate must be applied at this layer.
                if level.compare(filter_layer) == StateTxOrd::Equal {
                    return true;
                }
            }
        }
        false
    }

    // Get datatypes from the pattern in order to build up `actions`
    // Note: this skips filter predicates that have already matched
    pub(super) fn get_datatypes(&self) -> Vec<DataLevelSpec> {
        self.predicates
            .iter()
            .filter_map(|p| DataLevelSpec::from_pred(p))
            .collect()
    }

    pub(super) fn with_l7_state(&self) -> Self {
        let mut predicates = self.predicates.clone();
        // LayerState::Discovery
        // LayerState::Headers
        // LayerState::Payload
        if let Some(i) = predicates.iter().position(|x| x.on_proto()) {
            predicates.insert(
                i,
                Predicate::LayerState {
                    layer: SupportedLayer::L7,
                    state: LayerState::Headers,
                    op: BinOp::Ge,
                },
            );
        }
        if let Some(i) = predicates.iter().position(|x| x.on_session()) {
            predicates.insert(
                i,
                Predicate::LayerState {
                    layer: SupportedLayer::L7,
                    state: LayerState::Payload,
                    op: BinOp::Ge,
                },
            );
        }

        // Move up anything that doesn't rely on the state predicate
        // TODO do this recursively
        if let Some(first_state) = predicates.iter().position(|p| p.is_state()) {
            if first_state < predicates.len() - 1 {
                if let Predicate::LayerState { layer, state, .. } = predicates[first_state] {
                    let back: Vec<_> = predicates.drain(first_state + 1..).collect();
                    let (pre_state, post_state): (Vec<_>, Vec<_>) =
                        back.into_iter().partition(|p| !p.depends_on(layer, state));
                    predicates.splice(first_state..first_state, pre_state);
                    predicates.extend(post_state);
                }
            }
        }
        Self { predicates }
    }

    // Returns FlatPattern of only predicates that can be filtered in hardware
    pub(super) fn retain_hardware_predicates(&self, port: &Port) -> FlatPattern {
        FlatPattern {
            predicates: self
                .predicates
                .clone()
                .into_iter()
                .filter(|p| p.is_hardware_filterable(port))
                .collect::<Vec<_>>(),
        }
    }

    // Returns the predicates in FlatPattern that come after (or may come after)
    // the given StateTransition. TODO make more effic.
    pub(super) fn next_pred(&self, curr: StateTransition) -> Vec<StateTransition> {
        // All levels that may come after `curr`
        let mut pat: Vec<_> = self
            .predicates
            .iter()
            .flat_map(|p| p.levels())
            .filter(|l| matches!(l.compare(&curr), StateTxOrd::Unknown | StateTxOrd::Greater))
            .collect::<HashSet<_>>() // dedup
            .into_iter()
            .collect();
        // For `matching` streaming filters that are applied at this state,
        // need to update at future iterations of this filter.
        if curr.is_streaming() {
            if self
                .predicates
                .iter()
                .any(|p| p.is_custom() && p.is_matching() && p.levels().iter().any(|l| l == &curr))
            {
                pat.push(curr);
            }
        }
        pat
    }
}

impl fmt::Display for FlatPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "[")?;
        let mut first = true;
        for predicate in self.predicates.iter() {
            if !first {
                write!(f, ", {}", predicate)?;
            } else {
                write!(f, "{}", predicate)?;
            }
            first = false;
        }
        write!(f, "]")?;
        Ok(())
    }
}

// Represents a fully qualified pattern, ordered by header layer
#[derive(Debug, Clone)]
pub struct LayeredPattern(LinkedHashMap<ProtocolName, Vec<Predicate>>);

impl LayeredPattern {
    pub(super) fn new() -> Self {
        LayeredPattern(LinkedHashMap::new())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // Add `predicates` to the _end_ of the pattern.
    fn extend_patterns(&mut self, predicates: &HashSet<Predicate>) {
        if self.0.is_empty() {
            self.0.insert(
                ProtocolName::none().clone(),
                predicates.iter().map(|p| p.to_owned()).collect(),
            );
            return;
        }
        self.0.insert(
            ProtocolName::none().clone(),
            predicates.iter().cloned().collect(),
        );
    }

    // Adds predicates on protocol header. Returns true on success
    fn add_protocol(&mut self, proto_name: ProtocolName, field_predicates: Vec<Predicate>) -> bool {
        let (layers, labels) = (&*LAYERS, &*NODE_BIMAP);

        // check that there is an edge to previous protocol header
        // check that field_predicates are all binary
        // check that field_predicates are all predicates on protocol
        // ignore custom filters
        let mut ret = true;
        let node = unwrap_or_ret_false!(labels.get_by_right(&proto_name));
        if let Some((outer_proto, _)) = self.0.back() {
            let prev = unwrap_or_ret_false!(labels.get_by_right(outer_proto));
            ret = ret && layers.contains_edge(*node, *prev);
            for pred in field_predicates.iter() {
                ret = ret
                    && match pred {
                        Predicate::Unary { .. } => false,
                        Predicate::Binary { protocol, .. } => protocol == &proto_name,
                        Predicate::Custom { .. }
                        | Predicate::Callback { .. }
                        | Predicate::LayerState { .. } => false,
                    }
            }
        } else {
            // IPv4 or IPv6
            let root = unwrap_or_ret_false!(labels.get_by_right(&protocol!("ethernet")));
            ret = ret && layers.contains_edge(*node, *root);
        }

        if ret {
            self.0.insert(proto_name, field_predicates);
            ret
        } else {
            false
        }
    }

    // flattens LayeredPattern to fully qualified FlatPattern
    pub(super) fn to_flat_pattern(&self) -> FlatPattern {
        let mut predicates = vec![];
        for (protocol, field_preds) in self.0.iter() {
            if protocol != ProtocolName::none() {
                predicates.push(Predicate::Unary {
                    protocol: protocol.to_owned(),
                });
            }
            predicates.extend(field_preds.to_owned());
        }
        FlatPattern { predicates }
    }

    pub(super) fn get_header_predicates(&self) -> &LinkedHashMap<ProtocolName, Vec<Predicate>> {
        &self.0
    }
}

impl Default for LayeredPattern {
    fn default() -> Self {
        Self::new()
    }
}

impl Ord for LayeredPattern {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_flat_pattern().cmp(&other.to_flat_pattern())
    }
}

impl PartialOrd for LayeredPattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for LayeredPattern {
    fn eq(&self, other: &Self) -> bool {
        self.to_flat_pattern() == other.to_flat_pattern()
    }
}

impl Eq for LayeredPattern {}

impl fmt::Display for LayeredPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_flat_pattern())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        conntrack::DataLevel,
        filter::{ast::Predicate, parser::FilterParser, pred_ptree::PredPTree, Filter},
    };

    lazy_static! {
        static ref CUSTOM_FILTERS: Vec<Predicate> = vec![Predicate::Custom {
            name: filterfunc!("my_filter"),
            levels: vec![vec![DataLevel::L4InPayload(false)]],
            matched: true,
        }];
    }

    #[test]
    fn test_custom_single() {
        // Single custom filter.
        let filter_raw = "my_filter";
        let raw_patterns = FilterParser::parse_filter(filter_raw).unwrap();
        // Vector of patterns. Expect one pattern and for this pattern to have one predicate.
        assert!(
            raw_patterns.len() == 1
                && raw_patterns.first().unwrap().len() == 1
                && raw_patterns.first().unwrap().first().unwrap().is_custom()
        );
        let flat_patterns = raw_patterns
            .into_iter()
            .map(|p| {
                let mut patt = FlatPattern { predicates: p };
                patt.handle_custom_predicates(&CUSTOM_FILTERS).unwrap();
                patt
            })
            .collect::<Vec<_>>();
        let fq_patterns = flat_patterns[0].to_fully_qualified().unwrap();
        assert!(
            fq_patterns.len() == 1
                && fq_patterns[0]
                    .0
                    .get(ProtocolName::none())
                    .expect("Expecting `none` protocol entry")
                    .get(0)
                    .expect("Expecting `none` protocol with 1 predicate")
                    .get_name()
                    == &filterfunc!("my_filter")
        );
    }

    #[test]
    fn test_custom_pattern() {
        let filter_raw = "tcp.port = 80 and tls and my_filter";
        let raw_patterns = FilterParser::parse_filter(filter_raw).unwrap();
        let flat_patterns = raw_patterns
            .into_iter()
            .map(|p| {
                let mut patt = FlatPattern { predicates: p };
                patt.handle_custom_predicates(&CUSTOM_FILTERS).unwrap();
                patt
            })
            .collect::<Vec<_>>();
        let fq_patterns = flat_patterns[0].to_fully_qualified().unwrap();
        assert!(fq_patterns.len() == 2); // branches for ipv4/ipv6
        assert!(
            fq_patterns[0]
                .0 // my_filter in end of each branch
                .get(ProtocolName::none())
                .expect("Expecting `none` protocol entry")
                .len()
                == 1
        );
        assert!(
            fq_patterns[0].0.back().unwrap().0 == ProtocolName::none(),
            "`none` should be at back of patterns."
        );

        let flat_patterns: Vec<_> = fq_patterns.iter().map(|p| p.to_flat_pattern()).collect();
        let mut ptree = PredPTree::new(&flat_patterns, false);
        ptree.prune_branches();
        // ipv4 -> tcp -> port -> tls -> my_filter
        // + same for ipv6
        assert!(ptree.size == 11, "Actual size: {}", ptree.size);
    }

    #[test]
    fn test_custom_invalid() {
        let filter_raw = "tcp.port = 80 and tls and my_filter and invalid_filter";
        let raw_patterns = FilterParser::parse_filter(filter_raw).unwrap();
        let mut flat_patterns = raw_patterns
            .into_iter()
            .map(|p| FlatPattern { predicates: p })
            .collect::<Vec<_>>();
        flat_patterns[0]
            .handle_custom_predicates(&CUSTOM_FILTERS)
            .expect_err("Should have failed on invalid_filter");
        // println!("Error thrown: {:?}", err);
    }

    #[test]
    fn test_subpattern() {
        let filter_raw = "tcp.port = 80 and tls.sni = \'abc\'";
        let filter = Filter::new(filter_raw, &vec![]).unwrap();
        let pattern = filter.get_patterns_flat();
        let pattern = pattern.get(0).unwrap();
        let subpattern = pattern.get_subpattern(SupportedLayer::L7, LayerState::Discovery);
        // "tls" and SNI field checks removed
        assert!(subpattern
            .predicates
            .iter()
            .all(|x| x.get_protocol() != &protocol!("tls")));
        let subpattern = pattern.get_subpattern(SupportedLayer::L7, LayerState::Headers);
        // SNI field check removed
        assert!(subpattern
            .predicates
            .iter()
            .all(|x| x.get_protocol() != &protocol!("tls") || x.is_unary()));
    }

    #[test]
    fn test_with_l7_state() {
        let filter_raw = "tcp.port = 80 and tls.sni = \'abc\' and my_filter";
        let filter = Filter::new(filter_raw, &CUSTOM_FILTERS).unwrap();
        let pattern = filter.get_patterns_flat();
        let pattern = pattern.get(0).unwrap();
        let with_state = pattern.with_l7_state();
        assert!(
            with_state.predicates.len() > 3,
            "Predicates too small: {:?}",
            with_state
        );
        assert!(with_state.predicates[3].is_custom());
        assert!(with_state.predicates[4].is_state());
    }
}
