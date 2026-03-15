use crate::parse::*;
use iris_core::conntrack::{DataLevel, StateTransition};
use iris_core::filter::{
    ast::{FuncIdent, Predicate},
    pattern::FlatPattern,
    pred_ptree::PredPTree,
    ptree::PTree,
    subscription::{CallbackSpec, DataLevelSpec, SubscriptionLevel},
    Filter,
};
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};

lazy_static! {
    pub(crate) static ref BUILTIN_TYPES: Vec<ParsedInput> = vec![
        ParsedInput::Datatype(DatatypeSpec {
            name: "L4Pdu".into(),
            level: Some(DataLevel::Packet),
            expl_parsers: vec![],
        }),
        ParsedInput::Datatype(DatatypeSpec {
            name: "FilterStr".into(),
            level: Some(DataLevel::Packet),
            expl_parsers: vec![],
        }),
        ParsedInput::Datatype(DatatypeSpec {
            name: "StateTxData".into(),
            level: Some(DataLevel::Packet),
            expl_parsers: vec![], // Must be provided by application
        }),
        ParsedInput::Datatype(DatatypeSpec {
            name: "Session".into(),
            level: Some(DataLevel::L7EndHdrs),
            expl_parsers: vec![], // Must be provided by application
        }),
        ParsedInput::Datatype(DatatypeSpec {
            name: "SessionProto".into(),
            level: Some(DataLevel::L7OnDisc),
            expl_parsers: vec![], // Must be provided by application
        }),
        ParsedInput::Datatype(DatatypeSpec {
            name: "CoreId".into(),
            level: Some(DataLevel::Packet),
            expl_parsers: vec![],
        }),
        // TODO StateTx (without data?)
    ];
}

#[derive(Debug)]
pub(crate) struct SubscriptionSpec {
    pub(crate) callbacks: Vec<CallbackSpec>,
    pub(crate) filter: String,
    pub(crate) as_str: String,
    pub(crate) patterns: Option<Vec<FlatPattern>>,
}

impl SubscriptionSpec {
    fn add_patterns(&mut self, custom_preds: &Vec<Predicate>) {
        if self.patterns.is_none() {
            let filter = Filter::new(&self.filter, &custom_preds)
                .expect(&format!("Invalid filter: {}", self.filter));
            self.patterns = Some(filter.get_patterns_flat());
        }
    }

    fn get_filter_parsers(&self) -> HashSet<String> {
        let mut ret = HashSet::new();
        for pat in self.patterns.as_ref().unwrap() {
            for pred in &pat.predicates {
                if pred.on_proto() {
                    ret.insert(pred.get_protocol().clone().0);
                }
            }
        }
        ret
    }

    fn add_invoke_once(&mut self) {
        // We don't make guarantees for grouped CBs
        // [TODO could change this in future]
        if self.callbacks.len() > 1 {
            return;
        }

        // Streaming CBs invoked until unsubscribe; L4Terminated subscriptions
        // don't need to be tracked.
        if let Some(level) = self.callbacks[0].expl_level {
            if level.is_streaming() || level == DataLevel::L4Terminated {
                return;
            }
        }

        // Any CB that has streaming patterns
        let patterns = self.patterns.as_ref().expect("Patterns not populated");
        let streaming_pred = patterns
            .iter()
            .any(|pat| pat.predicates.iter().any(|pred| pred.is_streaming()));
        if streaming_pred {
            for cb in &mut self.callbacks {
                cb.invoke_once = true;
            }
        }
    }
}

/// Responsible for transforming the raw data in `parse.rs` into the formats
/// Iris requires.
pub(crate) struct SubscriptionDecoder {
    /// Filter group (or function name) --> Parsed Input(s)
    pub(crate) filters_raw: HashMap<String, Vec<ParsedInput>>,
    /// Map datatype group (or name) -> Parsed Input(s)
    pub(crate) datatypes_raw: HashMap<String, Vec<ParsedInput>>,
    /// Map cb group (or name) -> Parsed Input(s)
    pub(crate) cbs_raw: HashMap<String, Vec<ParsedInput>>,

    /// Required stream protocol parsers
    pub(crate) parsers: HashSet<String>,

    /// Valid custom predicates passed into Filter::new()
    pub(crate) custom_preds: Vec<Predicate>,
    /// Datatype name -> Datatype Spec with all updates
    /// Used to derive levels for callbacks and custom filters
    pub(crate) datatypes: HashMap<String, DataLevelSpec>,
    /// Full subscriptions
    pub(crate) subscriptions: Vec<SubscriptionSpec>,

    /// Required `updates`: Level of required update -->
    /// datatype update, filter method, or streaming callback.
    pub(crate) updates: HashMap<DataLevel, Vec<ParsedInput>>,
    /// Tracked datatypes (stored as fields in Tracked struct)
    pub(crate) tracked: HashSet<TrackedType>,
}

impl SubscriptionDecoder {
    pub(crate) fn new(inputs: &Vec<ParsedInput>) -> Self {
        let mut ret = Self {
            filters_raw: HashMap::new(),
            datatypes_raw: HashMap::new(),
            cbs_raw: HashMap::new(),
            parsers: HashSet::new(),
            custom_preds: Vec::new(),
            datatypes: HashMap::new(),
            subscriptions: Vec::new(),
            updates: HashMap::new(),
            tracked: HashSet::new(),
        };
        ret.parse_raw(inputs);
        ret.decode_datatypes();
        ret.decode_filters();
        ret.decode_subscriptions();
        ret.prune_filters_and_datatypes();
        ret.add_parsers();
        for spec in &mut ret.subscriptions {
            spec.add_patterns(&ret.custom_preds);
            ret.parsers.extend(spec.get_filter_parsers());
            spec.add_invoke_once();
        }
        ret.decode_updates();
        ret
    }

    /// Map inputs by name
    fn parse_raw(&mut self, inputs: &Vec<ParsedInput>) {
        BUILTIN_TYPES.iter().for_each(|dt| {
            self.datatypes_raw
                .insert(dt.name().clone(), vec![dt.clone()]);
        });
        for inp in inputs {
            let name = inp.name().clone();
            match inp {
                ParsedInput::Datatype(_) => {
                    let v = self.datatypes_raw.entry(name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::DatatypeFn(dt) => {
                    let group_name = dt.group_name.clone();
                    let v = self.datatypes_raw.entry(group_name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::Filter(_) => {
                    self.filters_raw.insert(name.clone(), vec![inp.clone()]);
                }
                ParsedInput::FilterGroup(_) => {
                    let v = self.filters_raw.entry(name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::FilterGroupFn(f) => {
                    let group_name = f.group_name.clone();
                    let v = self.filters_raw.entry(group_name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::Callback(_) => {
                    assert!(
                        !self.cbs_raw.contains_key(&name),
                        "Callback {} defined twice",
                        name
                    );
                    self.cbs_raw.insert(name.clone(), vec![inp.clone()]);
                }
                ParsedInput::CallbackGroup(_) => {
                    let v = self.cbs_raw.entry(name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::CallbackGroupFn(cb) => {
                    let group_name = cb.group_name.clone();
                    let v = self.cbs_raw.entry(group_name).or_insert(vec![]);
                    v.push(inp.clone());
                }
            }
        }
    }

    fn decode_datatypes(&mut self) {
        for (dt, inp) in &self.datatypes_raw {
            let spec = DataLevelSpec {
                name: dt.clone(),
                updates: inp.iter().cloned().flat_map(|l| l.levels()).collect(),
            };
            self.datatypes.insert(dt.clone(), spec);
        }
    }

    fn decode_filters(&mut self) {
        for (name, v) in self.filters_raw.iter() {
            // Validate grouped input
            if v.iter().any(|inp| inp.is_group()) {
                assert!(v.len() > 1, "Missing group for {:?}", v);
                assert!(
                    v.iter().map(|s| s.group()).all(|x| x == v[0].group()),
                    "Mismatched groups in: {:?}",
                    v
                );
            } else {
                assert!(v.len() == 1, "Missing filter group for: {:?}", v);
            }

            // TODO this breaks if filter is trying to
            // request multiple datatypes like a callback
            let mut levels = vec![];
            for inp in v {
                let mut lvls = vec![];
                // Levels of the datatypes in the function(s)
                match inp {
                    ParsedInput::Filter(f) => {
                        lvls.extend(self.datatypes_to_levels(&f.func));
                    }
                    ParsedInput::FilterGroupFn(f) => {
                        lvls.extend(self.datatypes_to_levels(&f.func));
                    }
                    _ => continue,
                }
                if lvls.iter().any(|l| l.is_streaming()) {
                    assert!(
                        !inp.levels().is_empty(),
                        "Filter {}::{} requests streaming datatypes; must explicitly specify level",
                        name,
                        inp.name()
                    );
                }
                // Explicitly annotated levels
                lvls.extend(inp.levels());
                lvls.sort();
                lvls.dedup();
                if !lvls.is_empty() {
                    levels.push(lvls);
                }
            }
            self.custom_preds.push(Predicate::Custom {
                name: FuncIdent(name.clone()),
                levels,
                matched: true,
            });
        }
    }

    fn decode_subscriptions(&mut self) {
        for (cb_name, v) in &self.cbs_raw {
            let inp_group = v
                .iter()
                .find(|i| matches!(i, ParsedInput::Callback(_) | ParsedInput::CallbackGroup(_)))
                .expect(&format!("{} missing callback definition", cb_name));
            let filter = match inp_group {
                ParsedInput::Callback(cb) => cb.filter.clone(),
                ParsedInput::CallbackGroup(cb) => cb.filter.clone(),
                _ => unreachable!(),
            };
            let mut callbacks = vec![];

            for inp in v {
                match inp {
                    ParsedInput::Callback(cb) => {
                        assert!(v.len() == 1);
                        assert!(
                            cb.level.len() <= 1, // TODO fix this??
                            "Cannot specify >1 explicit level per callback"
                        );
                        let expl_level = cb.level.last().cloned();
                        let cb_spec = self.spec_to_cbs(
                            &cb.func,
                            cb.func.name.clone(),
                            cb.func.name.clone(),
                            expl_level,
                        );
                        callbacks.push(cb_spec);
                    }
                    ParsedInput::CallbackGroupFn(cb) => {
                        // TODO fix this to allow multiple levels
                        let expl_level = cb.level.last().cloned();
                        let sub_id = cb.group_name.clone();
                        let as_str = format!("{}::{}", sub_id, cb.func.name);
                        let cb_spec = self.spec_to_cbs(&cb.func, as_str, sub_id, expl_level);
                        callbacks.push(cb_spec);
                    }
                    ParsedInput::CallbackGroup(_) => continue,
                    _ => panic!("Unknown ParsedInput in callback list"),
                }
            }
            self.subscriptions.push(SubscriptionSpec {
                callbacks,
                filter,
                as_str: cb_name.clone(),
                patterns: None,
            });
        }
    }

    fn spec_to_cbs(
        &self,
        spec: &FnSpec,
        as_str: String,
        subscription_id: String,
        expl_level: Option<DataLevel>,
    ) -> CallbackSpec {
        let must_deliver = spec.datatypes.iter().any(|dt| dt == "FilterStr");
        let datatypes = spec
            .datatypes
            .iter()
            .map(|dt_name| {
                self.datatypes
                    .get(dt_name)
                    .expect(&format!("Can't find datatype {}", dt_name))
                    .clone()
            })
            .collect::<Vec<_>>();
        if datatypes
            .iter()
            .any(|dt| dt.updates.iter().any(|l| l.is_streaming()))
        {
            assert!(
                expl_level.is_some(),
                "Callback {} requests streaming datatype; must explicitly specify level.",
                spec.name
            );
        }
        CallbackSpec {
            expl_level,
            datatypes,
            must_deliver,
            invoke_once: false, // Filled in when patterns are built
            as_str,
            subscription_id,
            tracked_data: vec![],
        }
    }

    // TODO figure out what should go here -- need to fix filters
    // Pull the top-level datatype declaration to infer a function level
    fn datatypes_to_levels(&self, spec: &FnSpec) -> Vec<DataLevel> {
        let mut lvls = vec![];
        for dt_name in &spec.datatypes {
            let dt_info = self
                .datatypes_raw
                .get(dt_name)
                .expect(&format!("Cannot find datatype {}", dt_name));
            let mut level = dt_info
                .iter()
                .find(|grp| matches!(grp, ParsedInput::Datatype(_)))
                .expect(&format!("Cannot find datatype declaration {}", dt_name))
                .levels();
            assert!(
                level.len() == 1,
                "{} declaration has {} levels (requires 1)",
                dt_name,
                level.len()
            );
            lvls.push(level.pop().unwrap());
        }
        lvls.sort();
        lvls.dedup();
        lvls
    }

    fn prune_filters_and_datatypes(&mut self) {
        // Only retain filters that are actually used by a subscription
        self.filters_raw.retain(|name, _| {
            self.subscriptions
                .iter()
                .any(|spec| spec.filter.contains(name))
        });

        // Only retain datatypes that are actually used by a datatype or filter
        let mut req_datatypes = HashSet::new();
        for (_, v) in &self.filters_raw {
            for inp in v {
                match inp {
                    ParsedInput::FilterGroupFn(spec) => {
                        req_datatypes.extend(&spec.func.datatypes);
                    }
                    ParsedInput::Filter(spec) => {
                        req_datatypes.extend(&spec.func.datatypes);
                    }
                    _ => {}
                }
            }
        }
        for (_, v) in &self.cbs_raw {
            for inp in v {
                match inp {
                    ParsedInput::Callback(spec) => {
                        req_datatypes.extend(&spec.func.datatypes);
                    }
                    ParsedInput::CallbackGroupFn(spec) => {
                        req_datatypes.extend(&spec.func.datatypes);
                    }
                    _ => {}
                }
            }
        }
        self.datatypes_raw
            .retain(|name, _| req_datatypes.contains(name));
    }

    fn add_parsers(&mut self) {
        for (_, v) in &self.filters_raw {
            self.parsers.extend(
                v.iter()
                    .flat_map(|i| i.expl_parsers())
                    .filter(|p| !p.is_empty()),
            );
        }
        for (_, v) in &self.datatypes_raw {
            self.parsers.extend(
                v.iter()
                    .flat_map(|i| i.expl_parsers())
                    .filter(|p| !p.is_empty()),
            );
        }
        for (_, v) in &self.cbs_raw {
            self.parsers.extend(
                v.iter()
                    .flat_map(|i| i.expl_parsers())
                    .filter(|p| !p.is_empty()),
            );
        }
    }

    fn decode_updates(&mut self) {
        let mut updates = HashMap::new();
        for (_, v) in &self.filters_raw {
            Self::push_update(&mut updates, v);
            if let Some(tracked) = Self::is_tracked_type(v) {
                self.tracked.insert(tracked);
            }
        }
        for (_, v) in &self.datatypes_raw {
            Self::push_update(&mut updates, v);
            if let Some(tracked) = Self::is_tracked_type(v) {
                self.tracked.insert(tracked);
            }
        }
        for (_, v) in &self.cbs_raw {
            Self::push_update(&mut updates, v);
            if let Some(tracked) = Self::is_tracked_type(v) {
                self.tracked.insert(tracked);
            }
        }
        for spec in &self.subscriptions {
            for cb in &spec.callbacks {
                if cb.invoke_once {
                    assert!(
                        cb.subscription_id == cb.as_str,
                        "Grouped CB {}::{} marked as invoke_once",
                        cb.subscription_id,
                        cb.as_str
                    );
                    self.tracked.insert(TrackedType {
                        name: cb.as_str.clone(),
                        kind: TrackedKind::StaticCallback,
                    });
                }

                // Datatypes that are not builtin but need
                // to be cached for future delivery
                // TODO - change this to be datatypes that are ready before
                // callbacks and shouldn't be constructed in-place.
                // TODO - change to only do this if the subscription can't
                // be delivered at L4FirstPacket
                let static_dts = cb
                    .datatypes
                    .iter()
                    .filter(|dt| dt.updates.len() == 1 && dt.updates[0] == DataLevel::L4FirstPacket)
                    .collect::<Vec<_>>();
                for dt in static_dts {
                    self.tracked.insert(TrackedType {
                        name: dt.name.clone(),
                        kind: TrackedKind::StaticData,
                    });
                }
            }
        }
        self.updates = updates;
    }

    fn push_update(updates: &mut HashMap<DataLevel, Vec<ParsedInput>>, inps: &Vec<ParsedInput>) {
        for inp in inps {
            if inp.is_group() {
                continue;
            }
            let (streaming, stat): (Vec<_>, Vec<_>) =
                inp.levels().into_iter().partition(|l| l.is_streaming());
            for l in streaming {
                updates.entry(l).or_insert(vec![]).push(inp.clone());
            }
            for l in stat {
                match inp {
                    // Deliver requested tx update to filter and datatype fns
                    ParsedInput::FilterGroupFn(_) => {
                        updates.entry(l).or_insert(vec![]).push(inp.clone());
                    }
                    ParsedInput::DatatypeFn(f) => {
                        if !matches!(f.func.returns, FnReturn::Constructor(_)) {
                            updates.entry(l).or_insert(vec![]).push(inp.clone());
                        }
                    }
                    // Callbacks invoked inline
                    // Ungrouped filter functions that aren't streaming don't need to be tracked
                    _ => {}
                }
            }
        }
    }

    // TODO CB also needs to be tracked (differently - just make sure it hasn't already been invoked)
    // if it is a static CB with a streaming filter
    fn is_tracked_type(inps: &Vec<ParsedInput>) -> Option<TrackedType> {
        let is_streaming = inps
            .iter()
            .any(|inp| inp.levels().iter().any(|l| l.is_streaming()));
        // Only one function and it's not streaming
        if inps.len() == 1 && inps[0].levels().len() == 1 && !is_streaming {
            return None;
        }
        // Multiple parsed inputs, but one is a group definition
        // and only one is a function and it's not streaming.
        if !is_streaming
            && inps
                .iter()
                .filter(|i| {
                    matches!(
                        i,
                        ParsedInput::CallbackGroupFn(_)
                            | ParsedInput::DatatypeFn(_)
                            | ParsedInput::FilterGroupFn(_)
                    )
                })
                .count()
                <= 1
        {
            return None;
        }

        // Streaming or multiple functions
        for inp in inps {
            match inp {
                ParsedInput::CallbackGroup(group) => {
                    return Some(TrackedType {
                        kind: TrackedKind::StreamCallback,
                        name: group.name.clone(),
                    });
                }
                ParsedInput::FilterGroup(group) => {
                    return Some(TrackedType {
                        kind: TrackedKind::StreamFilter,
                        name: group.name.clone(),
                    });
                }
                ParsedInput::Datatype(group) => {
                    return Some(TrackedType {
                        kind: TrackedKind::Datatype,
                        name: group.name.clone(),
                    })
                }
                ParsedInput::Callback(cb) => {
                    return Some(TrackedType {
                        kind: TrackedKind::StatelessCallback,
                        name: cb.func.name.clone(),
                    });
                }
                ParsedInput::Filter(fil) => {
                    return Some(TrackedType {
                        kind: TrackedKind::StatelessFilter,
                        name: fil.func.name.clone(),
                    });
                }
                _ => continue,
            }
        }
        None
    }

    pub(crate) fn get_packet_filter_tree(&self) -> PredPTree {
        let mut ptree: PredPTree = PredPTree::new_empty(true);
        for spec in &self.subscriptions {
            let patterns = spec.patterns.as_ref().expect("Patterns not populated");
            ptree.build_tree(patterns, &spec.callbacks);
        }
        ptree.prune_branches();
        println!("{}", ptree);
        ptree
    }

    pub(crate) fn build_ptree(&self, filter_layer: StateTransition) -> PTree {
        assert!(!matches!(filter_layer, StateTransition::Packet));
        let mut ptree = PTree::new_empty(filter_layer);
        for spec in &self.subscriptions {
            let patterns = spec.patterns.as_ref().expect("Patterns not populated");
            ptree.add_subscription(patterns, &spec.callbacks, &spec.as_str);
        }
        ptree.collapse();
        println!("{}", ptree);
        ptree
    }

    /// The application requires a filter at this stage
    /// I.e., at this state transition, the application may have
    /// new information to invoke a callback, update Actions, or
    /// drop traffic.
    pub(crate) fn requires_filter(&self, filter_layer: &StateTransition) -> bool {
        for spec in &self.subscriptions {
            for cb in &spec.callbacks {
                let patterns = spec.patterns.as_ref().expect("Patterns not populated");
                for pat in patterns {
                    let level = SubscriptionLevel::new(&cb.datatypes, pat, cb.expl_level);
                    if level.can_skip(filter_layer) {
                        continue;
                    }
                    // 1. Delivery may be required or no longer required
                    // (in case of unsubscribe)
                    if level.can_deliver(filter_layer) {
                        return true;
                    }
                    // 2. Callback might unsubscribe
                    if let Some(cb) = level.callback {
                        if cb.is_streaming() && &cb == filter_layer {
                            return true;
                        }
                    }
                    // 3. Filter predicate might match
                    if level.filter_preds.iter().any(|l| l == filter_layer) {
                        return true;
                    }
                }
                for dt in &cb.datatypes {
                    if dt.updates.iter().any(|l| l == filter_layer) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrackedKind {
    StreamCallback,
    StatelessCallback,
    StaticCallback,
    StreamFilter,
    StatelessFilter,
    Datatype,
    // Stored in struct but does not require updates
    StaticData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrackedType {
    pub(crate) kind: TrackedKind,
    pub(crate) name: String,
}

use std::hash::{Hash, Hasher};
impl Hash for TrackedType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        format!("{:?}", self.kind).hash(state);
    }
}

#[cfg(test)]
mod tests {
    use iris_core::conntrack::DataLevel;
    use iris_core::filter::{ptree::*, Filter};

    use super::*;

    #[test]
    fn test_filter_parse_basic() {
        /*
         * struct MyGroup {
         *  field: ...
         * }
         *
         * impl MyGroup {
         *  fn new() -> Self;
         *
         *  #[filter_group("MyGroup,L4InPayload")]
         *  fn update(&mut self, pdu: &L4Pdu) -> FilterResult;
         *
         *  #[filter_group("MyGroup")]
         *  fn tls(&mut self, tls: &TlsHandshake) -> FilterResult;
         * }
         */
        let inputs = vec![
            ParsedInput::FilterGroup(FilterGroupSpec {
                level: None,
                name: "MyGroup".into(),
                expl_parsers: vec![],
            }),
            ParsedInput::FilterGroupFn(FilterGroupFnSpec {
                level: vec![DataLevel::L4InPayload(false)],
                group_name: "MyGroup".into(),
                func: FnSpec {
                    name: "update".into(),
                    returns: FnReturn::FilterResult,
                    datatypes: vec!["L4Pdu".into()],
                },
            }),
            ParsedInput::FilterGroupFn(FilterGroupFnSpec {
                level: vec![],
                group_name: "MyGroup".into(),
                func: FnSpec {
                    name: "on_tls".into(),
                    returns: FnReturn::FilterResult,
                    datatypes: vec!["TlsHandshake".into()],
                },
            }),
            ParsedInput::Datatype(DatatypeSpec {
                level: Some(DataLevel::Packet),
                name: "L4Pdu".into(),
                expl_parsers: vec![],
            }),
            ParsedInput::Datatype(DatatypeSpec {
                level: Some(DataLevel::L7EndHdrs),
                name: "TlsHandshake".into(),
                expl_parsers: vec![],
            }),
            ParsedInput::Datatype(DatatypeSpec {
                level: None,
                name: "ConnRecord".into(),
                expl_parsers: vec![],
            }),
            ParsedInput::DatatypeFn(DatatypeFnSpec {
                group_name: "ConnRecord".into(),
                func: FnSpec {
                    name: "update".into(),
                    datatypes: vec!["L4Pdu".into()],
                    returns: FnReturn::None,
                },
                level: vec![DataLevel::L4InPayload(false)],
            }),
            ParsedInput::Callback(CallbackFnSpec {
                filter: "ipv4 and tls and MyGroup".into(),
                level: vec![DataLevel::L4Terminated],
                func: FnSpec {
                    name: "my_cb".into(),
                    datatypes: vec!["ConnRecord".into(), "TlsHandshake".into()],
                    returns: FnReturn::None,
                },
                expl_parsers: vec![],
            }),
        ];
        let decoder = SubscriptionDecoder::new(&inputs);
        assert!(decoder.custom_preds.len() == 1);
        assert!({
            let pred = decoder.custom_preds.first().unwrap();
            let levels = pred.levels();
            levels.len() == 2
                && levels.contains(&DataLevel::L4InPayload(false))
                && levels.contains(&DataLevel::L7EndHdrs)
        });
        assert!({
            let sub = decoder.subscriptions.first().unwrap();
            let datatypes = &sub.callbacks.first().unwrap().datatypes;
            datatypes.len() == 2
                && datatypes
                    .iter()
                    .any(|dt| dt.updates == vec![DataLevel::L4InPayload(false)])
                && datatypes
                    .iter()
                    .any(|dt| dt.updates == vec![DataLevel::L7EndHdrs])
        });

        assert!(decoder.updates.len() == 1);
        let entr = decoder.updates.get(&DataLevel::L4InPayload(false)).unwrap();
        assert!(
            entr.len() == 2,
            "Actual len: {} (value: {:?}",
            entr.len(),
            entr
        );

        // Build up some basic trees
        let mut ptree = PTree::new_empty(DataLevel::L7OnDisc);
        for s in &decoder.subscriptions {
            let filter = Filter::new(&s.filter, &decoder.custom_preds).unwrap();
            let patterns = filter.get_patterns_flat();
            ptree.add_subscription(&patterns, &s.callbacks, &s.as_str);
        }
        ptree.collapse();
        assert!(ptree.size == 4); // eth -> tls -> [MyGroup matched, matching]
        let node1 = ptree.get_subtree(2).unwrap();
        let node2 = ptree.get_subtree(3).unwrap();
        assert!(node1.pred.is_matching() || node2.pred.is_matching());
        assert!(!node1.pred.is_matching() || !node2.pred.is_matching());

        let mut ptree = PTree::new_empty(DataLevel::L7EndHdrs);
        for s in &decoder.subscriptions {
            let filter = Filter::new(&s.filter, &decoder.custom_preds).unwrap();
            let patterns = filter.get_patterns_flat();
            ptree.add_subscription(&patterns, &s.callbacks, &s.as_str);
        }
        ptree.collapse();
        assert!(!ptree.deliver.is_empty());

        let mut ptree = PTree::new_empty(DataLevel::L4InPayload(false));
        for s in &decoder.subscriptions {
            let filter = Filter::new(&s.filter, &decoder.custom_preds).unwrap();
            let patterns = filter.get_patterns_flat();
            ptree.add_subscription(&patterns, &s.callbacks, &s.as_str);
        }
        ptree.collapse();
        assert!(!ptree.deliver.is_empty());
    }
}
