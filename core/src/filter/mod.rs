//! Utilities for compile-time filter generation and subscription handling.
//!
//! This module's exports will be most relevant for those adding new filter utilities
//! and/or datatypes. Nothing in this module is needed for writing an ordinary
//! Iris application.
//!

#[doc(hidden)]
#[macro_use]
pub mod macros;
#[doc(hidden)]
pub mod ast;
mod hardware;
#[allow(clippy::upper_case_acronyms)]
mod parser;
pub mod pattern;
#[doc(hidden)]
pub mod pred_ptree;
#[doc(hidden)]
pub mod ptree;
#[doc(hidden)]
pub mod subscription;

use crate::conntrack::{ConnInfo, DataLevel, StateTransition};
use crate::filter::ast::Predicate;
use crate::filter::hardware::{flush_rules, HardwareFilter};
use crate::filter::parser::FilterParser;
use crate::filter::pattern::{FlatPattern, LayeredPattern};
use crate::filter::pred_ptree::PredPTree;
use crate::lcore::CoreId;
use crate::memory::mbuf::Mbuf;
use crate::port::Port;
use crate::subscription::Trackable;
use crate::L4Pdu;

use std::fmt;

use anyhow::{bail, Result};
use ast::FuncIdent;
use thiserror::Error;

// Filter functions
// Note: Rust won't enforce trait bounds on type alias, but T must implement Tracked.

/// Software filter applied to each packet. Will drop, deliver, and/or
/// forward packets to the connection manager. If hardware assist is enabled,
/// the framework will additionally attempt to install the filter in the NICs.
pub type PacketFilterFn = fn(&Mbuf, &CoreId) -> bool;
/// Filter applied on a state transition.
pub type StateTxFn<T> = fn(&mut ConnInfo<T>, &StateTransition);
/// Invoked to update internal data on each new packet
/// Returns `true` if something changed (CB unsubscribed, streaming filter matched/didn't match)
pub type UpdateFn<T> = fn(&mut ConnInfo<T>, &L4Pdu, DataLevel) -> bool;

#[doc(hidden)]
pub struct FilterFactory<T>
where
    T: Trackable,
{
    pub hw_filter_str: String,
    pub packet_filter: PacketFilterFn,
    pub state_tx: StateTxFn<T>,
    pub update_fn: UpdateFn<T>,
}

impl<T> FilterFactory<T>
where
    T: Trackable,
{
    pub fn new(
        hw_filter_str: &str,
        packet_filter: PacketFilterFn,
        state_tx: StateTxFn<T>,
        update_fn: UpdateFn<T>,
    ) -> Self {
        FilterFactory {
            hw_filter_str: hw_filter_str.to_string(),
            packet_filter,
            state_tx,
            update_fn,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Filter {
    patterns: Vec<LayeredPattern>,
}

impl Filter {
    pub fn new(filter_raw: &str, valid_custom_preds: &Vec<Predicate>) -> Result<Filter> {
        let raw_patterns = FilterParser::parse_filter(filter_raw)?;

        let flat_patterns = raw_patterns
            .into_iter()
            .map(|p| {
                let mut patt = FlatPattern { predicates: p };
                patt.handle_custom_predicates(valid_custom_preds).unwrap();
                patt
            })
            .collect::<Vec<_>>();

        let mut fq_patterns = vec![];
        for pattern in flat_patterns.iter() {
            fq_patterns.extend(pattern.to_fully_qualified()?);
        }

        // deduplicate fully qualified patterns
        fq_patterns.sort();
        fq_patterns.dedup();

        // prune redundant branches
        let flat_patterns: Vec<_> = fq_patterns.iter().map(|p| p.to_flat_pattern()).collect();

        let mut ptree = PredPTree::new(&flat_patterns, false);
        ptree.prune_branches();

        Ok(Filter {
            patterns: ptree.to_layered_patterns(),
        })
    }

    // Returns disjunct of layered patterns
    pub fn get_patterns_layered(&self) -> Vec<LayeredPattern> {
        self.patterns.clone()
    }

    // Returns disjuct of flat patterns
    pub fn get_patterns_flat(&self) -> Vec<FlatPattern> {
        self.patterns
            .iter()
            .map(|p| p.to_flat_pattern())
            .collect::<Vec<_>>()
    }

    // Returns predicate tree
    pub fn to_ptree(&self) -> PredPTree {
        PredPTree::new(&self.get_patterns_flat(), false)
    }

    // Returns `true` if filter can be completely realized in hardware
    pub fn is_hardware_filterable(&self) -> bool {
        // needs to take port as argument
        todo!();
    }

    pub(crate) fn set_hardware_filter(&self, port: &Port) -> Result<()> {
        let hw_filter = HardwareFilter::new(self, port);
        match hw_filter.install() {
            Ok(_) => Ok(()),
            Err(error) => {
                flush_rules(port);
                bail!(error);
            }
        }
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[Filter]: ")?;
        for pattern in self.patterns.iter() {
            writeln!(f, "{}", pattern.to_flat_pattern())?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum FilterError {
    // Catches all filters that do not satisfy the grammar.
    // This is an umbrella error type that covers some of the
    // more specific errors below as well.
    #[error("Invalid filter format")]
    InvalidFormat,

    #[error("Invalid pattern. Contains unsupported layer encapsulation: {0}")]
    InvalidPatternLayers(FlatPattern),

    #[error("Invalid predicate type: {0}")]
    InvalidPredType(String),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Invalid field: {0}")]
    InvalidField(String),

    #[error("Invalid binary comparison op: {0}")]
    InvalidBinOp(String),

    #[error("Invalid RHS type for predicate: {0}")]
    InvalidRhsType(String),

    #[error("Invalid RHS value for predicate: {0}")]
    InvalidRhsValue(String),

    #[error("Invalid Integer")]
    InvalidInt {
        #[from]
        source: std::num::ParseIntError,
    },

    #[error("Invalid Range: {start}..{end}")]
    InvalidIntRange { start: u64, end: u64 },

    #[error("Invalid Address")]
    InvalidAddress {
        #[from]
        source: std::net::AddrParseError,
    },

    #[error("Invalid Prefix Len")]
    InvalidPrefixLen {
        #[from]
        source: ipnet::PrefixLenError,
    },

    #[error("Invalid Custom Filter: {0}")]
    InvalidCustomFilter(FuncIdent),
}

// Nice-to-have: tests for filter string parsing
