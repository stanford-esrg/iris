#![allow(clippy::needless_doctest_main)]
// #![warn(missing_docs)]

//! TODO high-level docs

#[macro_use]
mod timing;
pub mod config;
pub mod conntrack;
#[doc(hidden)]
#[allow(clippy::all)]
mod dpdk;
pub mod filter;
pub mod lcore;
pub mod memory;
mod port;
pub mod protocols;
mod runtime;
pub mod stats;
#[doc(hidden)]
pub mod subscription;
pub mod utils;

pub use self::conntrack::conn_id::{ConnId, FiveTuple};
pub use self::conntrack::pdu::L4Pdu;
pub use self::conntrack::{DataLevel, StateTransition, StateTxData};
pub use self::lcore::CoreId;
pub use self::memory::mbuf::Mbuf;
pub use self::runtime::Runtime;

pub use dpdk::rte_lcore_id;
pub use dpdk::rte_rdtsc;

#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate maplit;
