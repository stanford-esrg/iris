#![allow(clippy::needless_doctest_main)]
// #![warn(missing_docs)]

//! A framework for developing high speed network traffic analysis applications that run on commodity hardware.
//!
//! Iris provides a high-level interface for analyzing five-tuple-defined network connections, including
//! reassembled payloads and parsed application-layer sessions, from an in-network vantage point.
//!
//! Iris developers interact with network connections by defining subscriptions.
//! Each subscription consists of one or more data types (data to analyze), a filter (traffic of interest),
//! and a callback (analysis code). Each application can consist of one or more subscriptions.
//!
//! For simple use-cases, Iris provides built-in data types in [crate::datatypes] and a Wireshark-like filter
//! DSL documented in [crate::compiler].
//! For example, only a few lines of code are needed to capture HTTP requests with a specific user agent:
//!
//! ```rust,ignore
//! #[callback("http.user-agent contains 'Mozilla'")]
//! fn log_http(http: &HttpRequest, ft: &FiveTuple) {
//!     log::info!("{}: {}", ft.src_subnet(24), http);
//! }
//! ```
//!
//! For more complex use-cases, Iris developers can define custom filters and data types, as well as stateful
//! and streaming callbacks.
//!
//! Iris processes packets in a connection as they arrive, advancing connections through a set
//! of protocol state machines. Developers can hook into states and state transitions to extract
//! data, perform additional computation, or attach state for later use.
//! The currently-supported states are documented in TODO (state TX link moved).
//! Developers indicate that a struct, type, or function should hook into Iris using the macros exported by
//! [crate::compiler].
//!
//! For example, we can define a data type that extracts features from the body of a connection:
//!
//! ```rust,ignore
//! #[datatype]
//! struct FeatureChunk { /* ... */}
//!
//! impl FeatureChunk {
//!     fn new(first_pkt: &L4Pdu) -> Self { /* ... */}
//!
//!     #[datatype_fn("FeatureChunk,InL4Conn")]
//!     fn update(&mut self, pdu: &L4Pdu) {
//!         /* ... */
//!     }
//! }
//! ```
//!
//! Iris compiles user-defined subscriptions with framework functionality into a connection processing
//! and analysis pipeline, as described in [the paper](https://thearossman.github.io/files/iris.pdf).
//! When compiling an application, Iris prints out the "action trees" (mapping from filter predicates to
//! incremental processing steps) that it will apply at each state transition. We recommend using this as
//! a sanity check for application behavior.

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
pub mod multicore;
mod port;
pub mod protocols;
mod runtime;
pub mod stats;
#[doc(hidden)]
pub mod subscription;
pub mod utils;

pub use self::conntrack::conn_id::{ConnId, FiveTuple};
pub use self::conntrack::pdu::L4Pdu;
pub use self::conntrack::{StateTransition, StateTxData};
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
