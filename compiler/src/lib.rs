#![allow(clippy::needless_doctest_main)]
//! Macros for defining subscriptions in Iris.
//!
//! Every Iris subscription requires a callback, a filter, and one or more data types.
//! Many simple applications can get by with just the [fn@callback] macro, leveraging
//! Iris' filter DSL (which can filter on protocols and protocol fields) and the
//! sample data types in [crate::datatypes].
//!
//! For more complex use-cases, developers can define custom filters with [fn@filter] and
//! data types with [fn@datatypes]. Stateful callbacks, filters, and data types --- i.e.,
//! those that accumulate data over the lifetime of a connection -- use the [fn@callback_fn],
//! [fn@filter_fn], and [fn@datatype_fn], respectively, to annotate struct methods.
//!
//! ## Macro Arguments
//!
//! Because Rust macros cannot access state beyond their immediate input, all *_fn annotations
//! must take in the name of the struct they are associated with as their first argument.
//! The #[callback] macro must take in its filter pattern as its first argument.
//!
//! Other optional arguments:
//! * `level`: Explicitly indicate the state transition that a function should be invoked at.
//!    This
//! * `parsers`: Explicitly specify session-level protocol parsers, using `&` as a separator
//!    (e.g., "http&tls").
//!         - Iris will infer and register protocol parsers based on data types
//!           and filters; for example, if a function requests a TLS handshake or
//!           filters for "tls", then Iris will register the "tls" parser.
//!         - Developers should use this to explicitly register additional parsers.
//!           For example, the "Session", "StateTxData", and "SessionProto" types
//!           do not register any parsers.
//! * `reassembled`: Explicitly request that a function receive data after reassembly.
//!   By default, functions that request data in a streaming state (L4Conn) receive
//!   these updates before TCP reassembly.
//!
//! ## Return values
//!
//! Streaming callback functions must return a boolean value, which can be "false" to unsubscribe
//! from a connection (i.e., stop receiving updates for that connection). Note that if one function in
//! a callback group (i.e., a struct method) returns false, the entire callback (all struct methods)
//! is considered "unsubscribed".
//!
//! Filter functions must return a [crate::core::subscription::FilterResult].
//!
//! ## Filter DSL
//!
//! Iris' filter DSL implements
//! [Retina's filter language](https://stanford-esrg.github.io/retina/v0.1.0/retina_filtergen/index.html)
//! with added support for a `contains` operator and raw byte matching (see below).
//! Iris developers can also filter on custom predicates by referring to them by name
//! (function name for filter functions or struct name for stateful filters).
//!
//! ### Added Binary Comparison Operators
//! | Operator |   Alias   |         Description        | Example                         |
//! |----------|-----------|----------------------------|---------------------------------|
//! | `~b`     |           | Byte regular expression match | `ssh.protocol_version_ctos ~b '(?-u)^\x32\\.\x30$'` |
//! | `contains` |           | Check if right appears in left | `ssh.key_exchange_cookie_stoc contains \|15 A1\|` |
//! | `not contains` | `!contains` | Check that right doesn't appear in left | `ssh.key_exchange_cookie_stoc not contains \|15 A1\|` |
//!
//! ### Added Field Types (RHS values)
//! | Type          | Example            |
//! | Byte          | `\|32 2E 30\|`       |
//!

use proc_macro::TokenStream;
use quote::quote;
use std::collections::HashMap;
use syn::{parse_macro_input, Item};

mod parse;
use parse::*;
mod cache;
mod codegen;
mod packet_filter;
mod state_filters;
mod subscription;

use subscription::SubscriptionDecoder;

/// Indicate that a struct or type is an Iris data type.
///
/// Example usage:
///
/// ```rust,ignore
/// #[datatype("L7EndHdrs,parsers=dns"))]
/// pub type DnsTransaction = Box<Dns>;
/// ```
#[proc_macro_attribute]
pub fn datatype(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Datatype(DatatypeSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed datatype: {}", spec.name());
    cache::push_input(spec);
    quote! {
        #input
    }
    .into()
}

/// Indicate that a struct method should be invoked by Iris as part of
/// constructing a data type.
///
/// Example usage (in an `impl` block for `ConnRecord`)
///
/// ```rust,ignore
/// #[datatype_fn("ConnRecord,level=InL4Conn")]
/// fn update(&mut self, pdu: &L4Pdu) {
///    self.update_data(pdu);
/// }
/// ```
#[proc_macro_attribute]
pub fn datatype_fn(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::DatatypeFn(DatatypeFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed datatype function: {}", spec.name());
    cache::push_input(spec);
    quote! {
        #input
    }
    .into()
}

/// Indicate that a struct or function is a callback.
/// Must specify a filter as a string.
///
/// Example usage:
///
/// ```rust,ignore
/// #[callback("tcp or udp,level=InL4Conn")]
/// fn update(&mut self, conn: &ConnRecord) -> bool {
///     if conn.total_pkts() > 100 {
///         save_to_disk(conn);
///         return false; // unsubscribe from connection
///     }
///     true // keep receiving updates
/// }
/// ```
///
/// Or, as a stateful callback with a custom filter:
///
/// ```rust,ignore
/// #[callback("drop_high_vol_conn,level=InL4Conn")]
/// struct MyCallback {
///     /* ... */
/// }
/// ```
///
/// In this latter case, the custom filter `drop_high_vol_conn` is defined elsewhere
/// using the #[filter] macro. There is also an `impl` block with one or more `callback_fn`
/// functions.
#[proc_macro_attribute]
pub fn callback(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Callback(CallbackFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed callback: {:?}", spec.name());
    cache::push_input(spec);
    quote! {
        #input
    }
    .into()
}

/// Indicate that a struct method should be invoked by Iris as part of
/// constructing a stateful callback
///
/// Example usage (in an `impl` block for `Predictor`)
///
/// ```rust,ignore
/// #[datatype_fn("Predictor,level=InL4Conn")]
/// fn update(&mut self, tracked: &FeatureChunk) -> bool {
///    if self.last.elapsed().as_secs() < INTERVAL_TS {
///         return true; // Continue receiving data
///    }
///    let feature_vec = tracked.to_feature_vec();
///    self.update_data(feature_vec);
///    self.predictions.len() < THRESHOLD
/// }
/// ```
#[proc_macro_attribute]
pub fn callback_fn(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::CallbackGroupFn(CallbackGroupFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed grouped callback function: {}", spec.name());
    cache::push_input(spec);
    quote! {
        #input
    }
    .into()
}

/// Indicate that a struct or function is a filter.
///
/// Example usage:
///
/// ```rust,ignore
/// #[filter("level=L4FirstPacket")]
/// pub fn drop_high_vol_conn(ft: &FiveTuple) -> FilterResult {
///     if PORTS.contains(&ft.resp.port()) {
///         return FilterResult::Drop;
///     }
///     FilterResult::Accept
/// }
/// ```
#[proc_macro_attribute]
pub fn filter(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Filter(FilterFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed filter definition: {}", spec.name());
    cache::push_input(spec);
    quote! {
        #input
    }
    .into()
}

/// Indicate that a struct method should be invoked by Iris as part of
/// constructing a stateful filter.
///
/// Example usage (in an `impl` block for `ShortConnLen`):
///
/// ```rust,ignore
/// #[filter_fn("ShortConnLen,level=L4InPayload")]
///   fn update(&mut self, _: &L4Pdu) -> FilterResult {
///       self.len += 1;
///       if self.len > 10 {
///           return FilterResult::Drop;
///       }
///       FilterResult::Continue
///   }
/// ```
///
/// (Note that the above example could alternatively be implemented by requesting
/// the `PktCount` data type, rather than maintaining a counter in the `filter` struct.
/// Both are equivalent.)
#[proc_macro_attribute]
pub fn filter_fn(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::FilterGroupFn(FilterGroupFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed grouped filter function: {:?}", spec);
    cache::push_input(spec);
    quote! {
        #input
    }
    .into()
}

/// If a crate or target needs to export data types, filters, or callbacks to another crate
/// or target, it must specify a file to cache parsed data in.
/// Other crates or targets access these exported types using [fn@input_files].
/// Rust macros can't maintain local state across targets, and this is a simple workaround.
/// See [crate::datatypes] for an example of using `cache_file``, and see [crate::examples] for
/// applications that use [fn@input_files] to import definitions from other crates or targets.
///
/// Note: if you get an error such as "Can't find data type", but the data type is defined, you
/// may be missing a `cache_file` and/or `input_files`.
#[proc_macro_attribute]
pub fn cache_file(args: TokenStream, input: TokenStream) -> TokenStream {
    let fp = parse_macro_input!(args as syn::LitStr);
    cache::set_crate_outfile(fp.value());
    input
}

/// See [fn@cache_file].
#[proc_macro_attribute]
pub fn input_files(args: TokenStream, input: TokenStream) -> TokenStream {
    let fps = parse_macro_input!(args as syn::LitStr).value();
    let fps = fps.split(",").collect::<Vec<_>>();
    cache::set_input_files(fps);
    input
}

/// In practice, Rust processes procedural macros in the order they appear in imports and
/// in files (though technically this behavior is not guaranteed).
/// Iris use `iris_end_macros` to infer that it has read all macro inputs and
/// can begin generating code.
/// This must go in the main file of every binary target. Generally,
/// putting it on the `main` function makes sense.
#[proc_macro_attribute]
pub fn iris_end_macros(_args: TokenStream, input: TokenStream) -> TokenStream {
    env_logger::init();
    println!("Done with macros - beginning code generation\n");

    let input: proc_macro2::TokenStream = input.into();

    let decoder = {
        let mut inputs = cache::CACHED_DATA.lock().unwrap();
        SubscriptionDecoder::new(inputs.as_mut())
    };
    let tracked_def = codegen::tracked_to_tokens(&decoder);
    let tracked_new = codegen::tracked_new_to_tokens(&decoder);
    let tracked_update = codegen::tracked_update_to_tokens(&decoder);
    let parsers = codegen::parsers_to_tokens(&decoder);

    let packet_tree = decoder.get_packet_filter_tree();
    let packet_filter = packet_filter::gen_packet_filter(&packet_tree);
    let filter_str = packet_tree.to_filter_string();

    let mut statics: HashMap<String, (String, proc_macro2::TokenStream)> = HashMap::new();
    let (state_tx_main, state_fns) = state_filters::gen_state_filters(&decoder, &mut statics);
    let lazy_statics = if statics.is_empty() {
        quote! {}
    } else {
        let statics = statics
            .into_values()
            .map(|(_, tokens)| tokens)
            .collect::<Vec<_>>();
        quote! {
            lazy_static::lazy_static! {
                #( #statics )*
            }
        }
    };

    quote! {

        use iris_core::subscription::{Trackable, Subscribable};
        use iris_core::conntrack::{TrackedActions, ConnInfo};
        use iris_core::protocols::stream::ParserRegistry;
        use iris_core::StateTransition;
        use iris_core::subscription::*;
        use iris_datatypes::*;

        #lazy_statics

        pub struct SubscribedWrapper;
        impl Subscribable for SubscribedWrapper {
            type Tracked = TrackedWrapper;
        }

        pub struct TrackedWrapper {
            packets: Vec<iris_core::Mbuf>,
            core_id: iris_core::CoreId,
            #tracked_def
        }

        impl Trackable for TrackedWrapper {
            type Subscribed = SubscribedWrapper;
            fn new(first_pkt: &iris_core::L4Pdu, core_id: iris_core::CoreId) -> Self {
                Self {
                    packets: Vec::new(),
                    core_id,
                    #tracked_new
                }
            }

            fn packets(&self) -> &Vec<iris_core::Mbuf> {
                &self.packets
            }

            fn core_id(&self) -> &iris_core::CoreId {
                &self.core_id
            }

            fn parsers() -> ParserRegistry {
                ParserRegistry::from_strings(#parsers)
            }

            fn clear(&mut self) {
                self.packets.clear();
                // TODO: #clear
            }
        }

        pub fn filter() -> iris_core::filter::FilterFactory<TrackedWrapper> {

            fn packet_filter(
                mbuf: &iris_core::Mbuf,
                core_id: &iris_core::CoreId
            ) -> bool
            {
                #packet_filter
            }

            fn state_tx(conn: &mut ConnInfo<TrackedWrapper>,
                    tx: &iris_core::StateTransition) {
                #state_tx_main
            }

            #state_fns

            fn update(conn: &mut ConnInfo<TrackedWrapper>,
                pdu: &iris_core::L4Pdu,
                state: iris_core::StateTransition) -> bool
            {
                let mut ret = false;
                #tracked_update
                ret
            }

            iris_core::filter::FilterFactory::new(
                #filter_str,
                packet_filter,
                state_tx,
                update
            )
        }

        #input
    }
    .into()
}
