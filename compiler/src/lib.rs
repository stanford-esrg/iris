#![allow(clippy::needless_doctest_main)]
//! Macros for defining subscriptions in Iris.
//! See main README. Detailed documentation to be added.

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

#[proc_macro_attribute]
pub fn datatype(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Datatype(DatatypeSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed datatype: {}", spec.name());
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn datatype_group(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::DatatypeFn(DatatypeFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed datatype function: {}", spec.name());
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn callback(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Callback(CallbackFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed callback: {:?}", spec.name());
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn callback_group(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::CallbackGroupFn(CallbackGroupFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed grouped callback function: {}", spec.name());
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn filter(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Filter(FilterFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed filter definition: {}", spec.name());
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn filter_group(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::FilterGroupFn(FilterGroupFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed grouped filter function: {:?}", spec);
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn cache_file(args: TokenStream, input: TokenStream) -> TokenStream {
    let fp = parse_macro_input!(args as syn::LitStr);
    cache::set_crate_outfile(fp.value());
    input
}

#[proc_macro_attribute]
pub fn cache_file_env(args: TokenStream, input: TokenStream) -> TokenStream {
    let var = parse_macro_input!(args as syn::LitStr).value();
    let fp = std::env::var(var).unwrap();
    cache::set_crate_outfile(fp);
    input
}

#[proc_macro_attribute]
pub fn input_files(args: TokenStream, input: TokenStream) -> TokenStream {
    let fps = parse_macro_input!(args as syn::LitStr).value();
    let fps = fps.split(",").collect::<Vec<_>>();
    cache::set_input_files(fps);
    input
}

#[proc_macro_attribute]
pub fn iris_main(_args: TokenStream, input: TokenStream) -> TokenStream {
    env_logger::init();
    // TODO - backup option that lets you specify num expected invocations?
    println!("Done with macros - beginning code generation\n");

    // TODO - allow this to be any input
    let input = parse_macro_input!(input as syn::ItemFn);

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
                // TODO modify to actually return `ret`
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
