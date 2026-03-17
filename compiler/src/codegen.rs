use super::parse::*;
use super::subscription::*;
use iris_core::conntrack::{
    conn::conn_layers::SupportedLayer, conn::conn_state::LayerState, Actions, StateTransition,
    TrackedActions,
};
use iris_core::filter::{
    ast::{BinOp, FieldName, ProtocolName, Value},
    subscription::{CallbackSpec, DataActions},
};
use proc_macro2::{Ident, Span};
use quote::quote;

use heck::CamelCase;
use regex::{bytes::Regex as BytesRegex, Regex};
use std::collections::HashMap;
use syn::LitStr;

pub(crate) fn cb_to_tokens(
    sub: &SubscriptionDecoder,
    datatypes: &[String],
    cb_name: &str,
    cb_group: Option<&str>,
    invoke_once: bool,
) -> proc_macro2::TokenStream {
    let mut conditions = vec![];
    let mut cond_match = vec![];
    let mut params = vec![];
    params_to_tokens(
        sub,
        datatypes,
        &mut conditions,
        &mut cond_match,
        &mut params,
    );
    let cb_wrapper_str = cb_name.to_lowercase();
    let cb_name = match cb_name.contains("::") {
        // Workaround for weird formatting of CallbackSpec in PNodes; could be cleaner
        true => cb_name.split("::").last().unwrap(),
        false => cb_name,
    };
    let cb_name_ident = Ident::new(cb_name, Span::call_site());

    let invoke = match cb_group {
        Some(grp) => {
            // Allow for unsubscribe
            // Need to check for `is_active` in the `update` method
            // Invoke method on struct and check for unsubscribe
            let cb_wrapper_ident = Ident::new(&grp.to_lowercase(), Span::call_site());
            let invoke = if grp != cb_name {
                // Stateful callback; invoke on struct
                quote! { conn.tracked.#cb_wrapper_ident.callback.#cb_name_ident(#( #params ), *) }
            } else {
                // Stateless streaming
                quote! { #cb_name_ident(#( #params ), *) }
            };
            quote! {
                if conn.tracked.#cb_wrapper_ident.is_active() {
                    if !#invoke {
                        conn.tracked.#cb_wrapper_ident.set_inactive();
                        ret = true; // CB unsubscribed; something changed
                    }
                }
            }
        }
        None => {
            quote! { #cb_name_ident(#( #params ), *); }
        }
    };

    let invoke = match cond_match.is_empty() {
        true => {
            quote! { #invoke }
        }
        false => {
            quote! {
                match ( #( #conditions ), * ) {
                    (#( #cond_match ), *) => {
                        #invoke
                    }
                    _ => {},
                }
            }
        }
    };

    // Invoking this CB requires checking that it
    // hasn't already been invoked
    match invoke_once {
        true => {
            let cb_wrapper_ident = Ident::new(&cb_wrapper_str, Span::call_site());
            quote! {
                if conn.tracked.#cb_wrapper_ident.should_invoke() {
                    conn.tracked.#cb_wrapper_ident.set_invoked();
                    #invoke
                }
            }
        }
        false => quote! { #invoke },
    }
}

/// Invocation of a custom filter function to tokens.
/// This is the actual invocation of the filter predicate, either in a
/// filter PTree (static filter functions) or in an `update` function
/// (streaming filter functions).
pub(crate) fn filter_func_to_tokens(
    sub: &SubscriptionDecoder,
    filter: &ParsedInput,
    streaming: bool,
) -> proc_macro2::TokenStream {
    let needs_track = streaming || matches!(filter, ParsedInput::FilterGroupFn(_));
    let func = match filter {
        ParsedInput::FilterGroupFn(fil) => &fil.func,
        ParsedInput::Filter(fil) => &fil.func,
        _ => unreachable!(),
    };
    let mut conditions = vec![];
    let mut cond_match = vec![];
    let mut params = vec![];
    params_to_tokens(
        sub,
        &func.datatypes,
        &mut conditions,
        &mut cond_match,
        &mut params,
    );
    let func_ident = Ident::new(&func.name, Span::call_site());
    let fil_ident = match filter {
        ParsedInput::FilterGroupFn(fil) => {
            Ident::new(&fil.group_name.to_lowercase(), Span::call_site())
        }
        ParsedInput::Filter(fil) => Ident::new(&fil.func.name, Span::call_site()),
        _ => unreachable!(),
    };

    // Either invoke via `tracked` parent struct or just invoke directly
    let invoke = match filter {
        ParsedInput::FilterGroupFn(_) => {
            quote! { conn.tracked.#fil_ident.filter.#func_ident(#( #params ), *) }
        }
        ParsedInput::Filter(_) => {
            // TODO StatelessFilterWrapper needed - handle this case
            quote! { #func_ident(#( #params ), *) }
        }
        _ => unreachable!(),
    };
    // Record FilterResult - update needs to return `true` if something changes
    // Note that this may also be invoked in a static filter that doesn't return
    // anything; the `ret` parameter is not used in that case.
    let mut invoke = if needs_track {
        quote! {
            let filter_result = #invoke;
            ret = ret ||
                matches!(filter_result, FilterResult::Accept | FilterResult::Drop);
        }
    } else {
        quote! { #invoke }
    };
    // Get return value for `update` function
    if needs_track {
        invoke = quote! {
            #invoke
            conn.tracked.#fil_ident.record_result(filter_result);
        };
    }

    // Extract parameters for filter if needed
    if !cond_match.is_empty() {
        invoke = quote! {
            match ( #( #conditions ), * ) {
                (#( #cond_match ), *) => {
                    #invoke
                }
                _ => {},
            }
        };
    }

    if needs_track {
        invoke = quote! {
            if conn.tracked.#fil_ident.is_active() {
                #invoke
            }
        };
    }
    invoke
}

pub(crate) fn datatype_func_to_tokens(dt: &DatatypeFnSpec) -> proc_macro2::TokenStream {
    let param = dt
        .func
        .datatypes
        .last()
        .unwrap_or_else(|| panic!("No parameters provided in function {:?}", dt));
    let dt_name = Ident::new(&dt.group_name.to_lowercase(), Span::call_site());
    let fname = Ident::new(&dt.func.name, Span::call_site());
    if BUILTIN_TYPES.iter().any(|inp| inp.name() == param) {
        let builtin = builtin_to_tokens(param);
        return quote! { conn.tracked.#dt_name.#fname(#builtin); };
    }
    panic!("Unknown param for {}: {}", dt.func.name, param);
}

/// Used for filters and CBs
/// @sub Subscription decoder must already be built up
/// @datatypes Input datatypes (name of the type, e.g., struct)
///
/// Some parameters require constructors and may return Option<Self>.
/// Must provide vectors to generate the code that accounts for this.
/// @condition: e.g.: `match (val1, val2)`
/// @cond_match: e.g.: `Some(val1), Some(val2) => ... `
/// @params: actual variable names
pub(crate) fn params_to_tokens(
    sub: &SubscriptionDecoder,
    datatypes: &[String],
    conditions: &mut Vec<proc_macro2::TokenStream>,
    cond_match: &mut Vec<proc_macro2::TokenStream>,
    params: &mut Vec<proc_macro2::TokenStream>,
) {
    for dt in datatypes {
        let dt_metadata = sub
            .datatypes_raw
            .get(dt)
            .unwrap_or_else(|| panic!("Cannot find {} in known datatypes", dt));
        let dt_name_ident = Ident::new(&dt.to_lowercase(), Span::call_site());

        // Extract directly from tracked data
        if sub.tracked.iter().any(|tracked| &tracked.name == dt) {
            params.push(quote! { &conn.tracked.#dt_name_ident });
            continue;
        }

        // Built-in datatype
        if BUILTIN_TYPES.iter().any(|inp| inp.name() == dt) {
            let builtin = builtin_to_tokens(dt);
            params.push(quote! { #builtin });
            continue;
        }

        // Datatype constructed in-place
        let constructor = dt_metadata.iter().find(|inp| match inp {
            ParsedInput::DatatypeFn(spec) => {
                matches!(spec.func.returns, FnReturn::Constructor(_))
            }
            _ => false,
        });
        if let Some(ParsedInput::DatatypeFn(spec)) = constructor {
            // TODO validate / what other restrictions needed here?
            constr_to_tokens(spec, conditions, cond_match, params, &dt_name_ident);
        }
    }
}

pub(crate) fn constr_to_tokens(
    spec: &DatatypeFnSpec,
    conditions: &mut Vec<proc_macro2::TokenStream>,
    cond_match: &mut Vec<proc_macro2::TokenStream>,
    params: &mut Vec<proc_macro2::TokenStream>,
    name_ident: &Ident,
) {
    let returns = match spec.func.returns {
        FnReturn::Constructor(Constructor::Opt) => Constructor::Opt,
        FnReturn::Constructor(Constructor::OptRef) => Constructor::OptRef,
        FnReturn::Constructor(Constructor::Sel) => Constructor::Sel,
        _ => unreachable!(),
    };

    let constructor = {
        assert!(spec.func.datatypes.len() == 1);
        let dt = spec
            .func
            .datatypes
            .first()
            .expect("Constructor without datatypes");
        let param = if dt == "L4Pdu" {
            quote! { pdu }
        } else if dt == "Session" {
            quote! { conn.layers[0].last_session() }
        } else if dt == "Mbuf" {
            quote! { &pdu.mbuf }
        } else if dt == "SessionProto" {
            quote! { &conn.layers[0].last_protocol() }
        } else {
            panic!(
                "Invalid input for datatype constructor: {}",
                spec.func.datatypes.first().unwrap()
            );
        };
        let name = Ident::new(&spec.func.name, Span::call_site());
        let type_name = Ident::new(&spec.group_name, Span::call_site());
        quote! { #type_name::#name(#param) }
    };

    if matches!(returns, Constructor::Opt | Constructor::OptRef) {
        conditions.push(quote! { #constructor, });
        cond_match.push(quote! { Some(#name_ident), });
        if matches!(returns, Constructor::OptRef) {
            params.push(quote! { #name_ident });
        } else {
            // TODO can relax the borrowing requirement here
            params.push(quote! { &#name_ident });
        }
    } else {
        // TODO check is &Self also an option?
        params.push(quote! { &#constructor });
    }
}

pub(crate) fn builtin_to_tokens(name: &String) -> proc_macro2::TokenStream {
    match name.as_str() {
        "L4Pdu" => quote! { pdu },
        "FilterStr" => unimplemented!(),
        "StateTxData" => quote! { &tx },
        "Session" => quote! { conn.layers[0].last_session() },
        "SessionProto" => quote! { &conn.layers[0].last_protocol() },
        "CoreId" => quote! { &conn.tracked.core_id },
        _ => panic!("Unknown builtin datatype: {}", name),
    }
}

pub(crate) fn data_actions_to_tokens(actions: &DataActions) -> proc_macro2::TokenStream {
    let mut ret = vec![quote! {}];
    if !actions.transport.drop() {
        let tracked = tracked_actions_to_tokens(&actions.transport);
        ret.push(quote! { transport_actions.extend(&#tracked); });
    }
    if !actions.layers[0].drop() {
        let lyrs = tracked_actions_to_tokens(&actions.layers[0]);
        ret.push(quote! { layer0_actions.extend(&#lyrs); });
    }
    quote! { #( #ret )* }
}

pub(crate) fn tracked_actions_to_tokens(actions: &TrackedActions) -> proc_macro2::TokenStream {
    let active = actions_to_tokens(&actions.active);
    let refr_at: Vec<proc_macro2::TokenStream> =
        actions.refresh_at.iter().map(actions_to_tokens).collect();
    quote! {
        TrackedActions {
            active: #active,
            refresh_at: [#(#refr_at),*],
        }
    }
}

pub(crate) fn actions_to_tokens(actions: &Actions) -> proc_macro2::TokenStream {
    let bits = syn::LitInt::new(&actions.bits().to_string(), Span::call_site());
    quote! { iris_core::conntrack::Actions::from(#bits) }
}

pub(crate) fn update_to_tokens(
    sub: &SubscriptionDecoder,
    curr: &StateTransition,
) -> proc_macro2::TokenStream {
    let updates = match sub.updates.get(curr) {
        Some(updates) => updates,
        None => return quote! {},
    };
    let mut ret = vec![];
    for upd in updates {
        // Note these CBs are only here if streaming
        match upd {
            ParsedInput::Callback(cb) => {
                ret.push(cb_to_tokens(
                    sub,
                    &cb.func.datatypes,
                    &cb.func.name,
                    Some(&cb.func.name),
                    false,
                ));
            }
            ParsedInput::CallbackGroupFn(cb) => {
                ret.push(cb_to_tokens(
                    sub,
                    &cb.func.datatypes,
                    &cb.func.name,
                    Some(&cb.group_name),
                    false,
                ));
            }
            ParsedInput::Filter(_) | ParsedInput::FilterGroupFn(_) => {
                ret.push(filter_func_to_tokens(sub, upd, curr.is_streaming()));
            }
            ParsedInput::DatatypeFn(dt) => {
                ret.push(datatype_func_to_tokens(dt));
            }
            _ => panic!("Invalid input in update list: {:?}", upd),
        }
    }
    quote! {
        #( #ret )*
    }
}

pub(crate) fn tracked_to_tokens(sub: &SubscriptionDecoder) -> proc_macro2::TokenStream {
    let mut def = vec![];
    for tracked in &sub.tracked {
        let field_name = Ident::new(&tracked.name.to_lowercase(), Span::call_site());
        let type_name = tracked_to_type_tokens(tracked);
        def.push(quote! {
            #field_name: #type_name,
        });
    }
    quote! {
        #( #def )*
    }
}

pub(crate) fn tracked_new_to_tokens(sub: &SubscriptionDecoder) -> proc_macro2::TokenStream {
    let mut new = vec![];
    for tracked in &sub.tracked {
        let field_name = Ident::new(&tracked.name.to_lowercase(), Span::call_site());
        let type_name = tracked_to_type_tokens(tracked);
        new.push(quote! {
            #field_name: #type_name::new(first_pkt),
        });
    }
    quote! {
        #( #new )*
    }
}

fn tracked_to_type_tokens(tracked: &TrackedType) -> proc_macro2::TokenStream {
    let type_raw = Ident::new(&tracked.name, Span::call_site());
    match tracked.kind {
        TrackedKind::StreamCallback => {
            quote! {
                iris_core::subscription::callback::StreamCallbackWrapper::<#type_raw>
            }
        }
        TrackedKind::StatelessCallback => {
            quote! {
                iris_core::subscription::callback::StatelessCallbackWrapper
            }
        }
        TrackedKind::StaticCallback => {
            quote! {
                iris_core::subscription::callback::StaticCallbackWrapper
            }
        }
        TrackedKind::StreamFilter => {
            quote! {
                iris_core::subscription::filter::StreamFilterWrapper::<#type_raw>
            }
        }
        TrackedKind::StatelessFilter => {
            quote! {
                iris_core::subscription::filter::StatelessFilterWrapper
            }
        }
        TrackedKind::Datatype | TrackedKind::StaticData => quote! { #type_raw }, // No wrapper
    }
}

pub(crate) fn parsers_to_tokens(sub: &SubscriptionDecoder) -> proc_macro2::TokenStream {
    let mut parsers = vec![];
    if sub.parsers.is_empty() {
        println!(
            "No session-level parsers registered; L5-L7 protocols will not be detected or parsed."
        );
    } else {
        println!(
            "Parsers: {}\n",
            sub.parsers.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    for parser in &sub.parsers {
        let name = LitStr::new(parser.trim(), Span::call_site());
        parsers.push(quote! {
            #name
        });
    }
    quote! {
        Vec::from([#( #parsers ),*])
    }
}

/// Generates tokens for streaming updates to all tracked datatypes, callbacks,
/// and filters that need to be invoked within each streaming state.
/// This invokes the `update` for each.
pub(crate) fn tracked_update_to_tokens(sub: &SubscriptionDecoder) -> proc_macro2::TokenStream {
    let mut all_updates = vec![];
    for (level, inps) in &sub.updates {
        if inps.is_empty() || !level.is_streaming() {
            continue;
        }
        let updates = update_to_tokens(sub, level);
        let level_ident = Ident::new(&level.to_string(), Span::call_site());
        let level_ident = match level {
            StateTransition::L4InPayload(_) | StateTransition::L7InPayload(_) => {
                quote! { #level_ident(_) }
            }
            _ => quote! { #level_ident },
        };
        all_updates.push(quote! {
            StateTransition::#level_ident => {
                #updates
            }
        });
    }
    quote! {
        match state {
            #( #all_updates )*
            _ => {},
        }
    }
}

/// Callback invocation to tokens within a filter PTree.
/// This actually invokes the callback.
pub(crate) fn fil_callback_to_tokens(
    sub: &SubscriptionDecoder,
    spec: &CallbackSpec,
) -> proc_macro2::TokenStream {
    let dts: Vec<String> = spec.datatypes.iter().map(|dt| dt.name.clone()).collect();
    let name = spec.as_str.as_str();

    // Will track CB state within a streaming wrapper, either because
    // this is a multi-function CB or because it's a streaming CB
    let mut group: Option<&str> = None;
    if spec.subscription_id != spec.as_str {
        group = Some(&spec.subscription_id);
    }

    // Streaming CBs invoked in "update" methods only.
    // TODO logic for caching past data and streaming it on first match
    let mut invoke = quote! {};
    if match spec.expl_level {
        Some(l) => !l.is_streaming(),
        None => true,
    } {
        invoke = cb_to_tokens(sub, &dts, name, group, spec.invoke_once);
    }

    // "try set active" will set the CB as "matched" unless it has
    // already unsubscribed
    if let Some(grp) = group {
        let wrapper = Ident::new(&grp.to_lowercase(), Span::call_site());
        invoke = quote! {
            conn.tracked.#wrapper.try_set_active();
            #invoke
        };
    }

    invoke
}

pub(crate) fn cb_set_active_to_tokens(spec: &CallbackSpec) -> proc_macro2::TokenStream {
    assert!(
        spec.is_streaming() || spec.subscription_id != spec.as_str,
        "Setting CB as matched should only happen for streaming or multi-function CBs"
    );
    let wrapper = Ident::new(&spec.subscription_id.to_lowercase(), Span::call_site());
    quote! { conn.tracked.#wrapper.try_set_active(); }
}

/// Custom streaming (stateful or stateless) predicate to tokens
/// in a filter PTree. This checks for a filter result, but it does not
/// invoke the filter.
pub(crate) fn custom_pred_to_tokens(
    name: &String,
    matched: bool,
    decoder: &SubscriptionDecoder,
) -> proc_macro2::TokenStream {
    let filter = decoder
        .filters_raw
        .get(name)
        .unwrap_or_else(|| panic!("Can't find filter {}", name));

    assert!(!filter.is_empty(), "{} has no inputs", name);

    if filter.len() > 1 || filter[0].levels().iter().any(|l| l.is_streaming()) {
        let ident = Ident::new(&(name.to_lowercase()), Span::call_site());
        match matched {
            true => quote! { conn.tracked.#ident.matched() },
            false => quote! { conn.tracked.#ident.is_active() },
        }
    } else {
        let tokens = filter_func_to_tokens(decoder, &filter[0], false);
        quote! { #tokens == FilterResult::Accept }
    }
}

/// Custom streaming (stateful or stateless) callback predicate to tokens
/// in a filter PTree. This checks whether a callback is currently active,
/// but it does not invoke the callback.
pub(crate) fn callback_pred_to_tokens(name: &str) -> proc_macro2::TokenStream {
    let ident = Ident::new(&name.to_lowercase(), Span::call_site());
    quote! { conn.tracked.#ident.is_active() }
}

pub(crate) fn layerstate_to_tokens(
    layer: &SupportedLayer,
    state: &LayerState,
    op: BinOp,
) -> proc_macro2::TokenStream {
    let op = match op {
        BinOp::Eq => quote! { == },
        BinOp::Ge => quote! { >= },
        BinOp::Gt => quote! { > },
        BinOp::Le => quote! { <= },
        BinOp::Lt => quote! { < },
        _ => panic!("Invalid op for state: {:?}", op),
    };
    let layer_access = match layer {
        SupportedLayer::L4 => {
            quote! { conn.linfo.state }
        }
        SupportedLayer::L7 => {
            quote! { conn.layers[0].layer_info().state }
        }
    };
    let state_ident = format!("{:?}", state);
    let state_ident = Ident::new(&state_ident, Span::call_site());
    quote! {
        #layer_access #op iris_core::conntrack::LayerState::#state_ident
    }
}

// Binary filter predicates
pub(crate) fn binary_to_tokens(
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
    statics: &mut HashMap<String, (String, proc_macro2::TokenStream)>,
) -> proc_macro2::TokenStream {
    assert!(!field.is_combined()); // should have been split when building tree
    let proto = Ident::new(protocol.name(), Span::call_site());
    let field = Ident::new(field.name(), Span::call_site());

    match value {
        Value::Int(val) => {
            let val_lit = syn::LitInt::new(&val.to_string(), Span::call_site());
            match *op {
                BinOp::Eq => quote! { #proto.#field() == #val_lit },
                BinOp::Ne => quote! { #proto.#field() != #val_lit },
                BinOp::Ge => quote! { #proto.#field() >= #val_lit },
                BinOp::Le => quote! { #proto.#field() <= #val_lit },
                BinOp::Gt => quote! { #proto.#field() > #val_lit },
                BinOp::Lt => quote! { #proto.#field() < #val_lit },
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::IntRange { from, to } => {
            let from_lit = syn::LitInt::new(&from.to_string(), Span::call_site());
            let to_lit = syn::LitInt::new(&to.to_string(), Span::call_site());
            match *op {
                BinOp::In => quote! {
                    #proto.#field() >= #from_lit && #proto.#field() <= #to_lit
                },
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Ipv4(ipv4net) => {
            let addr_u32 = u32::from(ipv4net.addr());
            let addr_lit = syn::LitInt::new(&addr_u32.to_string(), Span::call_site());

            let netmask_u32 = u32::from(ipv4net.netmask());
            let netmask_lit = syn::LitInt::new(&netmask_u32.to_string(), Span::call_site());

            let net_u32 = addr_u32 & netmask_u32;
            let net_lit = syn::LitInt::new(&net_u32.to_string(), Span::call_site());

            match *op {
                BinOp::Eq => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                BinOp::Ne => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) != #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit != #net_lit }
                    }
                }
                BinOp::In => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Ipv6(ipv6net) => {
            let addr_u128 = u128::from(ipv6net.addr());
            let addr_lit = syn::LitInt::new(&addr_u128.to_string(), Span::call_site());

            let netmask_u128 = u128::from(ipv6net.netmask());
            let netmask_lit = syn::LitInt::new(&netmask_u128.to_string(), Span::call_site());

            let net_u128 = addr_u128 & netmask_u128;
            let net_lit = syn::LitInt::new(&net_u128.to_string(), Span::call_site());

            match *op {
                BinOp::Eq => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                BinOp::Ne => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) != #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit != #net_lit }
                    }
                }
                BinOp::In => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Text(text) => match *op {
            BinOp::Eq => {
                let val_lit = syn::LitStr::new(text, Span::call_site());
                quote! { #proto.#field() == #val_lit }
            }
            BinOp::Ne => {
                let val_lit = syn::LitStr::new(text, Span::call_site());
                quote! { #proto.#field() != #val_lit }
            }
            BinOp::En => {
                let field_ident = Ident::new(&field.to_string().to_camel_case(), Span::call_site());
                let variant_ident = Ident::new(&text.as_str().to_camel_case(), Span::call_site());
                quote! { #proto.#field() == iris_core::protocols::stream::#proto::#field_ident::#variant_ident }
            }
            BinOp::Re => {
                if Regex::new(text).is_err() {
                    panic!("Invalid Regex string: {}", text);
                }
                let val_lit = syn::LitStr::new(text, Span::call_site());
                let kind = quote! { regex::Regex };
                let re_ident = static_ident_re(statics, text, val_lit, kind);
                quote! {
                    #re_ident.is_match(&#proto.#field()[..])
                }
            }
            BinOp::ByteRe => {
                if BytesRegex::new(text).is_err() {
                    panic!("Invalid Regex string: {}", text);
                }
                let val_lit = syn::LitStr::new(text, Span::call_site());
                let kind = quote! { regex::bytes::Regex };
                let re_ident = static_ident_re(statics, text, val_lit, kind);
                quote! {
                    #re_ident.is_match((&#proto.#field()).as_ref())
                }
            }
            BinOp::Contains => {
                let val_lit = syn::LitStr::new(text, Span::call_site());
                let finder_ident =
                    static_ident_memchr(statics, text, quote! { #val_lit.as_bytes() });
                quote! {
                    #finder_ident.find(#proto.#field().as_bytes()).is_some()
                }
            }
            BinOp::NotContains => {
                let val_lit = syn::LitStr::new(text, Span::call_site());
                let finder_ident =
                    static_ident_memchr(statics, text, quote! { #val_lit.as_bytes() });
                quote! {
                    #finder_ident.find(#proto.#field().as_bytes()).is_none()
                }
            }
            _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
        },
        Value::Byte(b) => match *op {
            BinOp::Eq => {
                let bytes_lit = syn::LitByteStr::new(b, Span::call_site());
                quote! {
                    #proto.#field().as_ref() as &[u8] == #bytes_lit
                }
            }
            BinOp::Ne => {
                let bytes_lit = syn::LitByteStr::new(b, Span::call_site());
                quote! {
                    #proto.#field().as_ref() as &[u8] != #bytes_lit
                }
            }
            BinOp::Contains => {
                let bytes_lit = syn::LitByteStr::new(b, Span::call_site());
                let debug = b.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                let finder_ident = static_ident_memchr(statics, &debug, quote! { #bytes_lit });
                quote! {
                    #finder_ident.find(#proto.#field().as_ref()).is_some()
                }
            }
            BinOp::NotContains => {
                let bytes_lit = syn::LitByteStr::new(b, Span::call_site());
                let debug = b.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                let finder_ident = static_ident_memchr(statics, &debug, quote! { #bytes_lit });
                quote! {
                    #finder_ident.find(#proto.#field().as_ref()).is_none()
                }
            }
            _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
        },
    }
}

fn static_ident_re(
    statics: &mut HashMap<String, (String, proc_macro2::TokenStream)>,
    text: &String,
    val_lit: syn::LitStr,
    kind: proc_macro2::TokenStream,
) -> Ident {
    let key = format!("RE_{}", text);
    match statics.get(&key) {
        Some((name, _)) => Ident::new(name, Span::call_site()),
        None => {
            let name = format!("RE{}", statics.len());
            let ident = Ident::new(&name, Span::call_site());
            let lazy = quote! {
                static ref #ident: #kind = #kind::new(#val_lit).unwrap();
            };
            statics.insert(key, (name, lazy));
            ident
        }
    }
}

fn static_ident_memchr(
    statics: &mut HashMap<String, (String, proc_macro2::TokenStream)>,
    text: &String,
    val_lit: proc_macro2::TokenStream,
) -> Ident {
    let key = format!("FINDER_{}", text);
    match statics.get(&key) {
        Some((name, _)) => Ident::new(name, Span::call_site()),
        None => {
            let name = format!("FINDER{}", statics.len());
            let ident = Ident::new(&name, Span::call_site());
            let lazy = quote! {
                static ref #ident: memchr::memmem::Finder<'static> = memchr::memmem::Finder::new(#val_lit);
            };
            statics.insert(key, (name, lazy));
            ident
        }
    }
}
