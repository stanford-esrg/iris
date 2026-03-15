use std::collections::HashMap;

use crate::codegen::*;
use crate::subscription::SubscriptionDecoder;
use heck::CamelCase;
use iris_core::conntrack::conn::conn_layers::SupportedLayer;
use iris_core::conntrack::conn::conn_state::StateTxOrd;
use iris_core::conntrack::LayerState;
use iris_core::filter::ast::*;
use iris_core::filter::ptree::{PNode, PTree};
use iris_core::StateTransition;
use proc_macro2::{Ident, Span};
use quote::quote;
use strum::IntoEnumIterator;

pub(crate) fn gen_state_filters(
    sub: &SubscriptionDecoder,
    statics: &mut HashMap<String, (String, proc_macro2::TokenStream)>,
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    let mut fns = vec![];
    let mut main = vec![];
    for tx in StateTransition::iter() {
        if tx == StateTransition::Packet {
            continue;
        }
        if !sub.requires_filter(&tx) {
            continue;
        }
        let ptree = sub.build_ptree(tx);
        let mut body: Vec<proc_macro2::TokenStream> = vec![];

        // Ensure root delivery/matches are covered
        if !ptree.root.deliver.is_empty() || !ptree.root.actions.drop() {
            update_body(&mut body, &ptree.root, sub);
        }
        let extract_sessions = matches!(
            tx.compare(&StateTransition::L7EndHdrs),
            StateTxOrd::Greater | StateTxOrd::Equal
        );
        gen_state_filter_util(
            &mut body,
            &ptree.root,
            &ptree,
            statics,
            sub,
            extract_sessions,
        );
        let fn_name = Ident::new(&(format!("tx_{}", tx).to_lowercase()), Span::call_site());

        let ident = Ident::new(&tx.to_string(), Span::call_site());
        if matches!(
            tx,
            StateTransition::L4InPayload(_) | StateTransition::L7InPayload(_)
        ) {
            main.push(quote! {
                StateTransition::#ident(_) => #fn_name(conn, &tx),
            });
        } else {
            let ident = Ident::new(&tx.to_string(), Span::call_site());
            main.push(quote! {
                StateTransition::#ident => #fn_name(conn, &tx),
            });
        }

        // Ensure that datatypes and custom filters that requested updates
        // at this state transition receive them.
        let mut update = quote! {};
        if !tx.is_streaming() {
            update = update_to_tokens(sub, &tx);
            if !update.is_empty() {
                update = quote! {
                    #update
                };
            }
        }

        fns.push(quote! {
            fn #fn_name(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
                let mut ret = false; // unused in state_tx filters
                let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
                // Some callbacks/filters may require immutable borrow of `conn`;
                // it's easiest to just limit the body of the function to immutable
                // borrows and then update actions at the end.
                let mut transport_actions = iris_core::conntrack::TrackedActions::new();
                let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
                // Update filters, datatypes first
                #update
                #( #body )*
                conn.linfo.actions.extend(&transport_actions);
                conn.layers[0].extend_actions(&layer0_actions);
            }
        });
    }
    (
        quote! {
            match tx {
                #( #main )*
                _ => { },
            }
        },
        quote! { #( #fns )* },
    )
}

fn gen_state_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    tree: &PTree, // TODO may not need to pass in `tree`
    statics: &mut HashMap<String, (String, proc_macro2::TokenStream)>,
    sub: &SubscriptionDecoder,
    extract_sessions: bool,
) {
    let mut first_unary = true;
    for child in &node.children {
        match &child.pred {
            Predicate::Unary { protocol } => {
                if child.pred.on_packet() {
                    add_unary_pred(
                        code,
                        child,
                        tree,
                        protocol,
                        statics,
                        first_unary,
                        sub,
                        extract_sessions,
                    );
                    first_unary = false;
                } else if child.pred.on_proto() {
                    add_service_pred(code, child, tree, protocol, statics, sub, extract_sessions);
                } else {
                    panic!("Unknown unary predicate: {}", child.pred);
                }
            }
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => {
                if child.pred.on_packet() {
                    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
                    add_pred(
                        code,
                        child,
                        tree,
                        pred_tokenstream,
                        statics,
                        sub,
                        extract_sessions,
                    );
                } else if child.pred.on_session() {
                    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
                    add_pred(
                        code,
                        child,
                        tree,
                        pred_tokenstream,
                        statics,
                        sub,
                        extract_sessions,
                    );
                } else {
                    panic!("Unknown binary predicate: {}", child.pred);
                }
            }
            Predicate::LayerState { layer, state, op } => {
                let extract_sessions_ = extract_sessions
                    || (layer == &SupportedLayer::L7 && state >= &LayerState::Headers);
                let pred_tokenstream = layerstate_to_tokens(layer, state, *op);
                add_pred(
                    code,
                    child,
                    tree,
                    pred_tokenstream,
                    statics,
                    sub,
                    extract_sessions_,
                );
            }
            Predicate::Custom { name, matched, .. } => {
                let pred_tokenstream = custom_pred_to_tokens(&name.0, *matched, sub);
                add_pred(
                    code,
                    child,
                    tree,
                    pred_tokenstream,
                    statics,
                    sub,
                    extract_sessions,
                );
            }
            Predicate::Callback { name } => {
                assert!(
                    child.children.is_empty()
                        || (
                            // TODO - temporary workaround
                            // It may be okay to have a State predicate here that controls actions
                            // in cases where (1) a filter has already terminated, but (2) the
                            // callback is still waiting for a datatype to be constructed.
                            // In this case, the callback is "active" but hasn't yet been invoked.
                            // However, there should either be a different approach for this case
                            // in general (e.g., distinguish between "matched" and "active" callbacks).
                            child.children.iter().all(|c| c.pred.is_state()
                                && c.children.is_empty()
                                && !c.actions.drop())
                        ),
                    "Expect callback predicate {} to terminate pattern; found children: {}",
                    child.pred,
                    child
                        .children
                        .iter()
                        .map(|c| c.pred.to_string())
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                add_callback_pred(code, &name.0, child, sub);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_unary_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    tree: &PTree,
    protocol: &ProtocolName,
    statics: &mut HashMap<String, (String, proc_macro2::TokenStream)>,
    first_unary: bool,
    sub: &SubscriptionDecoder,
    extract_sessions: bool,
) {
    let ident = Ident::new(protocol.name(), Span::call_site());
    let ident_type = Ident::new(
        &(protocol.name().to_owned().to_camel_case() + "CData"),
        Span::call_site(),
    );
    let pred_tokenstream = quote! {
        &iris_core::protocols::stream::ConnData::parse_to::<iris_core::protocols::stream::conn::#ident_type>(&conn.cdata)
    };

    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_state_filter_util(&mut body, node, tree, statics, sub, extract_sessions);
    update_body(&mut body, node, sub);

    if first_unary {
        code.push(quote! {
            if let Ok(#ident) = #pred_tokenstream {
                #( #body )*
            }
        });
    } else {
        code.push(quote! {
            else if let Ok(#ident) = #pred_tokenstream {
                #( #body )*
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_service_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    tree: &PTree,
    protocol: &ProtocolName,
    statics: &mut HashMap<String, (String, proc_macro2::TokenStream)>,
    sub: &SubscriptionDecoder,
    extract_sessions: bool,
) {
    let service_ident = Ident::new(&protocol.name().to_camel_case(), Span::call_site());
    let pred_tokenstream = if extract_sessions {
        let proto_ident = Ident::new(&protocol.name(), Span::call_site());
        quote! {
            let iris_core::protocols::stream::SessionData::#service_ident(#proto_ident) = &conn.layers[0].last_session().data
        }
    } else {
        quote! {
            matches!(conn.layers[0].last_protocol(), iris_core::protocols::stream::SessionProto::#service_ident)
        }
    };
    add_pred(
        code,
        node,
        tree,
        pred_tokenstream,
        statics,
        sub,
        extract_sessions,
    );
}

fn add_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    tree: &PTree,
    pred_tokenstream: proc_macro2::TokenStream,
    statics: &mut HashMap<String, (String, proc_macro2::TokenStream)>,
    sub: &SubscriptionDecoder,
    extract_sessions: bool,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_state_filter_util(&mut body, node, tree, statics, sub, extract_sessions);
    update_body(&mut body, node, sub);
    if node.if_else {
        code.push(quote! {
            else if #pred_tokenstream {
                #( #body )*
            }
        });
    } else {
        code.push(quote! {
            if #pred_tokenstream {
                #( #body )*
            }
        });
    }
}

fn add_callback_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    name: &String,
    node: &PNode,
    sub: &SubscriptionDecoder,
) {
    // If we're at the callback predicate, then the CB is ready to
    // be invoked or set as active (if it hasn't already unsubscribed).
    for deliver in &node.deliver {
        assert!(
            &deliver.subscription_id == name,
            "Found callback {} at {} callback pred node",
            deliver.subscription_id,
            name
        );
        let cb = fil_callback_to_tokens(sub, deliver);
        code.push(quote! { #cb });
    }

    // Actions conditioned on whether callback is active
    let pred_tokenstream = callback_pred_to_tokens(name);
    let mut body = vec![];
    if !node.actions.drop() {
        let actions = data_actions_to_tokens(&node.actions);
        body.push(quote! { #actions });
    }
    code.push(quote! {
        if #pred_tokenstream {
            #( #body )*
        }
    });
}

fn update_body(body: &mut Vec<proc_macro2::TokenStream>, node: &PNode, sub: &SubscriptionDecoder) {
    if !node.actions.drop() {
        let actions = data_actions_to_tokens(&node.actions);
        body.push(quote! { #actions });
    }
    for deliver in &node.deliver {
        let cb = fil_callback_to_tokens(sub, deliver);
        body.push(quote! { #cb });
    }
    for matched in &node.matched {
        let cb = cb_set_active_to_tokens(matched);
        body.push(quote! { #cb });
    }
    // TODO datatypes
}
