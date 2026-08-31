use std::collections::BTreeMap;

use crate::codegen::*;
use crate::subscription::SubscriptionDecoder;
use heck::CamelCase;
use iris_core::StateTransition;
use iris_core::conntrack::LayerState;
use iris_core::conntrack::conn::conn_layers::SupportedLayer;
use iris_core::conntrack::conn::conn_state::StateTxOrd;
use iris_core::filter::ast::*;
use iris_core::filter::ptree::{PNode, PTree};
use proc_macro2::{Ident, Span};
use quote::quote;
use strum::IntoEnumIterator;

pub(crate) fn gen_state_filters(
    sub: &SubscriptionDecoder,
    statics: &mut BTreeMap<String, (String, proc_macro2::TokenStream)>,
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
        main.push(quote! {
            iris_core::StateTransition::#ident => #fn_name(conn, &tx, pdu),
        });

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

        // Start/end for filtered/tracked data
        let mut start_tracked = quote! {};
        let mut end_tracked = quote! {};
        for dt in ptree.filtered_datatypes {
            let dt_ident = Ident::new(&dt.to_lowercase(), Span::call_site());
            start_tracked = quote! {
                #start_tracked
                conn.tracked.#dt_ident.start_state_tx(&tx);
            };
            end_tracked = quote! {
                #end_tracked
                conn.tracked.#dt_ident.end_state_tx();
            };
        }

        // Complete state transition handler
        let extract_data = if matches!(tx, StateTransition::L4FirstPacket) {
            quote! { let pdu = pdu.expect("L4Pdu not passed to L4FirstPacket?"); }
        } else {
            quote! {}
        };
        fns.push(quote! {
            fn #fn_name(conn: &mut ConnInfo<TrackedWrapper>, tx: &iris_core::StateTransition, pdu: Option<&iris_core::L4Pdu>) {
                let mut ret = false; // unused in state_tx filters
                #extract_data
                #start_tracked
                let tx_data = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
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
                #end_tracked
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
    tree: &PTree,
    statics: &mut BTreeMap<String, (String, proc_macro2::TokenStream)>,
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
                if child.pred.on_packet() || child.pred.on_session() {
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
                    || (layer == &SupportedLayer::L7 && state >= &LayerState::Payload);
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
                            // In general, a callback node shouldn't have any other children.
                            // One exception: it can be OK to have a State predicate (e.g., "if L7 >= Headers") here if
                            // a filter has already terminated/matched, but the callback is still waiting for
                            // a data type to be constructed (e.g., a TLS handshake, but we're still in "L7Headers");
                            // here, the callback is "active" but not yet invoked.
                            // This is a sanity-check for these cases.
                            // Possible opportunity for REFACTOR of PTrees in the future.
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
                add_callback_pred(code, &name.0, child, tree, statics, sub, extract_sessions);
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
    statics: &mut BTreeMap<String, (String, proc_macro2::TokenStream)>,
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
    update_body(&mut body, node, sub);
    gen_state_filter_util(&mut body, node, tree, statics, sub, extract_sessions);

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
    statics: &mut BTreeMap<String, (String, proc_macro2::TokenStream)>,
    sub: &SubscriptionDecoder,
    extract_sessions: bool,
) {
    let service_ident = Ident::new(&protocol.name().to_camel_case(), Span::call_site());
    // Destructuring `last_session()` both binds the session variable and tests that a
    // session was actually parsed. Only do it when some descendant predicate needs the
    // binding: `binary_to_tokens` emits `#proto.#field()` against it.
    //
    // Otherwise this is a protocol check.
    // The compiler grants L7 `Parse` past `L7OnDisc` only when a subscription needs the
    // session, so, for a protocol-only pattern, parsing stops as soon as the protocol is
    // known and `last_session()` stays empty for the rest of the connection.
    let pred_tokenstream = if extract_sessions && binds_session(node, protocol) {
        let proto_ident = Ident::new(protocol.name(), Span::call_site());
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

/// Returns `true` if any descendant of `node` reads a session field of `protocol`, and so
/// needs the session variable that `add_service_pred`'s destructuring form binds.
fn binds_session(node: &PNode, protocol: &ProtocolName) -> bool {
    node.children.iter().any(|c| {
        (c.pred.on_session() && c.pred.get_protocol() == protocol) || binds_session(c, protocol)
    })
}

fn add_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    tree: &PTree,
    pred_tokenstream: proc_macro2::TokenStream,
    statics: &mut BTreeMap<String, (String, proc_macro2::TokenStream)>,
    sub: &SubscriptionDecoder,
    extract_sessions: bool,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    update_body(&mut body, node, sub);
    gen_state_filter_util(&mut body, node, tree, statics, sub, extract_sessions);
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

#[allow(clippy::too_many_arguments)]
fn add_callback_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    name: &String,
    node: &PNode,
    tree: &PTree,
    statics: &mut BTreeMap<String, (String, proc_macro2::TokenStream)>,
    sub: &SubscriptionDecoder,
    extract_sessions: bool,
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
        let cb = fil_callback_to_tokens(sub, deliver, Some(node));
        code.push(quote! { #cb });
    }

    // Actions conditioned on whether callback is active
    let pred_tokenstream = callback_pred_to_tokens(name);
    let mut body = vec![];
    if !node.actions.drop() {
        let actions = data_actions_to_tokens(&node.actions);
        body.push(quote! { #actions });
    }
    // A callback node can carry LayerState children if the callback filter matched but
    // the function(s) are still waiting on a datatype.
    gen_state_filter_util(&mut body, node, tree, statics, sub, extract_sessions);
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
    for matched in &node.matched {
        // Note: setting `matched` to active must come before `deliver`
        let cb = cb_set_active_to_tokens(matched);
        body.push(quote! { #cb });
    }
    for deliver in &node.deliver {
        let cb = fil_callback_to_tokens(sub, deliver, Some(node));
        body.push(quote! { #cb });
    }
    for dt in node.filtered_datatypes.values() {
        let dt = filtered_dt_to_tokens(dt);
        body.push(quote! { #dt });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ParsedInput;

    /// Definitions in the same line-delimited-JSON form as `datatypes/data.txt`, so these
    /// fixtures stay in the shape the macros actually emit.
    const CONN_DATATYPE: &str = r#"
{"Datatype":{"name":"ConnDuration","level":null,"expl_parsers":[],"filtered":false}}
{"DatatypeFn":{"group_name":"ConnDuration","func":{"name":"update","datatypes":["L4Pdu"],"returns":"None"},"level":["InL4Conn"]}}
"#;

    /// A session-derived datatype: available only once headers are parsed.
    const SESSION_DATATYPE: &str = r#"
{"Datatype":{"name":"TlsHandshake","level":"L7EndHdrs","expl_parsers":["tls"],"filtered":false}}
{"DatatypeFn":{"group_name":"TlsHandshake","func":{"name":"from_session","datatypes":["Session"],"returns":{"Constructor":"OptRef"}},"level":["L7EndHdrs"]}}
"#;

    /// A stateful streaming filter, in the shape `#[filter]`/`#[filter_fn]` emit.
    const STREAM_FILTER: &str = r#"
{"FilterGroup":{"level":null,"name":"StreamFilter","expl_parsers":[]}}
{"FilterGroupFn":{"level":["InL4Conn"],"group_name":"StreamFilter","func":{"name":"update","datatypes":["L4Pdu"],"returns":"FilterResult"}}}
{"FilterGroupFn":{"level":["L4Terminated"],"group_name":"StreamFilter","func":{"name":"terminated","datatypes":[],"returns":"FilterResult"}}}
"#;

    /// A conn-level callback at `L4Terminated`: needs no session-derived data, so the
    /// action planner has no reason to keep L7 `Parse` alive past `L7OnDisc`.
    fn conn_callback(name: &str, filter: &str) -> String {
        callback(name, filter, "ConnDuration")
    }

    /// A callback over a session-derived datatype, which does keep parsing alive.
    fn session_callback(name: &str, filter: &str) -> String {
        callback(name, filter, "TlsHandshake")
    }

    fn callback(name: &str, filter: &str, datatype: &str) -> String {
        let func = format!(
            r#"{{"name":"{}","datatypes":["{}"],"returns":"None"}}"#,
            name, datatype
        );
        format!(
            r#"{{"Callback":{{"filter":"{}","level":["L4Terminated"],"func":{},"expl_parsers":[]}}}}"#,
            filter, func
        )
    }

    /// Runs the real codegen path over `defs` and returns the generated state-transition
    /// functions as a token string.
    fn gen_fns(defs: &[&str]) -> String {
        let inputs: Vec<ParsedInput> = defs
            .iter()
            .flat_map(|d| d.lines())
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{}: {}", e, l)))
            .collect();
        let sub = SubscriptionDecoder::new(&inputs);
        let mut statics = HashMap::new();
        gen_state_filters(&sub, &mut statics).1.to_string()
    }

    /// Extracts the body of the generated `tx_<state>` function from `code`.
    fn tx_fn(code: &str, state: &str) -> String {
        let marker = format!("fn tx_{} ", state);
        let start = code
            .find(&marker)
            .unwrap_or_else(|| panic!("no tx_{} in generated code:\n{}", state, code));
        let rest = &code[start + marker.len()..];
        // Functions are emitted back to back, so the next `fn tx_` ends this one.
        match rest.find("fn tx_") {
            Some(end) => rest[..end].to_string(),
            None => rest.to_string(),
        }
    }

    /// A protocol-only pattern -- one naming an L7 protocol but reading no session field,
    /// whose callback wants no session-derived datatype -- must be dispatched on the
    /// identified protocol, never on the presence of a parsed session.
    ///
    /// The action planner keeps L7 `Parse` alive past `L7OnDisc` only when a subscription
    /// needs the session. A protocol-only pattern does not, so parsing stops the moment
    /// the protocol is known and `last_session()` stays empty for the rest of the
    /// connection. Testing `SessionData::<Proto>` there is unsatisfiable forever.
    ///
    /// The predicate only reaches `L7EndHdrs`/`L4Terminated` at all when something else in
    /// the binary keeps non-matching connections alive that far -- otherwise arriving there
    /// already implies the match and the predicate is pruned. Each case below is one way
    /// for that to happen; none of them is special, which is why this is easy to hit.
    #[test]
    fn protocol_only_pattern_dispatches_on_protocol_not_session() {
        let cases: Vec<(&str, Vec<String>)> = vec![
            // A second protocol callback: neither predicate implies the other.
            (
                "two protocols",
                vec![conn_callback("a", "tls"), conn_callback("b", "ssh")],
            ),
            // A transport-level callback: every connection survives to L4Terminated.
            (
                "protocol + transport",
                vec![conn_callback("a", "tls"), conn_callback("b", "udp")],
            ),
            // A custom filter that resolves no earlier than L7OnDisc.
            (
                "protocol + streaming filter",
                vec![
                    conn_callback("a", "tls"),
                    conn_callback("b", "StreamFilter"),
                ],
            ),
            // A disjunction, which leaves both arms to be told apart at dispatch.
            (
                "disjunction",
                vec![conn_callback("a", "tls or ssh"), conn_callback("b", "udp")],
            ),
        ];

        for (name, defs) in cases {
            let mut all = vec![CONN_DATATYPE.to_string(), STREAM_FILTER.to_string()];
            all.extend(defs);
            let refs: Vec<&str> = all.iter().map(String::as_str).collect();
            let term = tx_fn(&gen_fns(&refs), "l4terminated");
            assert!(
                term.contains("last_protocol"),
                "[{}] should dispatch on last_protocol() at L4Terminated:\n{}",
                name,
                term
            );
            assert!(
                !term.contains("SessionData"),
                "[{}] no session field is read, so dispatch must not require a parsed \
                 session -- for a protocol-only pattern one is never produced, so this \
                 would never match:\n{}",
                name,
                term
            );
        }
    }

    /// Pattern that reads a session field still needs the variable that
    /// destructuring `last_session()` binds, and the planner keeps L7 `Parse` alive to
    /// populate it.
    #[test]
    fn session_field_pattern_still_destructures_the_session() {
        let term = tx_fn(
            &gen_fns(&[
                CONN_DATATYPE,
                STREAM_FILTER,
                &conn_callback("a", "tls.sni = 'example.com'"),
                &conn_callback("b", "StreamFilter"),
            ]),
            "l4terminated",
        );
        assert!(
            term.contains("SessionData :: Tls"),
            "`tls.sni` reads a session field and must bind the session:\n{}",
            term
        );
        assert!(
            term.contains("sni ()"),
            "expected the bound session to be read:\n{}",
            term
        );
    }

    /// A callback over a session-derived datatype is still gated on the session existing,
    /// via the `Option` its constructor returns -- so relaxing the protocol test does not
    /// hand it an empty session.
    #[test]
    fn session_datatype_delivery_stays_gated_on_the_session() {
        let term = tx_fn(
            &gen_fns(&[
                CONN_DATATYPE,
                SESSION_DATATYPE,
                STREAM_FILTER,
                &session_callback("a", "tls"),
                &conn_callback("b", "StreamFilter"),
            ]),
            "l4terminated",
        );
        assert!(
            term.contains("TlsHandshake :: from_session")
                && term.contains("(Some (tlshandshake) ,)"),
            "session-derived delivery must stay behind its Option guard:\n{}",
            term
        );
    }
}
