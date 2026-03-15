use std::collections::HashMap;

/// Generate code for the filter applied to every packet that hits an RX core.
/// This returns `true` if a packet should continue to the connection tracker
/// and `false` otherwise.
use crate::codegen::binary_to_tokens;
use heck::CamelCase;
use iris_core::filter::ast::*;
use iris_core::filter::pred_ptree::{PredPNode, PredPTree};
use proc_macro2::{Ident, Span};
use quote::quote;

pub(crate) fn gen_packet_filter(ptree: &PredPTree) -> proc_macro2::TokenStream {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    // Store result in variable if there may be a callback invoked.
    // Otherwise, return on first match.
    if !ptree.deliver.is_empty() {
        body.push(quote! { let mut matched = false; });
    }

    // Ensure root delivery/matches are covered
    if !ptree.root.deliver.is_empty() || ptree.root.is_terminal {
        update_body(&mut body, &ptree.root, ptree);
    }

    gen_packet_filter_util(&mut body, &ptree.root, &ptree);

    // Return value
    body.push(match ptree.deliver.is_empty() {
        true => quote! { return false; },
        false => quote! { return matched; },
    });

    // Extract outer protocol (ethernet)
    let outer = Ident::new("ethernet", Span::call_site());
    let outer_type = Ident::new(&outer.to_string().to_camel_case(), Span::call_site());

    quote! {
        if let Ok(#outer) = &iris_core::protocols::packet::Packet::parse_to::<iris_core::protocols::packet::#outer::#outer_type>(mbuf) {
            #( #body )*
        }
        false
    }
}

fn gen_packet_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PredPNode,
    tree: &PredPTree,
) {
    let mut first_unary = true;
    for child in node.children.iter().filter(|n| n.pred.on_packet()) {
        match &child.pred {
            Predicate::Unary { protocol } => {
                add_unary_pred(
                    code,
                    child,
                    node.pred.get_protocol(),
                    protocol,
                    first_unary,
                    tree,
                );
                first_unary = false;
            }
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => {
                add_binary_pred(code, child, protocol, field, op, value, tree);
            }
            _ => panic!("Unexpected predicate in packet filter: {:?}", child.pred),
        }
    }
}

fn update_body(body: &mut Vec<proc_macro2::TokenStream>, node: &PredPNode, tree: &PredPTree) {
    if node.is_terminal {
        // If there won't be anything that needs to be delivered,
        // return `true` immediately
        if tree.deliver.is_empty() {
            body.push(quote! { return true; });
        } else {
            body.push(quote! { ret = true; });
        }
    }
    if !node.deliver.is_empty() {
        panic!("Packetlevel subscriptions not yet implemented");
    }
}

fn add_unary_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PredPNode,
    outer_protocol: &ProtocolName,
    protocol: &ProtocolName,
    first_unary: bool,
    tree: &PredPTree,
) {
    let outer = Ident::new(outer_protocol.name(), Span::call_site());
    let ident = Ident::new(protocol.name(), Span::call_site());
    let ident_type = Ident::new(&ident.to_string().to_camel_case(), Span::call_site());

    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_packet_filter_util(&mut body, node, tree);
    update_body(&mut body, node, tree);

    if first_unary {
        code.push(quote! {
            if let Ok(#ident) = &iris_core::protocols::packet::Packet::parse_to::<iris_core::protocols::packet::#ident::#ident_type>(#outer) {
                #( #body )*
            }
        });
    } else {
        code.push(quote! {
            else if let Ok(#ident) = &iris_core::protocols::packet::Packet::parse_to::<iris_core::protocols::packet::#ident::#ident_type>(#outer) {
                #( #body )*
            }
        });
    }
}

fn add_binary_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PredPNode,
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
    tree: &PredPTree,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_packet_filter_util(&mut body, node, tree);
    update_body(&mut body, node, tree);
    let mut statics = HashMap::new();
    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, &mut statics);
    assert!(statics.is_empty());
    code.push(quote! {
        if #pred_tokenstream {
            #( #body )*
        }
    });
}
