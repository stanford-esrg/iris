use std::collections::HashMap;

/// Generate code for the filter applied to every packet that hits an RX core.
/// This returns `true` if a packet should continue to the connection tracker
/// and `false` otherwise.
///
/// Note: packet-level subscriptions are not yet supported. In the future, this
/// filter might also apply filters to forward packets to packet-level callbacks.
use crate::codegen::binary_to_tokens;
use heck::CamelCase;
use iris_core::filter::ast::*;
use iris_core::filter::pred_ptree::{PredPNode, PredPTree};
use proc_macro2::{Ident, Span};
use quote::quote;

pub(crate) fn gen_packet_filter(ptree: &PredPTree) -> proc_macro2::TokenStream {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    // Ensure root matches are covered
    if ptree.root.is_terminal {
        update_body(&mut body, &ptree.root);
    }

    gen_packet_filter_util(&mut body, &ptree.root, ptree);

    // Extract outer protocol (ethernet)
    let outer = Ident::new("ethernet", Span::call_site());
    let outer_type = Ident::new(&outer.to_string().to_camel_case(), Span::call_site());

    quote! {
        if let Ok(#outer) = &iris_core::protocols::packet::Packet::parse_to::<iris_core::protocols::packet::#outer::#outer_type>(mbuf) {
            #( #body )*
        }
        return false;
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

fn update_body(body: &mut Vec<proc_macro2::TokenStream>, node: &PredPNode) {
    if node.is_terminal {
        // Return true on first match
        body.push(quote! { return true; });
    }
    if !node.deliver.is_empty() {
        panic!("Packet-level subscriptions not yet implemented");
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
    update_body(&mut body, node);

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
    update_body(&mut body, node);
    let mut statics = HashMap::new();
    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, &mut statics);
    assert!(statics.is_empty());
    code.push(quote! {
        if #pred_tokenstream {
            #( #body )*
        }
    });
}
