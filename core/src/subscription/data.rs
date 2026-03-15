use crate::conntrack::conn::conn_state::StateTxData;
use crate::L4Pdu;

/// Interface for datatypes that must be "tracked" throughout
/// all or part of a connection.
///
/// The datatype can optionally be tagged as #[expensive], which
/// indicates that the runtime should track which subscriptions require
/// it and drop the Tracked data if all of those subscriptions go out
/// of scope. This may limit how much the compiler can optimize the
/// filter predicates, but it is generally valuable if the datatype is memory-
/// or computationally-intensive (e.g., a list of packets).
pub trait Tracked {
    /// Initialize internal data. Invoked on first PDU in connection.
    /// Note that this first PDU will also be received in `update`.
    fn new(first_pkt: &L4Pdu) -> Self;
    /// Invoked for each newly received PDU.
    /// Update phases of interest must be specified as attributes, e.g.
    /// #[invoke(L4InPayload)]
    fn update(&mut self, pdu: &L4Pdu);
    /// Invoked for phase transitions of interest, which must be specified
    /// as attributes.
    fn phase_tx(&mut self, tx: &StateTxData);
    /// Utility method to clear internal data.
    /// Recommended to implement for memory-intensive datatypes.
    fn clear(&mut self);
}

/// The string literal representing a matched filter.
/// Used if multiple filters are available for the same callback
/// (specified in input file).
pub type FilterStr<'a> = &'a str;

/// Must be implemented as a trait; cannot define inherent `impl`
/// for foreign type.
#[doc(hidden)]
pub trait StringToTokens {
    fn from_string(filter: &String) -> proc_macro2::TokenStream;
}
impl StringToTokens for FilterStr<'_> {
    /// Convert a filter string into a token representation at compile-time.
    #[doc(hidden)]
    fn from_string(filter: &String) -> proc_macro2::TokenStream {
        let str = syn::LitStr::new(filter, proc_macro2::Span::call_site());
        quote::quote! { &#str }
    }
}

/// If a datatype is specified as "expensive", it is wrapped in this
/// so that we can track when it's still needed by active subscriptions.
/// TODO need to redo this; currently dead code.
#[doc(hidden)]
pub struct TrackedDataWrapper<T>
where
    T: Tracked + std::fmt::Debug,
{
    /// The wrapped tracked data.
    pub data: T,
    /// Has terminally matched some subscription; continue
    /// tracking until the datatype has reached its ending point.
    pub term: bool,
    /// Count of subscriptions that have matched non-terminally.
    pub nonterm: Option<u32>,
}
