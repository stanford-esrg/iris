use crate::{L4Pdu, StateTransition};
use bitvec::{array::BitArray, order::Lsb0};
use quote::quote;

/// Interface for datatypes that must be "tracked" throughout
/// all or part of a connection.
/// Datatypes tagged with "track" must implement this trait.
///
/// Each tracked datatype can optionally be tagged as "track", which
/// indicates that the runtime should track which subscriptions require
/// it and drop the Tracked data if all of those subscriptions go out
/// of scope. This may limit how much the compiler can optimize the
/// filter predicates, but it is generally valuable if the datatype is memory-
/// or computationally-intensive (e.g., a list of packets) and is only needed
/// for a small subset of connections.
pub trait Tracked {
    /// Initialize internal data. Invoked on first PDU in connection.
    /// Note that this first PDU will also be received in `update`.
    fn new(first_pkt: &L4Pdu) -> Self;
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
    fn from_string(filter: &str) -> proc_macro2::TokenStream;
}

impl StringToTokens for FilterStr<'_> {
    /// Convert a filter string into a token representation at compile-time.
    #[doc(hidden)]
    fn from_string(filter: &str) -> proc_macro2::TokenStream {
        let str = syn::LitStr::new(filter, proc_macro2::Span::call_site());
        quote! { &#str }
    }
}

type RefreshAtState = BitArray<[u8; 1], Lsb0>;

#[derive(Debug)]
#[doc(hidden)]
pub enum DatatypeState {
    /// Should be updated
    Active,
    /// Pending (in state transition)
    Pending,
    /// No longer active at all
    Inactive,
}

/// If a datatype is specified as "expensive", it is wrapped in this
/// so that we can track when it's still needed by active subscriptions.
#[doc(hidden)]
pub struct TrackedDataWrapper<T>
where
    T: Tracked + std::fmt::Debug,
{
    /// The wrapped tracked data.
    pub data: T,
    /// Whether and until when to continue updating.
    state: DatatypeState,
    /// States to "refresh at"
    refresh_at: RefreshAtState,
}

impl<T> TrackedDataWrapper<T>
where
    T: Tracked + std::fmt::Debug,
{
    pub fn new(pdu: &L4Pdu) -> Self {
        Self {
            data: T::new(pdu),
            state: DatatypeState::Active,
            refresh_at: BitArray::ZERO,
        }
    }

    pub fn start_state_tx(&mut self, tx: &StateTransition) {
        if matches!(self.state, DatatypeState::Active) &&
           self.refresh_at[tx.as_usize()]
        {
            self.state = DatatypeState::Pending;
        }
    }

    pub fn set_match_until(&mut self, txs: usize) {
        self.state = DatatypeState::Active;
        self.refresh_at.as_raw_mut_slice()[0] |= txs as u8;
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, DatatypeState::Active)
    }

    pub fn end_state_tx(&mut self) {
        if matches!(self.state, DatatypeState::Pending) {
            self.data.clear();
            self.state = DatatypeState::Inactive;
            self.refresh_at.fill(false);
        }
    }
}

mod tests {
    #[test]
    fn test_num_state_tx() {
        assert!(
            crate::conntrack::conn::conn_state::NUM_STATE_TRANSITIONS <=
            u8::BITS as usize
        );
    }
}
