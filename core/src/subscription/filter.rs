use super::FilterResult;
use crate::L4Pdu;

/// The framework expects that any stateful filter implements this trait.
/// The user must also define the actual filter function(s), annotated with
/// the appropriate #[filter_group(...)] macros. Each filter function must
/// return a FilterResult.
pub trait StreamingFilter {
    /// Initialize internal data, if applicable. Invoked on first packet.
    fn new(first_packet: &L4Pdu) -> Self;
    /// Clears internal data, if applicable.
    fn clear(&mut self);
}

#[doc(hidden)]
/// If a streaming filter is specified as "expensive", it is wrapped in this
/// so that we can track when it's still needed by active subscriptions.
/// When it is cleared, it will no longer be invoked.
#[derive(Debug)]
pub struct StreamFilterWrapper<F>
where
    F: StreamingFilter + std::fmt::Debug,
{
    /// The stateful filter.
    pub filter: F,
    /// This filter has definitively matched (returned FilterResult).
    pub matched: FilterResult,
}

impl<F> StreamFilterWrapper<F>
where
    F: StreamingFilter + std::fmt::Debug,
{
    /// Create a new filter wrapper.
    pub fn new(first_pkt: &L4Pdu) -> Self {
        StreamFilterWrapper {
            filter: F::new(first_pkt),
            matched: FilterResult::Continue,
        }
    }

    /// Returns true if the filter should be invoked.
    pub fn is_active(&self) -> bool {
        matches!(self.matched, FilterResult::Continue)
    }

    /// Returns true if the filter has matched
    pub fn matched(&self) -> bool {
        matches!(self.matched, FilterResult::Accept)
    }

    /// Records a filter result
    pub fn record_result(&mut self, result: FilterResult) {
        self.matched = result;
        match self.matched {
            FilterResult::Accept | FilterResult::Drop => {
                self.filter.clear();
            }
            _ => {}
        }
    }
}

#[doc(hidden)]
/// Wrapper for a filter that is stateless but may be invoked
/// in a streaming state and thus cannot be trivially reapplied.
#[derive(Debug)]
pub struct StatelessFilterWrapper {
    pub matched: FilterResult,
}

impl StatelessFilterWrapper {
    /// Create a new filter wrapper.
    pub fn new() -> Self {
        Self {
            matched: FilterResult::Continue,
        }
    }

    /// Returns true if the filter should be invoked.
    pub fn is_active(&self) -> bool {
        matches!(self.matched, FilterResult::Continue)
    }

    /// Returns true if the filter has matched
    pub fn matched(&self) -> bool {
        matches!(self.matched, FilterResult::Accept)
    }

    /// Records a filter result
    pub fn record_result(&mut self, result: FilterResult) {
        self.matched = result;
    }
}
