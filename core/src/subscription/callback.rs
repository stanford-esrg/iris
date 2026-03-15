use crate::L4Pdu;

/// The framework expects that any stateful callback implements this trait.
/// The user must also define the actual callback function(s), annotated with
/// the appropriate #[callback_group(...)] macros.
pub trait StreamingCallback {
    /// Initializes internal data, if applicable.
    /// Called on first packet in connection.
    fn new(first_pkt: &L4Pdu) -> Self;
    /// Clears internal data, if applicable.
    fn clear(&mut self);
}

#[derive(Debug)]
pub enum CallbackState {
    Active,
    Matching,
    Unsubscribed,
}

#[doc(hidden)]
/// Wrapper for a stateful callback that is invoked in a streaming state
/// (e.g., L4InPayload) or has multiple functions.
#[derive(Debug)]
pub struct StreamCallbackWrapper<C>
where
    C: StreamingCallback + std::fmt::Debug,
{
    state: CallbackState,
    pub callback: C,
}

impl<C> StreamCallbackWrapper<C>
where
    C: StreamingCallback + std::fmt::Debug,
{
    pub fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            state: CallbackState::Matching,
            callback: C::new(first_pkt),
        }
    }

    /// Returns true if the callback should be invoked.
    pub fn is_active(&self) -> bool {
        matches!(self.state, CallbackState::Active)
    }

    /// Invoked when a filter pattern for callback has matched.
    pub fn try_set_active(&mut self) {
        if !matches!(self.state, CallbackState::Unsubscribed) {
            self.state = CallbackState::Active;
        }
    }

    /// Invoked when the callback has unsubscribed.
    pub fn set_inactive(&mut self) {
        if matches!(self.state, CallbackState::Active) {
            self.callback.clear();
        }
        self.state = CallbackState::Unsubscribed;
    }
}

#[doc(hidden)]
/// Wrapper around a streaming callback that does not maintain
/// state (i.e., is not StreamingCallback).
#[derive(Debug)]
pub struct StatelessCallbackWrapper {
    state: CallbackState,
}

impl StatelessCallbackWrapper {
    pub fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            state: CallbackState::Matching,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, CallbackState::Active)
    }

    pub fn try_set_active(&mut self) {
        if !matches!(self.state, CallbackState::Unsubscribed) {
            self.state = CallbackState::Active;
        }
    }

    pub fn set_inactive(&mut self) {
        self.state = CallbackState::Unsubscribed;
    }
}

#[doc(hidden)]
/// Wrapper around a boolean value to help ensure that a
/// callback is invoked once per connection or session if that
/// is its expected behavior. The framework uses this wrapper when
/// a subscription specifies a streaming filter and a non-streaming
/// callback.
#[derive(Debug)]
pub struct StaticCallbackWrapper {
    pub invoked: bool,
}
impl StaticCallbackWrapper {
    // Note - easier for code generation if all `new` fns
    // take in `L4Pdu` ref.
    pub fn new(_: &L4Pdu) -> Self {
        Self { invoked: false }
    }
    pub fn should_invoke(&self) -> bool {
        !self.invoked
    }
    pub fn set_invoked(&mut self) {
        self.invoked = true;
    }
}
