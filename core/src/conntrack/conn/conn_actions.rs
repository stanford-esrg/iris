use super::conn_state::{StateTransition, NUM_STATE_TRANSITIONS};
use bitmask_enum::bitmask;

/// Possible actions to be taken on a connection
#[bitmask(u8)]
#[bitmask_config(vec_debug)]
pub enum Actions {
    /// Invoke Tracked datatype "Update" API at this Layer to pass new frames
    /// to users' subscribed datatype(s).
    Update,
    /// Indicates that some Layer-specific stateful parsing is required.
    /// For L4, this is TCP reassembly. For L6/L7, this indicates a
    /// stateful application-layer protocol parser should be invoked.
    Parse,
    /// Indicates that some child layer(s) require actions.
    PassThrough,
    /// Track the connection, updating with state transitions.
    Track,
}

/// Basic representation of Actions
/// TODO change to single bitmask in the future
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct TrackedActions {
    // Currently-active actions (as bitmask)
    pub active: Actions,
    // Bitmask of actions that should be refreshed at each stage
    pub refresh_at: [Actions; NUM_STATE_TRANSITIONS],
}

fn fmt_actions(actions: Actions) -> String {
    if actions.is_none() {
        return "-".to_string();
    }
    let mut parts: Vec<&'static str> = Vec::new();
    if actions.intersects(Actions::Update) {
        parts.push("Update");
    }
    if actions.intersects(Actions::Parse) {
        parts.push("Parse");
    }
    if actions.intersects(Actions::PassThrough) {
        parts.push("PassThrough");
    }
    if actions.intersects(Actions::Track) {
        parts.push("Track");
    }
    parts.join(",")
}

// Clippy #new_without_default warning for pub types
impl Default for TrackedActions {
    fn default() -> Self {
        Self::new()
    }
}

impl TrackedActions {
    /// Initialize empty
    pub fn new() -> Self {
        Self {
            active: Actions { bits: 0 },
            refresh_at: [Actions { bits: 0 }; NUM_STATE_TRANSITIONS],
        }
    }

    /// Set up actions for executing a state transition
    /// Clear out actions that will need to be re-checked
    /// Also clear `PassThrough`, which will be reset after the
    /// state TX if child layer(s) have actions set.
    #[inline]
    pub fn start_state_tx(&mut self, state: StateTransition) {
        self.active &= self.refresh_at[state.as_usize()].not();
        self.active &= (Actions::PassThrough).not();
    }

    /// Clear an action
    #[inline]
    pub fn clear(&mut self, actions: &Actions) {
        self.active &= actions.not();
    }

    /// Clear intersection of actions with `peer`, including `update_at`
    #[inline]
    pub fn clear_intersection(&mut self, peer: &TrackedActions) {
        self.clear(&peer.active);
        for i in 0..NUM_STATE_TRANSITIONS {
            self.refresh_at[i] &= peer.refresh_at[i].not();
        }
    }

    /// All actions are empty; nothing to do for future packets in connection.
    #[inline]
    pub fn drop(&self) -> bool {
        self.active.is_none()
    }

    #[inline]
    pub fn has_next_layer(&self) -> bool {
        self.active.intersects(Actions::PassThrough)
    }

    #[inline]
    pub fn set_next_layer(&mut self) {
        self.active |= Actions::PassThrough;
    }

    #[inline]
    pub fn needs_parse(&self) -> bool {
        self.active.intersects(Actions::Parse)
    }

    #[inline]
    pub fn needs_update(&self) -> bool {
        self.active.intersects(Actions::Update)
    }

    /// Append TrackedActions. Used at compile-time and
    /// when building up actions in runtime filters.
    #[inline]
    pub fn extend(&mut self, other: &TrackedActions) {
        self.active |= other.active;
        for i in 0..NUM_STATE_TRANSITIONS {
            self.refresh_at[i] |= other.refresh_at[i];
        }
    }

    /// When a filter has definitively matched AND it will be required
    /// for the rest of the connection (i.e., connection-level subscription),
    /// remove it from all future state transition "refresh" slots.
    pub fn set_terminal_action(&mut self, action: &Actions) {
        for i in 0..NUM_STATE_TRANSITIONS {
            self.refresh_at[i] &= action.not();
        }
    }

    /// Returns `true` if this state TX can be safely skipped
    /// (i.e., nothing needs to be delivered and no actions need refresh here)
    pub fn skip_tx(&self, tx: &StateTransition) -> bool {
        self.refresh_at[tx.as_usize()].is_none()
    }
}

impl std::fmt::Display for TrackedActions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.active.is_none() {
            return write!(f, "-");
        }

        let active_str = fmt_actions(self.active);
        let mut state_txs: Vec<(String, Actions)> = Vec::new();
        for i in 0..NUM_STATE_TRANSITIONS {
            let a = self.refresh_at[i];
            if !a.is_none() {
                state_txs.push((StateTransition::from_usize(i).to_string(), a));
            }
        }

        assert!(
            !state_txs.is_empty(),
            "Active actions but no refresh points?"
        );

        // All actions have same refresh point
        if !self.active.is_none() && state_txs.iter().all(|(_, a)| *a == self.active) {
            let state_tx_list = state_txs
                .into_iter()
                .map(|(u, _)| u)
                .collect::<Vec<_>>()
                .join(",");
            return write!(f, "{}->({})", active_str, state_tx_list);
        }

        // Map actions to refresh point
        let mut state_tx_list: Vec<Actions> = Vec::new();
        for (_, a) in &state_txs {
            if !state_tx_list.contains(a) {
                state_tx_list.push(*a);
            }
        }
        let action_set = state_tx_list
            .into_iter()
            .map(fmt_actions)
            .collect::<Vec<_>>()
            .join(",");
        let state_tx_list = state_txs
            .into_iter()
            .map(|(u, a)| format!("{}={}", u, fmt_actions(a)))
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}->({})", action_set, state_tx_list)
    }
}
