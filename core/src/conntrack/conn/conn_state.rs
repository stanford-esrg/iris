///! Management for per-connection state machines.
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, str::FromStr};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{
    conntrack::Layer,
    protocols::{stream::SessionProto, Session},
};

#[doc(hidden)]
/// Current state of the Layer in per-connection state machine.
/// Based on what it has seen so far in the connection.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Ord, PartialOrd, Hash, EnumIter)]
pub enum LayerState {
    /// Determining protocol
    /// For L4, this indicates pre-handshake
    Discovery,
    /// Headers (TCP hshk, TLS hshk, HTTP hdrs, etc.)
    /// Contains number of packets seen in headers.
    Headers,
    /// Headers done; new packets expected to be in layer payload
    Payload,
    /// This Layer and all child layers* should no longer
    /// receive packets. This will be set based on the
    /// result of a filter.
    None,
}

/// The possible state transitions that a data type, filter, or callback
/// (function and/or struct) can be associated with.
/// Developers should refer to these in macros.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, EnumIter, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum StateTransition {
    /// On first packet in connection
    L4FirstPacket = 0,
    /// Complete TCP handshake has been observed.
    /// Note that this should not be used to indicate the beginning
    /// of payload, as payload may overlap with the handshake.
    L4EndHshk,

    /// Streaming anywhere in L4 connection, including TCP handshake.
    /// Streaming anywhere in TCP or UDP connection, including TCP handshake.
    // Packets are not TCP-reassembled.
    InL4Conn,
    /// Streaming anywhere in TCP or UDP connection, including TCP handshake.
    /// Packets are TCP-reassembled.
    InL4Stream,

    /// On L7 protocol identification
    L7OnDisc,
    /// On L6/L7 headers parsed
    L7EndHdrs,
    /// L4 connection terminated by FIN/ACK sequence or timeout
    L4Terminated,

    /// Packet-level datatype. Any filter or datatype tagged with this
    /// is built from a single, connectionless packet (Mbuf).
    ///
    /// Packet-level filters cannot be combined with datatypes or callbacks
    /// that require connection/session tracking. Packet-level datatypes can only be
    /// requested in higher-level filters/callbacks if a streaming level
    /// (e.g., InL4Conn) is specified.
    ///
    /// Internal notes:
    /// - This must be last in the enum variant list.
    /// - In the connection tracker, this is used as a no-op state transition.
    Packet,
}

impl std::fmt::Display for StateTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InL4Conn => write!(f, "InL4Conn"),
            Self::InL4Stream => write!(f, "InL4Stream"),
            _ => write!(f, "{:?}", self),
        }
    }
}

// https://doc.rust-lang.org/reference/items/enumerations.html#casting
impl StateTransition {
    #[doc(hidden)]
    pub fn as_usize(&self) -> usize {
        *self as u8 as usize
    }

    #[doc(hidden)]
    pub fn from_usize(i: usize) -> Self {
        for level in StateTransition::iter() {
            if level.as_usize() == i {
                return level;
            }
        }
        panic!("Cannot build StateTransition from {}", i);
    }

    #[doc(hidden)]
    pub fn name(&self) -> &str {
        match self {
            StateTransition::L4FirstPacket => "L4FirstPacket",
            StateTransition::L4EndHshk => "L4EndHshk",
            StateTransition::InL4Conn => "InL4Conn",
            StateTransition::InL4Stream => "InL4Stream",
            StateTransition::L4Terminated => "L4Terminated",
            StateTransition::L7OnDisc => "L7OnDisc",
            StateTransition::L7EndHdrs => "L7EndHdrs",
            StateTransition::Packet => "L4Pdu",
        }
    }

    #[doc(hidden)]
    pub fn in_transport(&self) -> bool {
        self.name().contains("L4")
    }

    #[doc(hidden)]
    pub fn is_streaming(&self) -> bool {
        self.name().contains("In")
    }

    #[doc(hidden)]
    pub fn layer_idx(&self) -> Option<usize> {
        if self.name().contains("L7") {
            return Some(0);
        }
        None
    }

    /// Returns Greater if self > Other, Less if self < Other, Equal if self == Other,
    /// and Unknown if the two cannot be compared (different layers).
    #[doc(hidden)]
    pub fn compare(&self, other: &StateTransition) -> StateTxOrd {
        if self == other {
            return StateTxOrd::Equal;
        }
        // L4Pdu is any
        if matches!(self, StateTransition::Packet) || matches!(other, StateTransition::Packet) {
            return StateTxOrd::Any;
        }

        // End of connection is always greatest
        if matches!(self, StateTransition::L4Terminated)
            || matches!(other, StateTransition::L4Terminated)
        {
            return StateTxOrd::from_ord(self.cmp(other));
        }
        // Start of connection is always lowest
        if matches!(self, StateTransition::L4FirstPacket)
            || matches!(other, StateTransition::L4FirstPacket)
        {
            return StateTxOrd::from_ord(self.cmp(other));
        }

        // TCP handshake must complete before anything
        // that requires data from both endpoints
        if matches!(self, StateTransition::L4EndHshk) || matches!(other, StateTransition::L4EndHshk)
        {
            if matches!(self, StateTransition::L7EndHdrs)
                || matches!(other, StateTransition::L7EndHdrs)
            {
                return StateTxOrd::from_ord(self.cmp(other));
            }
        }

        // Different layers
        if self.name().contains("L4") && !other.name().contains("L4")
            || self.name().contains("L7") && !other.name().contains("L7")
        {
            return StateTxOrd::Unknown;
        }

        // Exceptions to the ordering rule
        if matches!(self, StateTransition::L4EndHshk) {
            return StateTxOrd::Unknown;
        }

        // Streaming states throughout connection
        if matches!(
            self,
            StateTransition::InL4Conn | StateTransition::InL4Stream
        ) || matches!(
            self,
            StateTransition::InL4Stream | StateTransition::InL4Conn
        ) {
            return StateTxOrd::Unknown;
        }

        // Enum must be in listed order above.
        StateTxOrd::from_ord(self.cmp(other))
    }
}

/// Ordering of State Transitions in connection processing lifetime.
/// Used to insert filter predicates in trees.
/// Note: within a Layer, the StateTransitions have to be listed in order.
#[doc(hidden)]
#[derive(Debug, Eq, PartialEq)]
pub enum StateTxOrd {
    /// No ordering guaranteed (e.g., L4InPayload + L7OnDisc)
    Unknown,
    /// Not applicable
    Any,
    /// `self` > `other`
    Greater,
    /// `self` < `other`
    Less,
    /// `self`` == `other`
    Equal,
}

impl StateTxOrd {
    pub(crate) fn from_ord(ordering: Ordering) -> StateTxOrd {
        match ordering {
            Ordering::Greater => StateTxOrd::Greater,
            Ordering::Less => StateTxOrd::Less,
            Ordering::Equal => StateTxOrd::Equal,
        }
    }
}

/// The State Transitions that a connection can encounter.
/// For `InX` Levels, the state transition is triggered if
/// a streaming callback or filter changed match state (i.e.,
/// was and is no longer active).
/// Number of variants; used to size the `refresh_at` array
pub(crate) const NUM_STATE_TRANSITIONS: usize = 7;

/// State Transitions with associated data,
/// used as wrappers for users to request as a parameter to a function.
#[derive(Debug)]
pub enum StateTxData<'a> {
    L7OnDisc(SessionProto),
    L7EndHdrs(&'a Session),
    Null,
}

impl<'a> StateTxData<'a> {
    #[doc(hidden)]
    pub fn from_tx(state: &StateTransition, layer: &'a Layer) -> Self {
        match layer {
            Layer::L7(layer) => match state {
                StateTransition::L7OnDisc => Self::L7OnDisc(layer.get_protocol()),
                StateTransition::L7EndHdrs => {
                    Self::L7EndHdrs(layer.sessions.last().expect("L7EndHdrs without session"))
                }
                _ => Self::Null,
            },
        }
    }

    // Should be the same as the corresponding StateTransition. For testing only.
    #[allow(dead_code)]
    pub(crate) fn as_usize(&self) -> usize {
        match self {
            StateTxData::L7OnDisc(_) => StateTransition::L7OnDisc.as_usize(),
            StateTxData::L7EndHdrs(_) => StateTransition::L7EndHdrs.as_usize(),
            StateTxData::Null => panic!("Invalid StateTxData"),
        }
    }
}

#[doc(hidden)]
impl FromStr for StateTransition {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "L4FirstPacket" => Ok(StateTransition::L4FirstPacket),
            "L4EndHshk" => Ok(StateTransition::L4EndHshk),
            "InL4Conn" => Ok(StateTransition::InL4Conn),
            "InL4Stream" => Ok(StateTransition::InL4Stream),
            // Backward compat: old API used `InL4Conn(reassemble)` to request TCP reassembly.
            "InL4Conn(reassemble)" => Ok(StateTransition::InL4Stream),
            "L4Terminated" => Ok(StateTransition::L4Terminated),
            "L7OnDisc" => Ok(StateTransition::L7OnDisc),
            "L7EndHdrs" => Ok(StateTransition::L7EndHdrs),
            "Packet" => Ok(StateTransition::Packet),
            _ => Err(format!("Invalid StateTransition: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_level_raw() {
        assert_eq!(
            StateTransition::Packet.as_usize(),
            NUM_STATE_TRANSITIONS,
            "{} != {}",
            StateTransition::Packet.as_usize(),
            NUM_STATE_TRANSITIONS
        );
    }
}
