# Iris: Expressive Traffic Analysis for the Modern Internet

Iris is an open-source development framework for traffic analysis research.

Iris provides high-level abstractions, like [Zeek](https://zeek.org), alongside low-level, performant access to connection data. Iris absorbs the common, tedious tasks associated with traffic analysis, leaving researchers to focus on what is relevant to their use-cases. In experiments on the Stanford University network, we find that Iris can execute multiple concurrent, complex analsysis tasks at 100Gbps+ on a single commodity server.

## Note for Artifact Evaluation

Meaningfully replicating the experiments in the Iris paper requires access to live traffic.
However, Iris supports offline development and evaluation using packet captures.
Additionally, the Iris *compiler*---which translates user-defined code and specifications into an end-to-end analysis pipeline---is a key aspect of the system.

Full Rust crate documentation for using and developing against Iris will be improved and released in the coming weeks.

## Installation and Setup

Iris requires installing Rust and DPDK.
Follow the instructions in [INSTALL.md](INSTALL.md) to set up Iris.

## Iris Programming Framework: Overview

An Iris application consists of *one or more* traffic *subscriptions*, each of which consists of filters, data types, and callbacks over tracked connections.

* **Subscription Programming Model.** Iris supports analyzing packets, reassembled streams, and parsed application sessions within a bidirectional, "five-tuple"-defined connection. Each subscription includes a filter (what data is of interest?), a set of data types (what format should the data be delivered in?), and callback (what to do with the data?).

* **User-Defined Filters, Data Types, and Callbacks.** Iris provides complete programmable control over filter predicates, data transformation and construction, and callback (analysis) code.

* **Connection Scope.** Iris scopes subscriptions to inferred connections, i.e., bidirectional packet streams associated with the same five-tuple until a FIN/ACK sequence, RST, or user-configurable inactivity timeout. Connections may not fully establish (i.e., an unanswered SYN is treated as a ``connection'' by Iris).
Applications that analyze data across connections can be built on top of Iris, much like Iris is built on top of DPDK.

* **State Machines.** To expose both common abstractions and low-level access to connection data, Iris presents connections to user code as a set of protocol-specific state machines that user-defined functions can hook into.
Iris currently supports the states and state transitions described in [DataLevel](core/src/conntrack/conn/conn_state.rs#L29).
Iris processes packets in a connection as they arrive, advancing the connection through its state machines. Note that some events carry data (e.g., observed packet, parsed application headers).

### Data Types

Iris defines three primitive data types: raw packets, reassembled streams, and parsed fields available within any state transition (["DataLevel"](./core/src/conntrack/conn/conn_state.rs#L29)).
User-defined Iris data types are defined in Rust and can access any of these primitive data types to create higher-level abstractions, which are then made available to filters and callbacks.

A variety of default data types are provided in the [datatypes](./datatypes) crate.

For example, to request TLS handshakes, a data type defined in [datatypes](./datatypes/src/tls_handshake.rs), a user could write a callback:

```rust
/// Filter for TLS;
#[callback("tls")]
/// ...and request a parsed `TlsHandshake` in the callback:
fn callback(tls: &TlsHandshake) {}
```

A callback can request multiple data types, e.g.:

```rust
#[callback("tls")]
/// ...or request both the parsed `TlsHandshake` and a connection record
fn callback(tls: &TlsHandshake, conn: &ConnRecord) {}
```

Users can also define their own data types, using the #[datatype] macro for the parent struct and the #[dataype_fn] for included methods.

For example, the [openvpn](./examples/open_vpn) example defines multiple custom data types.

```rust
/// Identify data types using the `[datatype]` macro
#[datatype]
pub struct OpenVPNOpcode {
    // ... fields
}

/// Implement the data type: constructor and "update" functions
impl OpenVPNOpcode {
    /// The "new" function must take in a PDU
    /// This will be invoked at the beginning of each connection, i.e.,
    /// an `OpenVPNOpCode` struct will be initialized and maintained
    /// for each connection (as long as some subscription requires it).
    pub fn new(_pdu: &L4Pdu) -> Self {
        // ... body
    }

    /// Methods can take in any Iris data types.
    /// They must specify the name of the data type,
    /// as well as *when* the callback should be invoked
    /// within the lifetime of a connection
    /// (here, anywhere in a TCP or UDP connection payload).
    #[datatype_group("OpenVPNOpcode,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        // ... body
    }
}
```

Note: in some cases, Iris can infer the [DataLevel](core/src/conntrack/conn/conn_state.rs#L29) (e.g., a "tls" callback requesting a TLS handshake is delivered as soon as the TLS handshake is ready).
The compiler will throw an error if a DataLevel is required and missing.

### Filters

Iris supports a Wireshark-like filter syntax that builds on that introduced by [Retina](https://stanford-esrg.github.io/retina/retina_filtergen/index.html) for filtering on protocols and protocol fields.

Iris also supports defining custom (stateful or stateless) filters, similar to data types. Custom filter functions must return a `FilterResult` (Accept, Drop, or Continue). Stateful filters (i.e., those associated with a struct) must implement the [StatefulFilter](./core/src/subscription/filter.rs) trait.

For example, the [basic](./examples/basic) filters for "short" connections:

```rust
/// Filters can be stateful;
/// identify a struct as a filter using the #[filter] macro
#[filter]
struct ShortConnLen {
    len: usize,
}

/// Every stateful filter must implement the `StreamingFilter` trait.
impl StreamingFilter for ShortConnLen {
    /// ...which includes a constructor
    /// As with all Iris abstractions, each struct is scoped to a connection.
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { len: 0 }
    }
    /// ...and a "destructor"
    /// This optionally clears any internally-stored data in
    /// order to free up memory when the filter is out-of-scope.
    fn clear(&mut self) {}
}

impl ShortConnLen {
    /// As with data types, filter functions must specify
    /// when they should be invoked.
    #[filter_group("ShortConnLen,level=L4InPayload")]
    fn update(&mut self, _: &L4Pdu) -> FilterResult {
        self.len += 1;
        if self.len > 10 {
            // Dropping connections early helps Iris
            // quickly discard out-of-scope traffic.
            return FilterResult::Drop;
        }
        FilterResult::Continue
    }

    /// As with data types, stateful filters can have multiple functions.
    /// This one is invoked on connection termination (timeout or
    /// TCP FIN/ACK sequence).
    #[filter_group("ShortConnLen,level=L4Terminated")]
    fn terminated(&self) -> FilterResult {
        if self.len <= 10 {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }
}
```

### Callbacks

Callbacks execute arbitrary Rust code with access to one or more Iris datatypes for traffic that meets filter conditions. Callbacks that stream data within a state (e.g., to analyze video segments every ten seconds) are called repeatedly within a connection until they unsubscribe.

Callbacks can stream data over the course of a connection, optionally returning `false` to unsubscribe (i.e., stop receiving data).
For example, the [video](./examples/ml_qos/) example streams likely video traffic to perform inference:

```rust
/// Callbacks can specify a filter
/// i.e., the functions in this callback will be invoked for all
/// "tls" connections.
#[callback("tls")]
#[derive(Debug, Serialize)]
struct Predictor {
    // ...
}

/// Streaming callbacks must implement this trait
/// (similar to the StreamingFilter trait)
impl StreamingCallback for Predictor {
    fn new(_first_pkt: &L4Pdu) -> Predictor { /* ... */ }
    fn clear(&mut self) { /* ... */ }
}

/// Defining callback functions is similar to filter functions.
impl Predictor {
    /// Tag the callback with when it should be invoked, and request
    /// arbitrary data types.
    /// By requesting `L4InPayload` updates, this function is invoked
    /// on every new packet in the connection.
    #[callback_group("Predictor,level=L4InPayload")]
    fn update(&mut self, tracked: &FeatureChunk, start: &StartTime) -> bool {
        // ...
    }
}
```

## Applications

The instructions below demonstrate how to build the applications evaluated in Section 6.3 of the paper:

* [Measuring Security Practices](./examples/measuring_sec/)
* [Fingerprinting OpenVPN](./examples/open_vpn/)
* [Predicting Video Resolution](./examples/ml_qos/)
* [All examples combined](./examples/combined/)

### Building Applications

To build all applications:

```rust
cargo build --release
```

When each application builds, you will see a printout of the match-action decision trees generated by the Iris [compiler](./compiler/), as described in Section 5.

### Running Applications

Running the OpenVPN example requires relatively long-lived connections, and the "Predicting Video Resolution" example also requires a trained model. To evaluate Iris in offline mode (i.e., from a packet capture) we recommend running the `measuring_sec` example.

```
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/measuring_sec --config configs/offline.toml
```

This will read the packet capture specified in [offline.toml](./configs/offline.toml), currently the [small_flows](./traces/small_flows.pcap) pcap.
It will produce files with a report of application-layer and high-level connection data seen in the packet capture.

### Writing an Application

Iris is a development framework, and the [examples](./examples/) directory includes multiple example Iris applications.
We encourage reviewers to play around with these examples!
You can add (compatible) data types to any custom filters or callbacks and define new callbacks, filters, and data types.

If compilation fails, look for an error message printed by the [compiler](./compiler/) crate. An error typically means that a subscription is unresolvable (e.g., a packet-level data type requested in a connection-level callback).

### Technicalities

Set the $IRIS_HOME environment variable, e.g.:

```
export IRIS_HOME=~/iris-artifact-eval
```

Any crate that defines data types specifies an `output_file` where intermediate values are written. For example, the [datatypes](./datatypes/) crate has the following line:

```rust
#[cache_file("$IRIS_HOME/datatypes/data.txt")]
```

Other applications using the data types generated in this crate must tell the compiler where to find this specification.

For instance, many of the [examples](./examples/) have the line:

```rust
#[input_files("$IRIS_HOME/datatypes/data.txt")]
```

Finally, you must tag the `main` function with:

```rust
#[iris_main]
```