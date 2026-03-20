// Just some asserts/prints to confirm expected behavior of subscribing to
// data pre- and post-reassembly.

use iris_compiler::*;
use iris_core::L4Pdu;
use iris_core::StateTxData;
use iris_core::{Runtime, config::default_config};

// Specific known connection
// ip.src == 128.241.90.211 and ip.dst == 172.16.255.1 and tcp.port == 10655
#[derive(Debug)]
#[callback("tcp.port = 10655 and ipv4.addr = 128.241.90.211 and ipv4.addr = 172.16.255.1")]
struct ConnRecordTester {
    pdus_pre: Vec<L4Pdu>,
    pdus_post: Vec<L4Pdu>,
    reordering: usize,
}

impl StreamingCallback for ConnRecordTester {
    fn new(_: &L4Pdu) -> Self {
        Self {
            pdus_pre: Vec::new(),
            pdus_post: Vec::new(),
            reordering: 0,
        }
    }

    fn clear(&mut self) {
        self.pdus_pre.clear();
        self.pdus_post.clear();
    }
}

impl ConnRecordTester {
    #[callback_fn("ConnRecordTester,level=InL4Conn")]
    fn update_pre(&mut self, pdu: &L4Pdu) -> bool {
        self.pdus_pre.push(pdu.clone());
        true
    }

    #[callback_fn("ConnRecordTester,level=InL4Stream")]
    fn update_post(&mut self, pdu: &L4Pdu) -> bool {
        self.pdus_post.push(pdu.clone());
        let prev = self.pdus_pre.last().unwrap().ctxt;
        let eq = pdu.ctxt.seq_no == prev.seq_no
            && pdu.ctxt.ack_no == prev.ack_no
            && pdu.ctxt.length == prev.length;
        if !eq {
            println!("Prev: {:?}", prev);
            println!("Curr: {:?}", pdu.ctxt);
        }
        if self.pdus_post.len() != self.pdus_pre.len() {
            println!(
                "Out of sync: pre={} / post={}",
                self.pdus_pre.len(),
                self.pdus_post.len()
            );
            self.reordering += 1;
        }
        true
    }

    #[callback_fn("ConnRecordTester,level=L4Terminated")]
    fn ended(&mut self, _: &StateTxData) -> bool {
        println!("PRE LEN: {}", self.pdus_pre.len());
        println!("POST LEN: {}", self.pdus_post.len());
        assert!(self.pdus_pre.len() == 34 && self.pdus_post.len() == 34 && self.reordering == 4);
        false
    }
}

#[iris_end_macros]
fn main() {
    env_logger::init();
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
