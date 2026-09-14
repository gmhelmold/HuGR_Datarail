//! S1 gate (FASP-UDP-TRANSPORT.md): the reliable-UDP mover delivers every message, in order, over a REAL
//! `UdpSocket` loopback, and feeds the `DelayController` real RTT samples. No artificial loss here — S1 proves
//! the framing / ACK / reassembly / RTT-wiring skeleton on a clean path; loss recovery is S2, `tc netem` is S3.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use datarail_rail::reliable_udp::{FaspCfg, FaspLink};

fn loopback() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

#[test]
fn s1_reliable_ordered_delivery_over_real_udp_and_rtt_is_learned() {
    const N: u64 = 2000;
    let cfg = FaspCfg::default();
    let mut a = FaspLink::bind(loopback(), cfg).expect("bind a");
    let mut b = FaspLink::bind(loopback(), cfg).expect("bind b");
    let a_addr = a.local_addr().expect("a addr");
    let b_addr = b.local_addr().expect("b addr");
    a.set_peer(b_addr);
    b.set_peer(a_addr);

    // Each message is its own seq; the 8-byte big-endian index lets us assert exact order on the receiver.
    let mut sent = 0u64;
    let mut got: Vec<u64> = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(20);
    while (got.len() as u64) < N {
        assert!(
            Instant::now() < deadline,
            "S1 did not converge: delivered {}/{N}",
            got.len()
        );
        // Offer the next message when the window has room (send() also self-paces on max_inflight).
        if sent < N && a.inflight_len() < cfg.max_inflight {
            a.send(&sent.to_be_bytes()).expect("send");
            sent += 1;
        }
        // Drive both directions: A processes ACKs, B delivers DATA + ACKs back.
        a.pump().expect("pump a");
        while let Some(msg) = b.recv().expect("recv b") {
            let idx = u64::from_be_bytes(msg.as_slice().try_into().expect("8-byte message"));
            got.push(idx);
        }
    }

    // Every message, exactly once, in order.
    assert_eq!(got.len() as u64, N, "delivered count");
    for (i, v) in got.iter().enumerate() {
        assert_eq!(*v, i as u64, "out-of-order or missing at position {i}");
    }

    // The controller learned a real base RTT from real ACKs (INV-FASP-SIGNAL is wired to the socket).
    let sb = b.stats();
    let sa = a.stats();
    assert_eq!(sb.delivered, N, "B delivered all");
    assert!(
        sa.base_rtt < Duration::MAX,
        "A learned a base RTT from real ACKs"
    );
    assert!(sa.window >= cfg.min_window, "window stayed valid");
    // Clean loopback: delivery completes; if any spurious retransmit happened it must still be exactly-once
    // (asserted above). We don't hard-assert 0 retransmits — a slow CI box can trip the RTO benignly.
}
