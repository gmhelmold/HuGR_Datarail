//! FULL-CHAIN consumer-group REBALANCE proof: spawn the real `datarail kafka-broker` and drive TWO concurrent
//! consumer connections through `JoinGroup` → `SyncGroup` → `Heartbeat` (the automatic-assignment handshake a
//! `subscribe()` consumer performs). Asserts both join ONE generation, agree on the leader, the leader's
//! assignments reach each member, and both heartbeat NONE (stable). `KAFKA-REBALANCE-DESIGN.md` increment 4b.
//! Runs in normal CI (TCP loopback). Note: the join window is the broker's default initial rebalance delay (~3s).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use datarail_kafka::codec::{Reader, Writer};

const PORT: u16 = 19_096;

fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("rebal-wire"));
    w
}

fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).expect("read length");
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).expect("read body");
    body
}

struct JoinResult {
    generation: i32,
    leader: String,
    member_id: String,
    members: Vec<String>,
}

fn join_group(stream: &mut TcpStream, group: &str) -> JoinResult {
    let mut w = req_header(11, 4, 1);
    w.string(group);
    w.int32(30_000); // session_timeout
    w.int32(30_000); // rebalance_timeout (v1+)
    w.string(""); // member_id (empty → assigned)
    w.string("consumer"); // protocol_type
    w.int32(1); // 1 protocol
    w.string("range");
    w.bytes(b"subscription"); // opaque metadata
    stream.write_all(&Writer::frame(&w.into_bytes())).unwrap();

    let resp = read_frame(stream);
    let mut r = Reader::new(&resp);
    let _corr = r.int32().unwrap();
    let _throttle = r.int32().unwrap(); // v2+
    assert_eq!(r.int16().unwrap(), 0, "JoinGroup error NONE");
    let generation = r.int32().unwrap();
    let _protocol = r.string().unwrap();
    let leader = r.string().unwrap();
    let member_id = r.string().unwrap();
    let member_count = r.int32().unwrap();
    let mut members = Vec::new();
    for _ in 0..member_count {
        members.push(r.string().unwrap());
        let _meta = r.bytes().unwrap();
    }
    JoinResult {
        generation,
        leader,
        member_id,
        members,
    }
}

/// `SyncGroup`; `assignments` is non-empty only for the leader. Returns this member's assignment bytes.
fn sync_group(
    stream: &mut TcpStream,
    group: &str,
    generation: i32,
    member_id: &str,
    assignments: &[(String, Vec<u8>)],
) -> Vec<u8> {
    let mut w = req_header(14, 2, 2);
    w.string(group);
    w.int32(generation);
    w.string(member_id);
    w.int32(i32::try_from(assignments.len()).unwrap());
    for (mid, a) in assignments {
        w.string(mid);
        w.bytes(a);
    }
    stream.write_all(&Writer::frame(&w.into_bytes())).unwrap();

    let resp = read_frame(stream);
    let mut r = Reader::new(&resp);
    let _corr = r.int32().unwrap();
    let _throttle = r.int32().unwrap(); // v1+
    assert_eq!(r.int16().unwrap(), 0, "SyncGroup error NONE");
    r.bytes().unwrap()
}

fn heartbeat(stream: &mut TcpStream, group: &str, generation: i32, member_id: &str) -> i16 {
    let mut w = req_header(12, 2, 3);
    w.string(group);
    w.int32(generation);
    w.string(member_id);
    stream.write_all(&Writer::frame(&w.into_bytes())).unwrap();
    let resp = read_frame(stream);
    let mut r = Reader::new(&resp);
    let _corr = r.int32().unwrap();
    let _throttle = r.int32().unwrap(); // v1+
    r.int16().unwrap()
}

fn connect() -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", PORT)) {
            s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            return s;
        }
        assert!(Instant::now() < deadline, "broker never started");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One member's full lifecycle: join → (leader assigns / follower waits) sync → heartbeat. Reports the outcome.
fn run_member(group: &str) -> (String, i32, String, Vec<u8>, i16) {
    let mut s = connect();
    let jr = join_group(&mut s, group);
    let is_leader = jr.member_id == jr.leader;
    // The leader assigns each member its OWN id as opaque bytes (the broker only routes assignment bytes).
    let assignments: Vec<(String, Vec<u8>)> = if is_leader {
        jr.members
            .iter()
            .map(|m| (m.clone(), m.clone().into_bytes()))
            .collect()
    } else {
        Vec::new()
    };
    let assignment = sync_group(&mut s, group, jr.generation, &jr.member_id, &assignments);
    let hb = heartbeat(&mut s, group, jr.generation, &jr.member_id);
    (jr.member_id, jr.generation, jr.leader, assignment, hb)
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn two_consumers_join_one_generation_and_get_assignments() {
    let rail = std::env::temp_dir().join(format!("kafka-rebal-{}.toml", std::process::id()));
    std::fs::write(
        &rail,
        "[route]\n\
         route_id = \"0x03030303030303030303030303030303\"\n\
         stream_id = \"0x04040404040404040404040404040404\"\n\
         aead = \"gcm-siv-256\"\n\
         guarantee = \"exactly-once\"\n\
         [onboarding]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
         [offloading]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
         [keys]\n\
         source_seed = \"0x2222222222222222222222222222222222222222222222222222222222222222\"\n\
         dest_seed = \"0x2222222222222222222222222222222222222222222222222222222222222222\"\n\
         dest_x25519_secret = \"0x2222222222222222222222222222222222222222222222222222222222222222\"\n\
         tenant_secret = \"0x2222222222222222222222222222222222222222222222222222222222222222\"\n",
    )
    .expect("write rail.toml");
    let data_dir = std::env::temp_dir().join(format!("kafka-rebal-data-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);

    let child = Command::new(env!("CARGO_BIN_EXE_datarail"))
        .args([
            "kafka-broker",
            rail.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{PORT}"),
            "--advertised",
            "127.0.0.1",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--partitions",
            "2",
        ])
        .spawn()
        .expect("spawn datarail kafka-broker");
    let _daemon = Daemon(child);
    // wait for listen
    drop(connect());

    // Two members join the SAME group concurrently — they must land in one generation.
    let (tx, rx) = mpsc::channel();
    let tx2 = tx.clone();
    let h1 = std::thread::spawn(move || tx.send(run_member("analytics")).unwrap());
    let h2 = std::thread::spawn(move || tx2.send(run_member("analytics")).unwrap());
    let a = rx.recv_timeout(Duration::from_secs(20)).expect("member a");
    let b = rx.recv_timeout(Duration::from_secs(20)).expect("member b");
    h1.join().unwrap();
    h2.join().unwrap();

    let (a_id, a_gen, a_leader, a_assign, a_hb) = a;
    let (b_id, b_gen, b_leader, b_assign, b_hb) = b;

    assert_eq!(a_gen, b_gen, "both members share ONE generation");
    assert_eq!(a_leader, b_leader, "both agree on the leader");
    assert_ne!(a_id, b_id, "distinct member ids");
    assert!(
        a_leader == a_id || a_leader == b_id,
        "the leader is one of the two members"
    );
    // Each member received the leader's assignment for ITSELF (its own id bytes) — assignments were routed.
    assert_eq!(a_assign, a_id.as_bytes(), "member a got its assignment");
    assert_eq!(b_assign, b_id.as_bytes(), "member b got its assignment");
    // Both are stable.
    assert_eq!(a_hb, 0, "member a heartbeat NONE (stable)");
    assert_eq!(b_hb, 0, "member b heartbeat NONE (stable)");

    let _ = std::fs::remove_file(&rail);
    let _ = std::fs::remove_dir_all(&data_dir);
}
