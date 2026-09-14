//! System-level CHAOS / fault-injection: the component audits stressed each crate; the capstone proved ONE
//! clean restart. This proves the SYSTEM guarantee under ARBITRARY crashes — the broker is killed and reopened
//! over the same durable state at random points (mid-consume, after-poll-before-commit, after-commit) — and
//! asserts **no produced record is ever lost** (durable log + durable offsets + resume = at-least-once survives
//! crash chaos). Duplicates are allowed (uncommitted-then-recrashed records re-deliver — that's at-least-once).
//! Deterministic (seeded), in-process (no lingering threads), clean reopens (no concurrent handles).

use std::collections::HashSet;
use std::path::PathBuf;

use datarail_broker::{Request, Response, Server};
use datarail_offsets::FileOffsets;
use datarail_topic::Topic;

/// Zero-dep splitmix64 — seeded chaos is reproducible.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn tmp(tag: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("datarail-chaos-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Open a fresh broker over the same durable topic + offset store (a "process restart").
fn open_broker(tdir: &PathBuf, odir: &PathBuf) -> Server<FileOffsets> {
    let topic = Topic::open(tdir, 1 << 16).expect("topic");
    let offsets = FileOffsets::open(odir).expect("offsets");
    Server::new(topic, offsets)
}

#[test]
fn no_record_is_lost_across_arbitrary_broker_crashes() {
    const N: u32 = 2000;
    let tdir = tmp("topic");
    let odir = tmp("offsets");

    // Produce all N durably, then drop that broker (no concurrent writer during the chaotic consume).
    {
        let mut producer = open_broker(&tdir, &odir);
        for i in 0..N {
            let r = producer.handle(Request::Produce {
                key: Vec::new(),
                payload: format!("v{i}").into_bytes(),
            });
            assert!(matches!(r, Response::Produced(_)), "produce failed: {r:?}");
        }
    }
    let end = Topic::open(&tdir, 1 << 16).expect("end").end_offset();

    // Consume under CHAOS: a fresh broker, polling / committing / CRASHING at seeded-random points until the
    // committed offset reaches the end. The committed offset is the durable resume point.
    let mut rng = Rng::new(0x_C0FF_EE42);
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut server = open_broker(&tdir, &odir);
    let mut last_resume = 0u64; // the resume offset of the last polled record (commit-able)
    let mut committed = 0u64;
    let mut crashes = 0u32;
    let mut guard = 0u32;

    while committed < end {
        guard += 1;
        assert!(
            guard < 2_000_000,
            "chaos did not converge (committed {committed} < end {end})"
        );
        match rng.next() % 10 {
            // 0–5: poll (consume) a record.
            0..=5 => match server.handle(Request::Poll {
                group: "g".to_owned(),
            }) {
                Response::Record(Some((resume_off, _key, payload))) => {
                    seen.insert(payload);
                    last_resume = resume_off;
                }
                Response::Record(None) => {
                    // Caught up: the cursor is at `end`. Commit it to make progress to termination.
                    last_resume = end;
                }
                other => panic!("unexpected poll response: {other:?}"),
            },
            // 6–7: durably commit the last resume point.
            6 | 7 => {
                assert_eq!(
                    server.handle(Request::Commit {
                        group: "g".to_owned(),
                        offset: last_resume
                    }),
                    Response::Committed
                );
                committed = last_resume;
            }
            // 8–9: CRASH — drop the broker and reopen fresh over the same durable state. It resumes from the
            // last COMMITTED offset, so any polled-but-uncommitted records re-deliver (at-least-once).
            _ => {
                drop(server);
                server = open_broker(&tdir, &odir);
                last_resume = committed; // the fresh broker will resume polling from `committed`
                crashes += 1;
            }
        }
    }

    // THE INVARIANT: across all the crashes, every produced record was consumed at least once — nothing lost.
    assert!(
        crashes > 0,
        "the chaos must actually have crashed the broker"
    );
    for i in 0..N {
        let want = format!("v{i}").into_bytes();
        assert!(
            seen.contains(&want),
            "record v{i} was LOST across the crash chaos ({crashes} crashes)"
        );
    }
    assert_eq!(committed, end, "did not durably consume to the end");

    let _ = std::fs::remove_dir_all(&tdir);
    let _ = std::fs::remove_dir_all(&odir);
}
