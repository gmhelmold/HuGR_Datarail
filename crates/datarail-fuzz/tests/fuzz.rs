//! Deterministic fuzz/property tests. Every parser that touches untrusted bytes must (a) NEVER panic on garbage
//! and (b) round-trip valid input exactly. Reproducible via a fixed-seed `SplitMix64`.

/// A tiny zero-dependency PRNG (splitmix64). Deterministic ⇒ a failure is reproducible from the seed.
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
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            usize::try_from(self.next() % n as u64).unwrap_or(0)
        }
    }
    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Broker wire codec: decode of ARBITRARY bytes must never panic; valid messages must round-trip exactly.
// ---------------------------------------------------------------------------------------------------------------
#[test]
fn broker_codec_never_panics_on_garbage() {
    use datarail_broker::{decode_request, decode_response};
    let mut rng = Rng::new(0xB0_07);
    for _ in 0..300_000 {
        let g = rng.bytes(64);
        // Must return (Some/None) — never panic, never hang — on any byte string.
        let _ = decode_request(&g);
        let _ = decode_response(&g);
    }
}

#[test]
fn broker_request_response_round_trip() {
    use datarail_broker::{
        decode_request, decode_response, encode_request, encode_response, Request, Response,
    };
    let mut rng = Rng::new(0x4242);
    for _ in 0..100_000 {
        let req = match rng.below(3) {
            0 => Request::Produce {
                key: rng.bytes(40),
                payload: rng.bytes(80),
            },
            1 => Request::Poll {
                group: String::from_utf8_lossy(&rng.bytes(20)).into_owned(),
            },
            _ => Request::Commit {
                group: String::from_utf8_lossy(&rng.bytes(20)).into_owned(),
                offset: rng.next(),
            },
        };
        assert_eq!(
            decode_request(&encode_request(&req)),
            Some(req.clone()),
            "request did not round-trip: {req:?}"
        );

        let resp = match rng.below(4) {
            0 => Response::Produced(rng.next()),
            1 if rng.below(2) == 0 => Response::Record(None),
            1 => Response::Record(Some((rng.next(), rng.bytes(30), rng.bytes(50)))),
            2 => Response::Committed,
            _ => Response::Err(String::from_utf8_lossy(&rng.bytes(30)).into_owned()),
        };
        assert_eq!(
            decode_response(&encode_response(&resp)),
            Some(resp.clone()),
            "response did not round-trip: {resp:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Erasure: reconstruct from random k-of-(k+m) survivors == data; reconstruct of GARBAGE survivors never panics.
// ---------------------------------------------------------------------------------------------------------------
#[test]
fn erasure_reconstructs_after_random_loss() {
    use datarail_erasure::Rs;
    let mut rng = Rng::new(0xE7A5);
    for _ in 0..3_000 {
        let k = 1 + rng.below(12);
        let m = 1 + rng.below(6);
        let Ok(rs) = Rs::new(k, m) else { continue };
        let shard_len = 1 + rng.below(64);
        let data: Vec<Vec<u8>> = (0..k)
            .map(|_| (0..shard_len).map(|_| (rng.next() & 0xff) as u8).collect())
            .collect();
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let parity = rs.encode(&refs).expect("encode");
        // All k+m code shards, then drop a random m of them → k survive.
        let mut all: Vec<(usize, Vec<u8>)> = data.iter().cloned().enumerate().collect();
        for (i, p) in parity.iter().enumerate() {
            all.push((k + i, p.clone()));
        }
        // Fisher-Yates partial shuffle to pick k random survivors.
        for i in 0..all.len() {
            let j = i + rng.below(all.len() - i);
            all.swap(i, j);
        }
        let survivors: Vec<(usize, &[u8])> =
            all[..k].iter().map(|(i, b)| (*i, b.as_slice())).collect();
        let recovered = rs.reconstruct(&survivors).expect("reconstruct");
        assert_eq!(recovered, data, "erasure failed for k={k} m={m}");
    }
}

#[test]
fn erasure_reconstruct_never_panics_on_garbage() {
    use datarail_erasure::Rs;
    let mut rng = Rng::new(0x6A41);
    for _ in 0..100_000 {
        let k = 1 + rng.below(10);
        let m = 1 + rng.below(6);
        let Ok(rs) = Rs::new(k, m) else { continue };
        // Random number of survivors with random (possibly invalid/duplicate/out-of-range) indices + ragged bytes.
        let n = rng.below(k + m + 2);
        let blobs: Vec<Vec<u8>> = (0..n).map(|_| rng.bytes(40)).collect();
        let survivors: Vec<(usize, &[u8])> = blobs
            .iter()
            .map(|b| (rng.below(k + m + 3), b.as_slice()))
            .collect();
        // Must return Ok/Err — never panic — for any junk.
        let _ = rs.reconstruct(&survivors);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Blobstore: adversarial keys round-trip exactly and NEVER escape the store root.
// ---------------------------------------------------------------------------------------------------------------
#[test]
fn blobstore_adversarial_keys_round_trip_and_never_escape() {
    use datarail_blobstore::{BlobStore, FsBlob};
    let parent = std::env::temp_dir().join(format!("datarail-fuzz-blob-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    let root = parent.join("store");
    let mut fb = FsBlob::open(&root).expect("open");
    let mut rng = Rng::new(0x5701);
    // A palette of nasty key fragments, plus random bytes.
    let nasty = [
        "..",
        "/",
        "../",
        "..\\",
        ".",
        "",
        "%2e%2e",
        ".tmp.0",
        "a/b/../../c",
        "\u{0}",
        "k",
    ];
    for _ in 0..2_000 {
        let key: String = if rng.below(2) == 0 {
            nasty[rng.below(nasty.len())].to_owned()
        } else {
            String::from_utf8_lossy(&rng.bytes(24)).into_owned()
        };
        let val = rng.bytes(40);
        fb.put(&key, &val).expect("put");
        assert_eq!(
            fb.get(&key).expect("get"),
            Some(val.clone()),
            "key did not round-trip: {key:?}"
        );
        // The escape check: nothing must ever be written OUTSIDE the store root (i.e. directly under `parent`).
        for entry in std::fs::read_dir(&parent).expect("read parent") {
            let p = entry.expect("entry").path();
            assert!(p == root, "a blob escaped the root: {p:?} (key {key:?})");
        }
        let _ = fb.delete(&key);
    }
    let _ = std::fs::remove_dir_all(&parent);
}

// ---------------------------------------------------------------------------------------------------------------
// netblob server: a flood of random garbage frames must not crash it; it keeps serving legit ops after.
// ---------------------------------------------------------------------------------------------------------------
#[test]
fn netblob_server_survives_garbage() {
    use datarail_blobstore::{BlobStore, MemBlob};
    use datarail_netblob::{serve, NetBlob};
    use std::io::Write;
    use std::net::TcpStream;

    let addr = serve(MemBlob::new()).expect("serve");
    let mut rng = Rng::new(0x9001);
    for _ in 0..200 {
        if let Ok(mut s) = TcpStream::connect(addr) {
            let junk = rng.bytes(200);
            let _ = s.write_all(&junk); // garbage frame; server must reject/close cleanly, not crash
            let _ = s.flush();
        }
    }
    // The server is still alive and correct: a real op round-trips.
    let mut client = NetBlob::new(addr);
    client.put("after-flood", b"ok").expect("put after flood");
    assert_eq!(
        client.get("after-flood").expect("get"),
        Some(b"ok".to_vec()),
        "server died under garbage"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// replaylog: opening + replaying a segment file full of RANDOM bytes must never panic (recovery/parse safety).
// ---------------------------------------------------------------------------------------------------------------
#[test]
fn replaylog_survives_garbage_on_disk() {
    use datarail_replaylog::ReplayLog;
    let mut rng = Rng::new(0x1066);
    for it in 0..200 {
        let dir =
            std::env::temp_dir().join(format!("datarail-fuzz-rl-{}-{it}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        // Write a random-bytes file named like the first segment (000…0.seg).
        let garbage = rng.bytes(4096);
        std::fs::write(dir.join(format!("{:020}.seg", 0u64)), &garbage).expect("write seg");
        // open() scans for the valid tail; replay parses frames — neither may panic on arbitrary bytes.
        if let Ok(log) = ReplayLog::open(&dir, 1 << 16) {
            if let Ok(mut r) = log.replay_from(0) {
                while let Ok(Some(_)) = r.read_next() {}
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------------------------------
// Kafka wire-protocol parsers — the network-facing codec + Produce parsing. A hostile Kafka client
// controls every byte; these must NEVER panic on garbage (the adversarial audit proved this by
// inspection + one test — here we hammer it over millions of inputs).
// ---------------------------------------------------------------------------------------------------

#[test]
fn kafka_codec_never_panics_on_garbage() {
    use datarail_kafka::codec::{Reader, RequestHeader};
    let mut rng = Rng::new(0xCAFE_F00D_1234);
    for _ in 0..200_000 {
        let buf = rng.bytes(80);
        let mut r = Reader::new(&buf);
        // Drive every reader method over arbitrary bytes; each must return a Result, never panic.
        let _ = r.int8();
        let _ = r.int16();
        let _ = r.int32();
        let _ = r.int64();
        let _ = r.uint32();
        let _ = r.unsigned_varint();
        let _ = r.varint();
        let _ = r.varlong();
        let _ = r.string();
        let _ = r.nullable_string();
        let _ = r.compact_string();
        let _ = r.compact_nullable_string();
        let _ = r.bytes();
        let _ = r.nullable_bytes();
        let _ = r.compact_bytes();
        let _ = r.compact_nullable_bytes();
        let _ = r.skip_tagged_fields();
        let mut r2 = Reader::new(&buf);
        let _ = RequestHeader::parse(&mut r2, rng.next() & 1 == 0);
    }
}

#[test]
fn kafka_produce_parsers_never_panic_on_garbage() {
    use datarail_kafka::codec::Reader;
    use datarail_kafka::produce::{parse_produce, parse_record_batch};
    let mut rng = Rng::new(0x9E37_79B9_0F0F);
    for _ in 0..100_000 {
        let buf = rng.bytes(160);
        for version in [0i16, 3, 7] {
            let mut r = Reader::new(&buf);
            let _ = parse_produce(&mut r, version); // must not panic / OOM / hang on hostile counts
        }
        let _ = parse_record_batch(&buf); // v2/legacy dispatch on arbitrary bytes
    }
}

#[test]
fn kafka_consume_parsers_never_panic_on_garbage() {
    use datarail_kafka::codec::Reader;
    use datarail_kafka::consume::{parse_fetch, parse_list_offsets};
    let mut rng = Rng::new(0x00C0_FFEE_1234);
    for _ in 0..100_000 {
        let buf = rng.bytes(192);
        for version in [0i16, 1, 2, 3, 4, 9] {
            let mut r = Reader::new(&buf);
            let _ = parse_fetch(&mut r, version);
            let mut r2 = Reader::new(&buf);
            let _ = parse_list_offsets(&mut r2, version);
        }
    }
}

#[test]
fn kafka_group_parsers_never_panic_on_garbage() {
    use datarail_kafka::codec::Reader;
    use datarail_kafka::groups::{
        parse_find_coordinator, parse_heartbeat, parse_join_group, parse_leave_group,
        parse_offset_commit, parse_offset_fetch, parse_sync_group,
    };
    let mut rng = Rng::new(0x5EA1_ED00_4B1D);
    for _ in 0..100_000 {
        let buf = rng.bytes(192);
        for version in [0i16, 1, 2, 4] {
            let mut r = Reader::new(&buf);
            let _ = parse_join_group(&mut r, version); // bounded protocol array on hostile counts
            let mut r = Reader::new(&buf);
            let _ = parse_sync_group(&mut r, version); // bounded assignment array
            let mut r = Reader::new(&buf);
            let _ = parse_heartbeat(&mut r, version);
            let mut r = Reader::new(&buf);
            let _ = parse_leave_group(&mut r, version);
            let mut r = Reader::new(&buf);
            let _ = parse_offset_commit(&mut r, version);
            let mut r = Reader::new(&buf);
            let _ = parse_offset_fetch(&mut r, version);
            let mut r = Reader::new(&buf);
            let _ = parse_find_coordinator(&mut r, version);
        }
    }
}

#[test]
fn kafka_metadata_parser_never_panics_on_garbage() {
    use datarail_kafka::codec::Reader;
    use datarail_kafka::handlers::parse_metadata_topics;
    let mut rng = Rng::new(0xD15E_A5ED_0042);
    for _ in 0..100_000 {
        let buf = rng.bytes(160);
        let mut r = Reader::new(&buf);
        let _ = parse_metadata_topics(&mut r); // a huge topic count must bound, never over-allocate
    }
}

#[test]
fn cofre_decode_never_panics_on_garbage() {
    let mut rng = Rng::new(0xC0FF_EE5E_A100_0042);
    for _ in 0..100_000 {
        let buf = rng.bytes(256);
        let _ = datarail_cofre::decode(&buf); // arbitrary bytes → Err, never panic / OOM (parse-before-verify)
    }
}
