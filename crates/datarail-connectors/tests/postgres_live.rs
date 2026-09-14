//! LIVE integration test for `PostgresSink` against a REAL `PostgreSQL` server. `#[ignore]` by default — the
//! unit tests in the crate prove framing/MD5/escaping; THIS proves the wire protocol round-trips against a real
//! backend. Run it with a Postgres reachable via env (a docker container in the verification harness):
//!
//! ```text
//! DATARAIL_PG_HOST=127.0.0.1 DATARAIL_PG_PORT=5432 \
//!   cargo test -p datarail-connectors --test postgres_live -- --ignored --nocapture
//! ```
//! The harness creates the target table first and verifies the landed rows afterwards (via `psql`).

use datarail_connectors::{PgConfig, PostgresSink, Sink, TxnSink};

/// Shared connection config from the env (the docker verification harness sets these).
fn live_cfg(table: &str) -> PgConfig {
    let host = std::env::var("DATARAIL_PG_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port: u16 = std::env::var("DATARAIL_PG_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5432);
    let user = std::env::var("DATARAIL_PG_USER").unwrap_or_else(|_| "postgres".to_owned());
    let dbname = std::env::var("DATARAIL_PG_DB").unwrap_or_else(|_| "postgres".to_owned());
    let password = std::env::var("DATARAIL_PG_PASSWORD").ok();
    let mut cfg = PgConfig::new(host, user, dbname, table.to_owned(), "data".to_owned());
    cfg.port = port;
    cfg.password = password;
    cfg
}

#[test]
#[ignore = "needs a live Postgres (set DATARAIL_PG_* env); run in the docker verification harness"]
fn commits_records_into_a_real_postgres() {
    let mut sink =
        PostgresSink::connect(live_cfg("datarail_events")).expect("connect to live postgres");
    let records = vec![
        b"evt:alpha".to_vec(),
        b"evt:beta\twith-tab".to_vec(),
        b"evt:gamma\\with-backslash".to_vec(),
    ];
    sink.commit(&records).expect("commit a batch into postgres");
    // A second batch — proves the connection stays usable for repeated COPY rounds.
    sink.commit(&[b"evt:delta".to_vec()])
        .expect("commit a second batch");
}

#[test]
#[ignore = "needs a live Postgres (set DATARAIL_PG_* env); run in the docker verification harness"]
fn exactly_once_a_replayed_batch_does_not_double_land() {
    // The moat (EXACTLY-ONCE-DESIGN.md, Tier A): commit_at lands records + the watermark in one transaction, so
    // a redelivered batch (same watermark) is a committed NO-OP — exactly-once across a crash, with the dedup
    // watermark living transactionally in Postgres itself.
    let mut sink = PostgresSink::connect(live_cfg("datarail_eo")).expect("connect");
    let stream = b"route-xyz";
    let batch1 = vec![b"eo:a".to_vec(), b"eo:b".to_vec(), b"eo:c".to_vec()];

    sink.commit_at(&batch1, stream, 3).expect("commit batch1");
    // Simulate an at-least-once REDELIVERY after a 'crash': the exact same batch + watermark. Must be a no-op.
    sink.commit_at(&batch1, stream, 3)
        .expect("replay batch1 (idempotent)");
    sink.commit_at(&batch1, stream, 3)
        .expect("replay batch1 again");
    assert_eq!(
        sink.resume_watermark(stream).expect("resume"),
        3,
        "watermark resumes at 3"
    );

    // A genuinely new batch advances the watermark and lands.
    sink.commit_at(&[b"eo:d".to_vec()], stream, 4)
        .expect("commit batch2");
    sink.commit_at(&[b"eo:d".to_vec()], stream, 4)
        .expect("replay batch2"); // redelivery — no-op
    assert_eq!(
        sink.resume_watermark(stream).expect("resume2"),
        4,
        "watermark resumes at 4"
    );
    // The harness asserts exactly 4 rows landed (a,b,c,d) despite the replays.
}

#[test]
#[ignore = "needs a live Postgres (set DATARAIL_PG_* env); run in the docker verification harness"]
fn commit_at_seq_is_idempotent_per_sequence_range_and_advances_past_dead_letters() {
    // Kafka-EOS sequence model (KAFKA-EOS-DESIGN.md): commit_at_seq treats each batch as a whole unit keyed on
    // the producer's sequence range. A retry/replay of the same range is a committed no-op; a processed range
    // with zero landed records (all dead-lettered upstream) still advances the watermark so a replay no-ops.
    run_psql("DROP TABLE IF EXISTS datarail_seq");
    run_psql("CREATE TABLE datarail_seq (data text)");
    // Clear any stale watermark for this stream (order-independent: create the table first if no prior test made it).
    run_psql("CREATE TABLE IF NOT EXISTS datarail_watermark (stream bytea PRIMARY KEY, seq bigint NOT NULL)");
    run_psql("DELETE FROM datarail_watermark WHERE stream = '\\x726f7574652d7365712d7037'"); // 'route-seq-p7'
    let mut sink = PostgresSink::connect(live_cfg("datarail_seq")).expect("connect");
    let stream = b"route-seq-p7";

    // Batch [0,3): land a,b,c, watermark -> 3.
    sink.commit_at_seq(
        &[b"s:a".to_vec(), b"s:b".to_vec(), b"s:c".to_vec()],
        stream,
        3,
    )
    .expect("seq batch1");
    // Idempotent-producer RETRY of the exact same range -> no-op (whole-batch).
    sink.commit_at_seq(
        &[b"s:a".to_vec(), b"s:b".to_vec(), b"s:c".to_vec()],
        stream,
        3,
    )
    .expect("seq retry");
    assert_eq!(sink.resume_watermark(stream).expect("wm"), 3);

    // A processed range [3,5) where BOTH records dead-lettered upstream: 0 records land, watermark advances to 5.
    sink.commit_at_seq(&[], stream, 5)
        .expect("seq dead-letter range");
    // Replay of that empty range -> still no-op (5 <= 5).
    sink.commit_at_seq(&[], stream, 5)
        .expect("seq dead-letter replay");
    assert_eq!(sink.resume_watermark(stream).expect("wm2"), 5);

    // A genuinely new range [5,6): land f.
    sink.commit_at_seq(&[b"s:f".to_vec()], stream, 6)
        .expect("seq batch2");
    sink.commit_at_seq(&[b"s:f".to_vec()], stream, 6)
        .expect("seq batch2 retry"); // no-op
    assert_eq!(sink.resume_watermark(stream).expect("wm3"), 6);

    // Independent verification: exactly 4 rows (a,b,c,f) despite the retries + the dead-letter gap.
    let n = psql_scalar("SELECT count(*) FROM datarail_seq");
    assert_eq!(n, "4", "expected 4 rows (a,b,c,f), got {n}");
}

/// Run a SQL statement on the live DB via `psql` (the harness has it on PATH) — used to perturb the schema
/// out from under the sink to test error recovery.
fn run_psql(sql: &str) {
    let host = std::env::var("DATARAIL_PG_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = std::env::var("DATARAIL_PG_PORT").unwrap_or_else(|_| "5432".to_owned());
    let ok = std::process::Command::new("psql")
        .args(["-h", &host, "-p", &port, "-U", "postgres", "-c", sql])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "psql failed for: {sql}");
}

/// Run a scalar `SELECT` via `psql -tA` and return the single trimmed value (so a test can assert the landed
/// row count itself, rather than relying on an external harness step).
fn psql_scalar(sql: &str) -> String {
    let host = std::env::var("DATARAIL_PG_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = std::env::var("DATARAIL_PG_PORT").unwrap_or_else(|_| "5432".to_owned());
    let out = std::process::Command::new("psql")
        .args(["-h", &host, "-p", &port, "-U", "postgres", "-tA", "-c", sql])
        .output()
        .expect("psql scalar query");
    assert!(out.status.success(), "psql failed for: {sql}");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
#[ignore = "needs a live Postgres + psql on PATH; run in the docker verification harness"]
fn a_grown_replay_batch_lands_only_the_new_suffix_not_the_overlap() {
    // The partial-overlap case (the realistic replay shape for `datarail run` over a file, which reads the whole
    // file as ONE batch): run 1 lands a 2-record prefix; the source then GROWS and run 2 re-presents a LARGER
    // 4-record batch under the higher cumulative watermark. commit_at must land ONLY the new suffix [r2,r3] —
    // never re-land the [r0,r1] overlap. Batch-granularity idempotency would double-land; record-granularity
    // (base = watermark - records.len()) does not. This is the property the product flow depends on.
    run_psql("DROP TABLE IF EXISTS datarail_grow");
    run_psql("CREATE TABLE datarail_grow (data text)");
    // Clear any stale watermark for this stream (order-independent: create the table first if no prior test made it).
    run_psql("CREATE TABLE IF NOT EXISTS datarail_watermark (stream bytea PRIMARY KEY, seq bigint NOT NULL)");
    run_psql("DELETE FROM datarail_watermark WHERE stream = '\\x726f7574652d67726f77'"); // 'route-grow'
    let mut sink = PostgresSink::connect(live_cfg("datarail_grow")).expect("connect");
    let stream = b"route-grow";

    // Run 1: land the 2-record prefix (cumulative landed = 2).
    sink.commit_at(&[b"g:0".to_vec(), b"g:1".to_vec()], stream, 2)
        .expect("run1 prefix");
    assert_eq!(
        psql_scalar("SELECT count(*) FROM datarail_grow"),
        "2",
        "run1 landed 2 rows"
    );

    // Run 2 (fresh process semantics: once-gate empty, the GROWN source re-presents the whole 4-record batch).
    sink.commit_at(
        &[
            b"g:0".to_vec(),
            b"g:1".to_vec(),
            b"g:2".to_vec(),
            b"g:3".to_vec(),
        ],
        stream,
        4,
    )
    .expect("run2 grown batch");
    assert_eq!(
        psql_scalar("SELECT count(*) FROM datarail_grow"),
        "4",
        "the overlap [g:0,g:1] must NOT re-land — exactly 4 rows, not 6"
    );
    assert_eq!(
        sink.resume_watermark(stream).expect("wm"),
        4,
        "watermark advanced to 4"
    );
    // And the suffix that landed is exactly g:2,g:3 (the overlap kept its single copy).
    assert_eq!(
        psql_scalar("SELECT count(*) FROM datarail_grow WHERE data IN ('g:2','g:3')"),
        "2",
        "the new suffix g:2,g:3 landed exactly once"
    );
}

#[test]
#[ignore = "needs a live Postgres + psql on PATH; run in the docker verification harness"]
fn a_backend_error_does_not_desync_the_connection() {
    // audit C1 (PROVEN bug, now fixed): a backend ErrorResponse must not orphan the trailing ReadyForQuery and
    // desync every later query — which previously made resume_watermark misread 0 and re-land the whole stream.
    run_psql("DROP TABLE IF EXISTS datarail_recover");
    run_psql("CREATE TABLE datarail_recover (data text)");
    let mut sink = PostgresSink::connect(live_cfg("datarail_recover")).expect("connect");
    let stream = b"route-recover";
    sink.commit_at(&[b"r:1".to_vec()], stream, 1)
        .expect("land batch (watermark -> 1)");
    assert_eq!(sink.resume_watermark(stream).expect("wm"), 1);

    // Drop the records table out from under the sink: the next commit_at's COPY errors (a real backend 'E').
    run_psql("DROP TABLE datarail_recover");
    assert!(
        sink.commit_at(&[b"r:2".to_vec()], stream, 2).is_err(),
        "commit into a dropped table must error"
    );

    // Recreate it. If the error desynced the wire, resume_watermark would now misread 0. It must read the
    // DURABLE 1 — proving the connection realigned (the fix drains to ReadyForQuery on every error).
    run_psql("CREATE TABLE datarail_recover (data text)");
    assert_eq!(
        sink.resume_watermark(stream)
            .expect("watermark after a backend error"),
        1,
        "C1: a backend error must not desync the connection (durable watermark is still 1)"
    );
    // And the connection is fully usable again — a new batch lands + advances.
    sink.commit_at(&[b"r:2b".to_vec()], stream, 2)
        .expect("commit after recovery");
    assert_eq!(sink.resume_watermark(stream).expect("wm2"), 2);
}
