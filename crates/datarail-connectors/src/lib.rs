//! `datarail-connectors` — the source/sink adapters at the terminal edge (PRODUCT "terminals + connectors",
//! SPEC 09). A [`Source`] yields batches of raw byte-records until drained; a [`Sink`] durably commits
//! delivered records. The terminal sits between them — it enforces the content contract and seals/opens — so
//! connectors stay **datarail-agnostic** (they never see keys or cofres) and **dependency-light** (std only).
//!
//! Real backends — `postgres-cdc`, `s3-parquet`, … — are adapters that implement these same two traits behind
//! their own driver and a live system. The in-memory + file connectors here make `datarail run` move **real
//! data source→sink** today (file→file, stdin-style, tests), and are the reference the real adapters slot into.

#![forbid(unsafe_code)]

use std::io;
use std::path::Path;

pub mod http_source;
pub mod postgres_sink;
pub mod webhook_sink;

pub use http_source::HttpSource;
pub use postgres_sink::{PgConfig, PostgresSink};
pub use webhook_sink::WebhookSink;

/// A data **source**: the next batch of raw byte-records, or `None` once exhausted. The onboarding terminal
/// boards each batch (contract + seal); the connector never handles keys or cofres.
pub trait Source {
    /// The next batch of records, or `None` when the source is drained.
    ///
    /// # Errors
    /// Propagates a read error from the underlying source.
    fn next_batch(&mut self) -> io::Result<Option<Vec<Vec<u8>>>>;
}

/// A data **sink**: durably commit a batch of delivered records. The offloading terminal calls this only after
/// verify → open → contract → dedup, so the sink receives exactly the records to land.
pub trait Sink {
    /// Commit a batch of delivered records.
    ///
    /// # Errors
    /// Propagates a write error from the underlying sink.
    fn commit(&mut self, records: &[Vec<u8>]) -> io::Result<()>;

    /// In-memory committed records, when the sink keeps them for introspection (the default is `None`;
    /// only [`VecSink`] overrides it). Lets a caller assert what landed without a concrete-type downcast —
    /// used by the CLI's run report and tests. An opaque external sink (Postgres/webhook/file) returns `None`.
    fn committed_view(&self) -> Option<&[Vec<u8>]> {
        None
    }
}

/// A sink that can land a batch **and** record a monotonic watermark **atomically** — the basis for true
/// exactly-once delivery across crashes (see `docs/design/EXACTLY-ONCE-DESIGN.md`, Tier A). The dedup watermark
/// lives transactionally in the sink itself, so there is no external dedup state to keep in sync or to lose.
pub trait TxnSink {
    /// Atomically: if `watermark` is at or below the sink's stored watermark for `stream`, do nothing (this
    /// batch already landed — an idempotent replay); otherwise land `records` and advance the stored watermark to
    /// `watermark`, all-or-nothing. A crash leaves records+watermark both committed or neither — never "landed
    /// but forgotten".
    ///
    /// # Errors
    /// Propagates the underlying sink/transaction error (the transaction is rolled back).
    fn commit_at(&mut self, records: &[Vec<u8>], stream: &[u8], watermark: u64) -> io::Result<()>;

    /// Like [`TxnSink::commit_at`], but for a source whose watermark is a **monotonic sequence position supplied
    /// by the source** (e.g. a Kafka idempotent producer's `base_sequence + count`) rather than a cumulative
    /// landed count. The batch occupies a contiguous sequence range ending at `watermark` and is treated as a
    /// WHOLE, atomic unit: if `watermark <= the stored watermark`, do nothing (already processed — an
    /// idempotent-producer retry or a post-crash replay); otherwise land `records` and set the stored watermark
    /// to `watermark`, all-or-nothing. Unlike `commit_at` there is **no** partial-suffix landing: the source
    /// guarantees whole-batch, in-order presentation, so the stored watermark is always a clean batch boundary
    /// (see `KAFKA-EOS-DESIGN.md`). Dead-lettered records still advance the watermark (the sequence range is
    /// processed) so a replay does not resurrect them.
    ///
    /// # Errors
    /// Propagates the underlying sink/transaction error (the transaction is rolled back).
    fn commit_at_seq(
        &mut self,
        records: &[Vec<u8>],
        stream: &[u8],
        watermark: u64,
    ) -> io::Result<()>;

    /// The sink's durable watermark for `stream` (`0` if none) — where to resume after a restart. No external
    /// dedup state is consulted: the sink IS the dedup store.
    ///
    /// # Errors
    /// Propagates the underlying read error.
    fn resume_watermark(&mut self, stream: &[u8]) -> io::Result<u64>;
}

/// An in-memory source over pre-staged batches (tests / `datarail run` with inline records).
#[derive(Debug, Default)]
pub struct SliceSource {
    batches: std::collections::VecDeque<Vec<Vec<u8>>>,
}

impl SliceSource {
    /// A source over a queue of batches (delivered front-to-back).
    #[must_use]
    pub fn new(batches: Vec<Vec<Vec<u8>>>) -> Self {
        Self {
            batches: batches.into(),
        }
    }

    /// A single-batch source.
    #[must_use]
    pub fn one(batch: Vec<Vec<u8>>) -> Self {
        Self::new(vec![batch])
    }
}

impl Source for SliceSource {
    fn next_batch(&mut self) -> io::Result<Option<Vec<Vec<u8>>>> {
        Ok(self.batches.pop_front())
    }
}

/// A file source: each non-empty LF-delimited line is one record; the whole file is one batch, then drained.
/// (stdin / a CDC stream are the same trait with a different reader.)
#[derive(Debug)]
pub struct LineFileSource {
    batch: Option<Vec<Vec<u8>>>,
}

impl LineFileSource {
    /// Read `path` into a single batch of line-records (empty lines dropped).
    ///
    /// # Errors
    /// [`io::Error`] if the file cannot be read.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let raw = std::fs::read(path)?;
        let batch: Vec<Vec<u8>> = raw
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        Ok(Self { batch: Some(batch) })
    }
}

impl Source for LineFileSource {
    fn next_batch(&mut self) -> io::Result<Option<Vec<Vec<u8>>>> {
        Ok(self.batch.take())
    }
}

/// An in-memory sink that collects every committed record (tests / `datarail run` reporting).
#[derive(Debug, Default)]
pub struct VecSink {
    committed: Vec<Vec<u8>>,
}

impl VecSink {
    /// A fresh, empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every record committed so far, in order.
    #[must_use]
    pub fn committed(&self) -> &[Vec<u8>] {
        &self.committed
    }
}

impl Sink for VecSink {
    fn commit(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        self.committed.extend_from_slice(records);
        Ok(())
    }

    fn committed_view(&self) -> Option<&[Vec<u8>]> {
        Some(&self.committed)
    }
}

/// A file sink: appends each committed record as an LF-terminated line.
#[derive(Debug)]
pub struct LineFileSink {
    file: std::fs::File,
}

impl LineFileSink {
    /// Open `path` for append (creating it if needed).
    ///
    /// # Errors
    /// [`io::Error`] if the file cannot be opened.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self { file })
    }
}

impl Sink for LineFileSink {
    fn commit(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        use std::io::Write as _;
        for record in records {
            self.file.write_all(record)?;
            self.file.write_all(b"\n")?;
        }
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::{LineFileSink, LineFileSource, Sink, SliceSource, Source, VecSink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> std::path::PathBuf {
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("datarail-conn-{}-{n}.txt", std::process::id()))
    }

    #[test]
    fn slice_source_drains_into_vec_sink() {
        let batch = vec![b"evt:a".to_vec(), b"evt:b".to_vec()];
        let mut src = SliceSource::one(batch.clone());
        let mut sink = VecSink::new();
        while let Some(recs) = src.next_batch().expect("next") {
            sink.commit(&recs).expect("commit");
        }
        assert_eq!(sink.committed(), batch.as_slice());
        assert!(src.next_batch().expect("drained").is_none());
    }

    #[test]
    fn line_file_source_to_line_file_sink_round_trips() {
        let in_path = tmp();
        let out_path = tmp();
        std::fs::write(&in_path, b"evt:one\nevt:two\nevt:three\n").expect("write input");

        let mut src = LineFileSource::open(&in_path).expect("open source");
        let mut sink = LineFileSink::create(&out_path).expect("create sink");
        while let Some(recs) = src.next_batch().expect("next") {
            assert_eq!(
                recs,
                vec![
                    b"evt:one".to_vec(),
                    b"evt:two".to_vec(),
                    b"evt:three".to_vec()
                ]
            );
            sink.commit(&recs).expect("commit");
        }

        let out = std::fs::read(&out_path).expect("read output");
        assert_eq!(
            out, b"evt:one\nevt:two\nevt:three\n",
            "records land as lines, in order"
        );
        let _ = std::fs::remove_file(&in_path);
        let _ = std::fs::remove_file(&out_path);
    }
}
