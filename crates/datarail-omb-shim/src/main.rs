//! `datarail-omb-shim` — a mini-broker that lets the **`OpenMessaging` Benchmark** (OMB) drive datarail over
//! its REAL sealed terminals. It listens on two TCP ports (ingress for producers, egress for consumers) and,
//! per topic, runs datarail's full sealed datapath: `board` a batch into a cofre via a real
//! [`datarail_terminal::SourceTerminal`], move it to a real [`datarail_terminal::DestTerminal`]
//! (encode→decode→verify→open→admit→commit — no crypto shortcut), then fan the offloaded records out to every
//! subscribed egress consumer.
//!
//! THIS IS A BENCHMARK ADAPTER, **NOT A PRODUCT COMPONENT**. It maps OMB's pub/sub onto datarail's
//! point-to-point send/recv (a fair-but-partial fit; datarail has no native topic/partition/consumer-group).
//! The fixed, deterministic source/dest seeds and keys below exist only because both terminals run in **this
//! same process** — a real deployment derives and pins these via the identity layer (SPEC-08), never hardcodes
//! them.
//!
//! The wire protocol, config, batching rules, and honesty labels are the frozen contract in
//! `docs/design/OMB-PROTOCOL.md`; this binary implements it verbatim.
//!
//! ## Topology (async tokio I/O + per-topic blocking seal worker)
//! Earlier this shim was thread-per-connection (std-only). On a many-core box that plateaued at ~620 MB/s
//! because ~112 OS threads (one per producer/consumer + one per topic) oversubscribed the cores and thrashed;
//! per-stream rate fell from 65k msg/s at 8 topics to 38k at 16. This rewrite breaks that ceiling:
//! - A **tokio multi-thread runtime** (worker count = cores) owns ALL TCP socket I/O. Each accepted connection
//!   — ingress producer or egress consumer — is a **tokio task**, not an OS thread, so N connections cost a
//!   handful of runtime workers instead of N threads.
//! - The CPU-bound seal/open work stays on a **dedicated OS thread PER TOPIC**: the datarail
//!   `SourceTerminal`/`DestTerminal` are synchronous `&mut self` state machines and MUST NOT run on the async
//!   runtime workers (they would block the event loop). The async side bridges to that blocking thread over
//!   channels.
//! - **Thread count is now `cores` runtime workers + one seal thread per topic** (e.g. ~32 + 16 ≈ 48 on a
//!   32-core / 16-topic run), independent of connection count — versus ~112 before.
//!
//! ### Async ↔ blocking bridge (where backpressure lives)
//! - An ingress task assembles each `{publish_ts(8 BE) || payload}` record and `send().await`s it into a
//!   **bounded** [`tokio::sync::mpsc`] (capacity `batch_max_records * 16`, clamped `[256, 65536]`). That
//!   bounded channel is the **single backpressure point**: when the seal worker lags, the channel fills, the
//!   ingress task awaits on `send().await`, it stops reading the producer socket, the producer's TCP buffer
//!   fills, and the producer slows — 0-loss, no unbounded backlog (exactly the discipline of the old
//!   `SyncSender`).
//! - The per-topic **`std::thread`** owns the topic's [`TopicEngine`] (`SourceTerminal` + `DestTerminal` +
//!   `Transport`). It `blocking_recv()`s the first record of a batch, then fills the batch until it is full
//!   (`batch_max_records`) OR the time window (`batch_max_micros`) elapses — whichever first — using the
//!   runtime handle to drive a timed `recv` without busy-spinning. It runs the full real seal path
//!   (`board` → `transport.relay` → `offload` → `dest.sink_mut().take_committed()`) and hands each committed
//!   record (wrapped in `Arc<Vec<u8>>`) to the topic's subscriber set.
//! - Egress: each consumer task awaits delivered records over a per-subscriber **bounded**
//!   [`tokio::sync::mpsc`] (capacity `8192`) and async-writes `[u32 payload_len][record]` frames; the frame
//!   body IS the record bytes (record == ts || payload), so there is no split or per-message payload copy.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use datarail_core::{AeadAlg, Cofre, Disposition, Substrate};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_rail::TcpSubstrate;
use datarail_substrate_shmem::ShmemRing;
use datarail_terminal::{ContentContract, DestTerminal, SourceTerminal, TerminalConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

// ----------------------------------------------------------------------------------------------------------
// Fixed, deterministic route keys — SAME-PROCESS BENCH SHIM ONLY (NOT a product component).
//
// Source and dest terminals live in this one process, so a fixed route id / stream id / AEAD key material is
// fine: there is no third party to pin against. A real datarail deployment derives and pins these via the
// SPEC-08 identity layer; it MUST NOT hardcode them. They mirror `datarail-bench`'s `head_to_head` anchor.
// ----------------------------------------------------------------------------------------------------------

/// Fixed A→B route id for the shim's single in-process route.
const ROUTE_ID: [u8; 16] = [1u8; 16];
/// Fixed ordering domain for the shim's single in-process route.
const STREAM_ID: [u8; 16] = [2u8; 16];
/// Fixed Ed25519 source signing seed (bench shim — see module note).
const SRC_SEED: [u8; 32] = [11u8; 32];
/// Fixed destination admission-gate seed (bench shim — see module note).
const DEST_SEED: [u8; 32] = [22u8; 32];
/// Fixed destination X25519 secret; `board` seals each per-cofre data key to its public key (bench shim).
const DEST_X25519_SECRET: [u8; 32] = [9u8; 32];
/// Fixed per-tenant idempotency-MAC secret (bench shim — see module note).
const TENANT_SECRET: [u8; 32] = [6u8; 32];

/// Bounded capacity of each egress subscriber's delivery channel (frames awaiting async write). A burst beyond
/// this back-pressures the seal worker's fan-out send, never grows unbounded.
const EGRESS_CHANNEL_DEPTH: usize = 8192;

// ----------------------------------------------------------------------------------------------------------
// Config — TOML, all fields optional, defaults per OMB-PROTOCOL.md. Hand-rolled `key = value` parse (no deps).
// ----------------------------------------------------------------------------------------------------------

/// Which real transport the cofre traverses between source and dest. Default [`Substrate::Loopback`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubstrateKind {
    /// In-process handoff: `board` → `offload` directly (still the full seal/open path). The frozen default.
    Loopback,
    /// A real `127.0.0.1` TCP kernel hop ([`datarail_rail::TcpSubstrate`]) between board and offload.
    Tcp,
    /// A real shared-memory ring hop ([`datarail_substrate_shmem::ShmemRing`]) between board and offload.
    Shmem,
    /// A **durable** fsync'd write-ahead-log hop ([`datarail_substrate_wal::DurableLog`]) — each cofre is sealed
    /// to disk and fsync'd (group commit per 128-record cofre) before the dest opens it. The Kafka-`acks=all`
    /// equivalent path, at O(1) RAM.
    Wal,
}

/// The shim's parsed configuration (`docs/design/OMB-PROTOCOL.md` §"Shim config").
#[derive(Debug, Clone)]
struct Config {
    /// Address producers connect to. Default `127.0.0.1:7701`.
    ingress_addr: String,
    /// Address consumers connect to. Default `127.0.0.1:7702`.
    egress_addr: String,
    /// Transport between the source and dest terminals. Default [`SubstrateKind::Loopback`].
    substrate: SubstrateKind,
    /// Flush a cofre once a batch reaches this many records. Default `128`.
    batch_max_records: usize,
    /// Flush a partial batch once it has been filling for this long. Default `1000` µs.
    batch_max_micros: u64,
    /// Reject any single frame whose payload exceeds this many bytes (parse-safety). Default `1_048_576`.
    max_record_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ingress_addr: "127.0.0.1:7701".to_owned(),
            egress_addr: "127.0.0.1:7702".to_owned(),
            substrate: SubstrateKind::Loopback,
            batch_max_records: 128,
            batch_max_micros: 1000,
            max_record_bytes: 1_048_576,
        }
    }
}

impl Config {
    /// Parse a config from a TOML file at `path`, layering over [`Config::default`]. Only the documented flat
    /// `key = value` keys are recognised; any unknown key is a hard error (typo safety). All values optional.
    fn from_path(path: &str) -> Result<Self, ShimError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ShimError::Config(format!("{path}: {e}")))?;
        Self::from_str(&text)
    }

    /// Parse a config from already-loaded TOML `text`, layering over [`Config::default`].
    fn from_str(text: &str) -> Result<Self, ShimError> {
        let mut cfg = Self::default();
        for raw in text.lines() {
            // Strip a `#` comment, then surrounding whitespace; skip blank / comment-only lines.
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| ShimError::Config(format!("not `key = value`: {raw:?}")))?;
            let key = key.trim();
            let value = unquote(value.trim());
            match key {
                "ingress_addr" => value.clone_into(&mut cfg.ingress_addr),
                "egress_addr" => value.clone_into(&mut cfg.egress_addr),
                "substrate" => cfg.substrate = parse_substrate(value)?,
                "batch_max_records" => cfg.batch_max_records = parse_usize(key, value)?,
                "batch_max_micros" => cfg.batch_max_micros = parse_u64(key, value)?,
                "max_record_bytes" => cfg.max_record_bytes = parse_usize(key, value)?,
                other => return Err(ShimError::Config(format!("unknown config key `{other}`"))),
            }
        }
        if cfg.batch_max_records == 0 {
            return Err(ShimError::Config(
                "batch_max_records must be >= 1".to_owned(),
            ));
        }
        Ok(cfg)
    }
}

/// Strip one matching pair of surrounding single or double quotes from a TOML scalar, if present.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

/// Parse the `substrate` enum value.
fn parse_substrate(value: &str) -> Result<SubstrateKind, ShimError> {
    match value {
        "loopback" => Ok(SubstrateKind::Loopback),
        "tcp" => Ok(SubstrateKind::Tcp),
        "shmem" => Ok(SubstrateKind::Shmem),
        "wal" => Ok(SubstrateKind::Wal),
        other => Err(ShimError::Config(format!(
            "substrate must be loopback|tcp|shmem|wal, got `{other}`"
        ))),
    }
}

/// Parse a `usize` config scalar with a key-qualified error.
fn parse_usize(key: &str, value: &str) -> Result<usize, ShimError> {
    value
        .parse()
        .map_err(|_| ShimError::Config(format!("`{key}` is not a non-negative integer: `{value}`")))
}

/// Parse a `u64` config scalar with a key-qualified error.
fn parse_u64(key: &str, value: &str) -> Result<u64, ShimError> {
    value
        .parse()
        .map_err(|_| ShimError::Config(format!("`{key}` is not a non-negative integer: `{value}`")))
}

// ----------------------------------------------------------------------------------------------------------
// Errors.
// ----------------------------------------------------------------------------------------------------------

/// A fatal shim error (config, runtime build, or socket bind/accept). Per-connection I/O errors are handled
/// locally and end only that connection's task; they never reach here.
#[derive(Debug)]
enum ShimError {
    /// The config file could not be read or parsed.
    Config(String),
    /// An ingress/egress listener could not be bound.
    Bind(String),
    /// The async runtime could not be built.
    Runtime(String),
}

impl core::fmt::Display for ShimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config: {e}"),
            Self::Bind(e) => write!(f, "bind: {e}"),
            Self::Runtime(e) => write!(f, "runtime: {e}"),
        }
    }
}

impl core::error::Error for ShimError {}

// ----------------------------------------------------------------------------------------------------------
// Internal messages.
// ----------------------------------------------------------------------------------------------------------

/// One delivered message handed to every egress subscriber, as the whole `{publish_ts(8B) || payload}` record
/// behind an [`Arc`]. Fan-out is then an `Arc` clone (no payload copy), and egress writes the frame body
/// straight from it — the wire frame is `[u32 payload_len][record]` because `record == publish_ts || payload`,
/// so no split or re-assembly allocation is needed on the hot path.
#[derive(Clone)]
struct Delivered {
    /// The committed `{publish_ts(8 BE) || payload}` record; `record.len() >= 8` is guaranteed by the worker.
    record: Arc<Vec<u8>>,
}

/// One ingested message queued to a topic worker: the assembled `{publish_ts(8B) || payload}` record bytes.
struct Ingested {
    /// `publish_ts_millis` (8 BE bytes) followed by the raw payload — exactly the record `board` seals.
    record: Vec<u8>,
}

/// A topic's shared handle: the channel into its worker (for producers) and its subscriber list (for
/// consumers). Created lazily on first reference and stored in the [`Registry`].
#[derive(Clone)]
struct TopicHandle {
    /// Sink for ingested records → the topic worker. **Bounded** ([`tokio::sync::mpsc::Sender`]): when the
    /// seal/open worker is the bottleneck, this fills and `send().await` parks the ingress task, so it stops
    /// reading the producer socket → the producer's TCP buffer fills → the producer slows. That is datarail's
    /// backpressure (0-loss, no unbounded backlog), versus an unbounded queue that would grow until OOM under
    /// a firehose.
    ingress_tx: mpsc::Sender<Ingested>,
    /// Every egress subscriber's delivery channel. The worker fans each offloaded record out to all of them.
    subscribers: Arc<Mutex<Vec<mpsc::Sender<Delivered>>>>,
}

/// The lazy topic registry: topic name → handle, behind a mutex. Cloned (`Arc`) into every connection task.
type Registry = Arc<Mutex<HashMap<String, TopicHandle>>>;

// ----------------------------------------------------------------------------------------------------------
// Entry point.
// ----------------------------------------------------------------------------------------------------------

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("datarail-omb-shim: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Parse the optional config (argv[1]), build the multi-thread tokio runtime, bind both listeners, and serve
/// forever. Returns only on a fatal config/runtime/bind error (the accept loops never terminate normally).
///
/// The runtime is built explicitly (not via `#[tokio::main]`) so the worker count is the default = number of
/// cores and so a build failure is a typed [`ShimError`] rather than a panic.
fn run() -> Result<(), ShimError> {
    let cfg = match std::env::args().nth(1) {
        Some(path) => Config::from_path(&path)?,
        None => Config::default(),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| ShimError::Runtime(e.to_string()))?;

    runtime.block_on(serve(cfg))
}

/// The async entry point: bind both listeners, announce the bound addresses, then run both accept loops
/// concurrently forever. Returns only on a fatal bind error.
async fn serve(cfg: Config) -> Result<(), ShimError> {
    let ingress = TcpListener::bind(&cfg.ingress_addr)
        .await
        .map_err(|e| ShimError::Bind(format!("ingress {}: {e}", cfg.ingress_addr)))?;
    let egress = TcpListener::bind(&cfg.egress_addr)
        .await
        .map_err(|e| ShimError::Bind(format!("egress {}: {e}", cfg.egress_addr)))?;

    // Report the actually-bound addresses (an OS-assigned `:0` port resolves here) so a test/orchestrator can
    // discover them; flush so the line is observable before the accept loops block.
    let ingress_bound = ingress
        .local_addr()
        .map_err(|e| ShimError::Bind(e.to_string()))?;
    let egress_bound = egress
        .local_addr()
        .map_err(|e| ShimError::Bind(e.to_string()))?;
    println!(
        "DATARAIL-OMB-SHIM ingress={ingress_bound} egress={egress_bound} substrate={:?}",
        cfg.substrate
    );
    flush_stdout();

    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

    // Both accept loops run as concurrent tasks on the runtime; neither returns. `select` so that if either
    // listener dies (a fatal accept error path that breaks its loop) the process surfaces it instead of
    // silently serving on one port.
    let ingress_registry = Arc::clone(&registry);
    let ingress_cfg = cfg.clone();
    let ingress_task = tokio::spawn(async move {
        accept_loop(ingress, ingress_registry, ingress_cfg, ConnKind::Ingress).await;
    });
    let egress_task =
        tokio::spawn(async move { accept_loop(egress, registry, cfg, ConnKind::Egress).await });

    // Neither task returns under normal operation; join both so a panic/cancel in one is not lost.
    let _ = tokio::join!(ingress_task, egress_task);
    Ok(())
}

/// Flush stdout, ignoring the (unobservable here) error — the announce line is best-effort observability.
fn flush_stdout() {
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
}

/// Which side a connection serves; selects the per-connection handler.
#[derive(Clone, Copy)]
enum ConnKind {
    /// Producer side (ingress port).
    Ingress,
    /// Consumer side (egress port).
    Egress,
}

/// Generic async accept loop: for every accepted connection, spawn a tokio task running the matching handler
/// (each task owns its own clones). A failed `accept` is logged and skipped (the listener stays up). Never
/// returns under normal operation.
async fn accept_loop(listener: TcpListener, registry: Registry, cfg: Config, kind: ConnKind) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let registry = Arc::clone(&registry);
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    match kind {
                        ConnKind::Ingress => serve_ingress(stream, &registry, &cfg).await,
                        ConnKind::Egress => serve_egress(stream, &registry, &cfg).await,
                    }
                });
            }
            Err(e) => eprintln!("datarail-omb-shim: accept failed: {e}"),
        }
    }
}

// ----------------------------------------------------------------------------------------------------------
// Lazy topic creation.
// ----------------------------------------------------------------------------------------------------------

/// Look up `topic`, creating its worker thread + handle on first reference (lazy topics — no control message).
/// Returns a clone of the handle. A poisoned registry mutex is reported as `None` (the caller ends its
/// connection); it cannot happen unless a worker panicked, which the no-unwrap datapath precludes.
///
/// The seal worker is a real `std::thread` (the `SourceTerminal`/`DestTerminal` are synchronous `&mut self`
/// state machines that must not block a runtime worker). It is handed the runtime [`Handle`] so it can drive a
/// timed batch `recv` on its [`tokio::sync::mpsc::Receiver`] without busy-spinning.
fn topic_handle(registry: &Registry, cfg: &Config, topic: &str) -> Option<TopicHandle> {
    let mut map = registry.lock().ok()?;
    if let Some(handle) = map.get(topic) {
        return Some(handle.clone());
    }
    // Bounded ingress queue → backpressure (see `TopicHandle::ingress_tx`). Depth scales with the batch size
    // (a handful of batches in flight) and is clamped so worst-case buffered memory stays bounded.
    let depth = cfg.batch_max_records.saturating_mul(16).clamp(256, 65_536);
    let (ingress_tx, ingress_rx) = mpsc::channel::<Ingested>(depth);
    let subscribers: Arc<Mutex<Vec<mpsc::Sender<Delivered>>>> = Arc::new(Mutex::new(Vec::new()));
    let handle = TopicHandle {
        ingress_tx,
        subscribers: Arc::clone(&subscribers),
    };
    let worker_cfg = cfg.clone();
    let topic_name = topic.to_owned();
    let runtime = Handle::current();
    std::thread::Builder::new()
        .name(format!("omb-topic-{topic}"))
        .spawn(move || topic_worker(&topic_name, &worker_cfg, ingress_rx, &subscribers, &runtime))
        .ok()?;
    map.insert(topic.to_owned(), handle.clone());
    Some(handle)
}

// ----------------------------------------------------------------------------------------------------------
// Topic worker — the REAL sealed datapath (board → substrate → offload → fan-out), batched.
// ----------------------------------------------------------------------------------------------------------

/// Build the content contract for the shim's route: a **zero-length** required prefix (OMB sends random
/// payloads, so no prefix may be required) and a `max_record_len` of `max_record_bytes + 8` (the 8-byte
/// `publish_ts` rides ahead of every payload inside the record). Mirrors `OMB-PROTOCOL.md` §"Shim internals".
fn build_contract(cfg: &Config) -> ContentContract {
    ContentContract::new(cfg.max_record_bytes + 8, Vec::new())
}

/// Build the shared [`TerminalConfig`] for the shim's single in-process route (GCM-SIV default AEAD).
fn build_terminal_config() -> TerminalConfig {
    TerminalConfig {
        route_id: ROUTE_ID,
        stream_id: STREAM_ID,
        // Default = AES-256-GCM-SIV (portable, two-pass). With `--features vaes` the route uses plain
        // AES-256-GCM (single-pass) on datarail's VAES backend — the "warp" seal path. Plain GCM is sound here
        // because every cofre carries a FRESH per-cofre data key (SPEC key-uniqueness gate ⇒ no nonce reuse).
        #[cfg(feature = "vaes")]
        aead_alg: AeadAlg::Gcm256,
        #[cfg(not(feature = "vaes"))]
        aead_alg: AeadAlg::Gcmsiv256,
        // The destination X25519 *public* key matching `DEST_X25519_SECRET` — the same primitive
        // `head_to_head` uses, so `board`'s per-cofre key-wrap targets a key the dest can open.
        dest_x25519_pk: x25519_public(&DEST_X25519_SECRET),
        tenant_secret: TENANT_SECRET,
    }
}

/// One topic's REAL sealed datapath: a real `SourceTerminal`, a real `DestTerminal`, the chosen substrate, and
/// the two cursors that make fan-out exactly-once. Bundled into one struct so the per-batch step is a method
/// (not an 8-argument free function) — and so the cohesive seal-path state lives in one place.
struct TopicEngine {
    /// Onboarding terminal — seals each batch into a cofre.
    source: SourceTerminal,
    /// Offloading terminal — verifies/opens/admits/commits each cofre; its sink holds the delivered records.
    dest: DestTerminal,
    /// The transport the cofre traverses between board and offload.
    transport: Transport,
    /// Monotonic record-key counter: a unique key per cofre ⇒ the once-gate never false-dedups a distinct
    /// batch (the same discipline as `datarail-bench`'s `head_to_head`).
    cofre_seq: u64,
}

impl TopicEngine {
    /// Build the engine for one topic from the shim config (fixed in-process route keys — bench shim only).
    fn new(cfg: &Config) -> Self {
        let term_cfg = build_terminal_config();
        let contract = build_contract(cfg);
        let src_vk = verifying_key(&SRC_SEED);
        let source = SourceTerminal::new(term_cfg.clone(), contract.clone(), SRC_SEED);
        let dest = DestTerminal::new(term_cfg, contract, src_vk, DEST_SEED, DEST_X25519_SECRET);
        Self {
            source,
            dest,
            transport: Transport::new(cfg.substrate),
            cofre_seq: 0,
        }
    }

    /// Board one batch into a sealed cofre, move it across the substrate, offload it (full verify→open→admit→
    /// commit), then split each newly-committed record back into `{publish_ts, payload}` and fan it out to
    /// every subscriber. A unique `record_key` per cofre keeps the once-gate from deduping distinct batches.
    ///
    /// The seal-path calls are infallible in practice for our own well-formed records, but the code never
    /// unwraps: a board/offload error or a non-`Delivered` disposition is logged and the batch is skipped (a
    /// regression would surface as missing deliveries in the round-trip test, never a panic).
    fn flush(
        &mut self,
        topic: &str,
        batch: &[Vec<u8>],
        subscribers: &Arc<Mutex<Vec<mpsc::Sender<Delivered>>>>,
    ) {
        if batch.is_empty() {
            return;
        }
        let refs: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
        let record_key = self.cofre_seq.to_le_bytes();
        self.cofre_seq += 1;

        let cofre = match self.source.board(&refs, &record_key) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "datarail-omb-shim[{topic}]: board failed ({e}); dropping {} record(s)",
                    batch.len()
                );
                return;
            }
        };

        let received = match self.transport.relay(&cofre) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "datarail-omb-shim[{topic}]: substrate relay failed ({e}); dropping batch"
                );
                return;
            }
        };

        match self.dest.offload(&received) {
            Ok(Disposition::Delivered) => {}
            Ok(other) => {
                // Distinct record-keys mean this is never Duplicate; a DeadLettered batch never delivers.
                eprintln!("datarail-omb-shim[{topic}]: offload returned {other:?} (not Delivered); skipping");
                return;
            }
            Err(e) => {
                eprintln!("datarail-omb-shim[{topic}]: offload failed ({e}); dropping batch");
                return;
            }
        }

        // DRAIN the records this offload committed (take, not borrow): the sink must not retain them, else a
        // long stream grows it until OOM. Each offload commits exactly this batch, and we drained last time, so
        // the drain yields exactly the fresh records. Wrap each owned record in an Arc (no copy) and fan it out;
        // the egress writer emits `[len][record]` directly, so there is no per-message split/clone of the payload.
        for record in self.dest.sink_mut().take_committed() {
            if record.len() >= 8 {
                fan_out(
                    subscribers,
                    &Delivered {
                        record: Arc::new(record),
                    },
                );
            } else {
                eprintln!("datarail-omb-shim[{topic}]: committed record shorter than 8-byte ts header; skip");
            }
        }
    }
}

/// The per-topic worker (a dedicated **`std::thread`**): owns the topic's [`TopicEngine`], drains the bounded
/// ingress channel in **batches** (flush on `batch_max_records` OR `batch_max_micros`, whichever first), runs
/// every batch through the full seal/open path, and fans the delivered records out to every subscriber. Exits
/// when the registry (hence every producer) drops the [`tokio::sync::mpsc::Sender`] and the channel closes.
///
/// It bridges async→blocking by holding the [`tokio::sync::mpsc::Receiver`] directly and driving its `recv`
/// from this OS thread via the runtime `handle`: a synchronous `blocking_recv` for the first record of a
/// batch, then `handle.block_on(timeout(..))` to fill the batch up to the time window. No CPU-bound terminal
/// work ever runs on a runtime worker, so the async event loop is never blocked.
fn topic_worker(
    topic: &str,
    cfg: &Config,
    mut ingress_rx: mpsc::Receiver<Ingested>,
    subscribers: &Arc<Mutex<Vec<mpsc::Sender<Delivered>>>>,
    handle: &Handle,
) {
    let mut engine = TopicEngine::new(cfg);
    let batch_window = Duration::from_micros(cfg.batch_max_micros);

    loop {
        // Block for the first record of a batch; `None` means the channel closed (every producer hung up and
        // the registry handle is gone) ⇒ the topic is done.
        let Some(first) = ingress_rx.blocking_recv() else {
            return;
        };
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(cfg.batch_max_records);
        batch.push(first.record);

        // Fill the batch until it is full OR the time window elapses, whichever first. `recv_until` drives the
        // async receiver from this thread with a deadline; a closed channel ends the fill (then the next outer
        // `blocking_recv` returns `None` and the worker exits).
        let deadline = Instant::now() + batch_window;
        while batch.len() < cfg.batch_max_records {
            match recv_until(handle, &mut ingress_rx, deadline) {
                BatchRecv::Got(record) => batch.push(record),
                BatchRecv::WindowElapsed | BatchRecv::Closed => break,
            }
        }

        engine.flush(topic, &batch, subscribers);
    }
}

/// The outcome of a timed batch-fill `recv` on the ingress channel.
enum BatchRecv {
    /// A record arrived before the deadline.
    Got(Vec<u8>),
    /// The batch time window elapsed before another record arrived.
    WindowElapsed,
    /// The channel closed (every producer + the registry handle dropped).
    Closed,
}

/// Receive the next ingested record, waiting at most until `deadline`. Drives the async
/// [`tokio::sync::mpsc::Receiver`] from the blocking worker thread via `handle.block_on(timeout(..))` — so the
/// batch time window is honoured without busy-spinning and without blocking a runtime worker.
fn recv_until(
    handle: &Handle,
    ingress_rx: &mut mpsc::Receiver<Ingested>,
    deadline: Instant,
) -> BatchRecv {
    let now = Instant::now();
    if now >= deadline {
        return BatchRecv::WindowElapsed;
    }
    let remaining = deadline - now;
    match handle.block_on(async { tokio::time::timeout(remaining, ingress_rx.recv()).await }) {
        Ok(Some(msg)) => BatchRecv::Got(msg.record),
        Ok(None) => BatchRecv::Closed,
        Err(_elapsed) => BatchRecv::WindowElapsed,
    }
}

/// Fan `delivered` out to every live subscriber on the topic, dropping any whose consumer has disconnected
/// (its egress task closed the receiver). Each distinct subscription is an independent delivery copy, per OMB
/// semantics ("each subscription gets all messages"). The clone is a cheap `Arc` bump — no payload copy.
///
/// A bounded subscriber channel that is momentarily full back-pressures here via `blocking_send` (this is a
/// dedicated OS thread, so blocking it is correct — it parks the seal worker, which fills the ingress channel,
/// which slows the producer; the same 0-loss chain as ingress). A closed receiver (consumer gone) drops the
/// subscriber.
fn fan_out(subscribers: &Arc<Mutex<Vec<mpsc::Sender<Delivered>>>>, delivered: &Delivered) {
    let Ok(mut subs) = subscribers.lock() else {
        return; // poisoned only if an egress task panicked; nothing to deliver to then.
    };
    subs.retain(|tx| tx.blocking_send(delivered.clone()).is_ok());
}

// ----------------------------------------------------------------------------------------------------------
// Substrate relay — board → (chosen transport) → offload. Loopback is a direct in-process handoff.
// ----------------------------------------------------------------------------------------------------------

/// The transport a cofre traverses between `board` and `offload`. `Loopback` returns the cofre directly (the
/// frozen default in-process handoff); `Tcp`/`Shmem` push it through a real substrate and drain it back, so
/// the full framed encode→decode round-trip is exercised before the dest opens it.
enum Transport {
    /// Direct hand-off — no transport object; the cofre is offloaded as boarded.
    Loopback,
    /// A real `127.0.0.1` TCP substrate (a genuine kernel hop on loopback).
    Tcp(TcpSubstrate),
    /// A real shared-memory ring substrate.
    Shmem(ShmemRing),
    /// A durable fsync'd write-ahead log (each cofre sealed to disk + fsync'd before offload).
    Wal(datarail_substrate_wal::DurableLog),
}

impl Transport {
    /// Build the transport for `kind`. A failure to create the real `tcp`/`shmem` substrate falls back to a
    /// loopback handoff (logged): the seal/open path still runs, only the extra hop is skipped — a benchmark
    /// adapter degrades to the faithful default rather than refusing to serve.
    fn new(kind: SubstrateKind) -> Self {
        match kind {
            SubstrateKind::Loopback => Self::Loopback,
            SubstrateKind::Tcp => match TcpSubstrate::loopback_pair() {
                Ok(s) => Self::Tcp(s),
                Err(e) => {
                    eprintln!("datarail-omb-shim: tcp substrate unavailable ({e}); using loopback handoff");
                    Self::Loopback
                }
            },
            SubstrateKind::Shmem => match ShmemRing::pair() {
                Ok(s) => Self::Shmem(s),
                Err(e) => {
                    eprintln!("datarail-omb-shim: shmem substrate unavailable ({e}); using loopback handoff");
                    Self::Loopback
                }
            },
            SubstrateKind::Wal => {
                // A unique per-engine durable log dir (DATARAIL_WAL_DIR root, else the system temp dir).
                let root = std::env::var("DATARAIL_WAL_DIR")
                    .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
                let dir = std::path::Path::new(&root).join(format!("dr-wal-{}", next_wal_id()));
                match datarail_substrate_wal::DurableLog::open(&dir) {
                    Ok(log) => Self::Wal(log),
                    Err(e) => {
                        eprintln!("datarail-omb-shim: wal substrate unavailable ({e}); using loopback handoff");
                        Self::Loopback
                    }
                }
            }
        }
    }

    /// Move one cofre across the transport and return the received copy to offload. For `Loopback` this is the
    /// same cofre; for a real substrate it is the byte-identical cofre after a framed send/recv round-trip.
    ///
    /// # Errors
    /// Returns a transport error string if a real substrate fails to send/recv (loopback never fails).
    fn relay(&mut self, cofre: &Cofre) -> Result<Cofre, String> {
        match self {
            Self::Loopback => Ok(cofre.clone()),
            Self::Tcp(s) => relay_through(s, cofre),
            Self::Shmem(s) => relay_through(s, cofre),
            Self::Wal(s) => relay_through(s, cofre),
        }
    }
}

/// Monotonic id for per-engine WAL directories (unique dir per topic worker so their logs never collide).
fn next_wal_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// Send `cofre` over a real substrate and drain it back (the substrate is a FIFO pipe; one in, one out). Used
/// for the `tcp`/`shmem` modes. Polls `recv` with a bounded spin so a slow kernel hop cannot hang the worker
/// forever, then acks the received cofre to keep any resumable substrate's window clear.
fn relay_through<S: Substrate>(sub: &mut S, cofre: &Cofre) -> Result<Cofre, String>
where
    S::Error: core::fmt::Display,
{
    sub.send(cofre).map_err(|e| format!("send: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match sub.recv() {
            Ok(Some(received)) => {
                sub.ack(received.etiqueta.cofre_id)
                    .map_err(|e| format!("ack: {e}"))?;
                return Ok(received);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err("substrate recv timed out".to_owned());
                }
                std::thread::yield_now();
            }
            Err(e) => return Err(format!("recv: {e}")),
        }
    }
}

// ----------------------------------------------------------------------------------------------------------
// Ingress connection — producer → shim. Header, then frames; one monotonic ack per accepted message.
// ----------------------------------------------------------------------------------------------------------

/// Serve one producer connection (a tokio task). Reads the `[u16 topic_len][topic]` header, resolves (lazily
/// creates) the topic, then loops reading `[u32 payload_len][u64 publish_ts][payload]` frames: for each,
/// assemble the `{publish_ts || payload}` record, `send().await` it to the topic worker, and write back a
/// monotonic `[u64 seq]` ack (from 0, in receive order). The handoff to the worker IS the ack point (acks=1:
/// boarded + handed to the substrate, per the frozen contract) — the worker still seals every record on the
/// real datapath. Ends the task cleanly on EOF or any socket/parse error.
async fn serve_ingress(stream: TcpStream, registry: &Registry, cfg: &Config) {
    if let Err(e) = serve_ingress_inner(stream, registry, cfg).await {
        // EOF/peer-close is the normal end of a producer; only note genuinely unexpected errors.
        if e.kind() != std::io::ErrorKind::UnexpectedEof
            && e.kind() != std::io::ErrorKind::ConnectionReset
        {
            eprintln!("datarail-omb-shim: ingress connection ended: {e}");
        }
    }
}

/// The fallible body of [`serve_ingress`]; every framing/socket error bubbles up as `io::Error` to end the
/// connection task without panicking.
async fn serve_ingress_inner(
    stream: TcpStream,
    registry: &Registry,
    cfg: &Config,
) -> std::io::Result<()> {
    // Buffered async I/O on BOTH directions: an unbuffered per-message read+ack is ~3 syscalls/msg, which caps
    // throughput at the syscall rate (the real bottleneck, not the crypto). A BufReader coalesces frame reads
    // and a BufWriter coalesces acks; acks flush when we have caught up to the socket (so a streaming producer
    // still gets timely acks, but a burst is acked in one write).
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut acks = BufWriter::new(write_half);
    let topic = read_topic_header(&mut reader).await?;
    let handle = topic_handle(registry, cfg, &topic)
        .ok_or_else(|| std::io::Error::other("topic registry unavailable"))?;

    let mut seq: u64 = 0;
    let mut hdr = [0u8; 12]; // [u32 payload_len][u64 publish_ts]
    loop {
        // Read the 12-byte frame header; a clean EOF here ends the producer. Flush any pending acks first so a
        // producer that paused is not left waiting on buffered-but-unsent acks.
        if reader.buffer().is_empty() {
            acks.flush().await?;
        }
        match read_exact_or_eof(&mut reader, &mut hdr).await? {
            ReadEnd::Eof => {
                acks.flush().await?;
                return Ok(());
            }
            ReadEnd::Full => {}
        }
        let payload_len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let publish_ts = u64::from_be_bytes([
            hdr[4], hdr[5], hdr[6], hdr[7], hdr[8], hdr[9], hdr[10], hdr[11],
        ]);
        if payload_len > cfg.max_record_bytes {
            return Err(std::io::Error::other(format!(
                "frame payload_len {payload_len} exceeds max_record_bytes {}",
                cfg.max_record_bytes
            )));
        }

        // Assemble the record `{publish_ts(8 BE) || payload}` directly, reading the payload into place.
        let mut record = vec![0u8; 8 + payload_len];
        record[0..8].copy_from_slice(&publish_ts.to_be_bytes());
        reader.read_exact(&mut record[8..]).await?;

        // Hand to the worker (the accept point; the bounded channel applies backpressure here — when the seal
        // worker lags, `send().await` parks this task, so we stop reading this socket and the producer's TCP
        // buffer fills). Then buffer the ack in receive order. A worker-gone (closed channel) error ends us.
        // Flush pending acks before a send that may park so the producer is never stalled on acks we are holding.
        if reader.buffer().is_empty() {
            acks.flush().await?;
        }
        handle
            .ingress_tx
            .send(Ingested { record })
            .await
            .map_err(|_| std::io::Error::other("topic worker gone"))?;
        acks.write_all(&seq.to_be_bytes()).await?;
        seq += 1;
    }
}

// ----------------------------------------------------------------------------------------------------------
// Egress connection — consumer → shim. Header, then a stream of delivered frames.
// ----------------------------------------------------------------------------------------------------------

/// Serve one consumer connection (a tokio task). Reads the `[u16 topic_len][topic][u16 sub_len][sub]` header,
/// registers a fresh delivery channel on the topic (each distinct subscription is its own fan-out copy), then
/// streams `[u32 payload_len][u64 publish_ts][payload]` frames for every delivered message until the consumer
/// disconnects. Ends the task cleanly on any socket error.
async fn serve_egress(stream: TcpStream, registry: &Registry, cfg: &Config) {
    if let Err(e) = serve_egress_inner(stream, registry, cfg).await {
        if e.kind() != std::io::ErrorKind::UnexpectedEof
            && e.kind() != std::io::ErrorKind::ConnectionReset
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            eprintln!("datarail-omb-shim: egress connection ended: {e}");
        }
    }
}

/// The fallible body of [`serve_egress`]: register a subscriber channel, then write each delivered frame to
/// the socket. The `sub` name is read per the protocol and (intentionally) used only to model an independent
/// delivery copy — every subscription receives every message (OMB consumer-group semantics, v1).
async fn serve_egress_inner(
    stream: TcpStream,
    registry: &Registry,
    cfg: &Config,
) -> std::io::Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let topic = read_topic_header(&mut reader).await?;
    let _sub = read_len_prefixed_string(&mut reader).await?; // independent fan-out copy per subscription (v1).

    let handle = topic_handle(registry, cfg, &topic)
        .ok_or_else(|| std::io::Error::other("topic registry unavailable"))?;
    // Bounded subscriber channel: a slow consumer back-pressures the seal worker's fan-out (`blocking_send`),
    // never an unbounded backlog. Matches the old `mpsc::channel` delivery semantics with a hard cap.
    let (tx, mut rx) = mpsc::channel::<Delivered>(EGRESS_CHANNEL_DEPTH);
    handle
        .subscribers
        .lock()
        .map_err(|_| std::io::Error::other("subscriber registry poisoned"))?
        .push(tx);

    // Buffered async writer: a per-message `write_all` is one syscall per message and caps egress throughput at
    // the syscall rate. We coalesce a burst of delivered frames into the buffer and flush only when the delivery
    // channel momentarily drains — full throughput under load, still low-latency when idle.
    let mut out = BufWriter::new(write_half);
    loop {
        // Block for the next delivery; `recv` returns `None` only when the worker drops the sender (topic done).
        let Some(delivered) = rx.recv().await else {
            out.flush().await?;
            return Ok(());
        };
        write_egress_frame(&mut out, &delivered).await?;
        // Drain whatever else is immediately ready into the same buffer, then flush once.
        while let Ok(more) = rx.try_recv() {
            write_egress_frame(&mut out, &more).await?;
        }
        out.flush().await?;
    }
}

/// Write one egress frame `[u32 payload_len][u64 publish_ts][payload]` into the buffered writer. Because a
/// committed record is exactly `publish_ts || payload`, the frame body after the length prefix IS the record
/// bytes — write the length then the record slice directly. No split, no per-message payload copy.
async fn write_egress_frame<W: AsyncWriteExt + Unpin>(
    out: &mut W,
    d: &Delivered,
) -> std::io::Result<()> {
    let payload_len = u32::try_from(d.record.len() - 8)
        .map_err(|_| std::io::Error::other("delivered payload exceeds u32"))?;
    out.write_all(&payload_len.to_be_bytes()).await?;
    out.write_all(&d.record).await
}

// ----------------------------------------------------------------------------------------------------------
// Wire-reading helpers (big-endian, length-prefixed). Async over `tokio::io`.
// ----------------------------------------------------------------------------------------------------------

/// Whether a read filled the buffer or hit a clean EOF at a frame boundary.
enum ReadEnd {
    /// The buffer was fully filled.
    Full,
    /// EOF occurred with **zero** bytes read (a clean end between frames).
    Eof,
}

/// Read exactly `buf.len()` bytes, distinguishing a clean EOF at the start (no bytes yet) from a truncated
/// frame mid-read (which is an error). A frame header read uses this so a producer closing between frames ends
/// the connection cleanly rather than erroring.
async fn read_exact_or_eof<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    buf: &mut [u8],
) -> std::io::Result<ReadEnd> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]).await {
            Ok(0) => {
                if filled == 0 {
                    return Ok(ReadEnd::Eof);
                }
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ReadEnd::Full)
}

/// Read a `[u16 len][utf8]` length-prefixed string (big-endian). Used for the topic and the subscription name.
async fn read_len_prefixed_string<R: AsyncReadExt + Unpin>(
    stream: &mut R,
) -> std::io::Result<String> {
    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|_| std::io::Error::other("topic/sub name is not valid UTF-8"))
}

/// Read the leading `[u16 topic_len][topic_utf8]` header common to both ingress and egress connections.
async fn read_topic_header<R: AsyncReadExt + Unpin>(stream: &mut R) -> std::io::Result<String> {
    read_len_prefixed_string(stream).await
}

#[cfg(test)]
mod tests {
    use super::{build_contract, unquote, Config, SubstrateKind};

    #[test]
    fn config_defaults_match_the_frozen_contract() {
        let cfg = Config::default();
        assert_eq!(cfg.ingress_addr, "127.0.0.1:7701");
        assert_eq!(cfg.egress_addr, "127.0.0.1:7702");
        assert_eq!(cfg.substrate, SubstrateKind::Loopback);
        assert_eq!(cfg.batch_max_records, 128);
        assert_eq!(cfg.batch_max_micros, 1000);
        assert_eq!(cfg.max_record_bytes, 1_048_576);
    }

    #[test]
    fn config_parses_documented_keys_and_layers_over_defaults() {
        let toml = r#"
            # a comment
            ingress_addr = "127.0.0.1:9001"
            egress_addr  = '127.0.0.1:9002'
            substrate    = "tcp"
            batch_max_records = 64
            batch_max_micros  = 500   # inline comment
        "#;
        let cfg = Config::from_str(toml).unwrap();
        assert_eq!(cfg.ingress_addr, "127.0.0.1:9001");
        assert_eq!(cfg.egress_addr, "127.0.0.1:9002");
        assert_eq!(cfg.substrate, SubstrateKind::Tcp);
        assert_eq!(cfg.batch_max_records, 64);
        assert_eq!(cfg.batch_max_micros, 500);
        // Untouched key keeps its default.
        assert_eq!(cfg.max_record_bytes, 1_048_576);
    }

    #[test]
    fn config_rejects_unknown_key_and_zero_batch() {
        assert!(Config::from_str("nope = 1").is_err());
        assert!(Config::from_str("batch_max_records = 0").is_err());
        assert!(Config::from_str("substrate = \"carrier-pigeon\"").is_err());
    }

    #[test]
    fn unquote_strips_one_matching_pair() {
        assert_eq!(unquote("\"x\""), "x");
        assert_eq!(unquote("'x'"), "x");
        assert_eq!(unquote("bare"), "bare");
        assert_eq!(unquote("\"mismatch'"), "\"mismatch'");
    }

    #[test]
    fn contract_admits_max_payload_plus_ts_and_zero_prefix() {
        let cfg = Config::default();
        let contract = build_contract(&cfg);
        assert!(contract.required_prefix.is_empty());
        // A full-size payload plus the 8-byte ts header must validate (boundary).
        let max_record = vec![0xABu8; cfg.max_record_bytes + 8];
        assert!(contract.validate(&max_record));
        // One byte over the cap must NOT validate.
        let too_big = vec![0xABu8; cfg.max_record_bytes + 9];
        assert!(!contract.validate(&too_big));
    }

    #[test]
    fn egress_frame_body_is_the_record() {
        // The egress wire frame is `[u32 payload_len][u64 publish_ts][payload]`. Because a committed record is
        // exactly `publish_ts || payload`, the frame body after the length prefix IS the record bytes — this is
        // what lets egress write `[len][record]` with no split/copy. Assert the relationship holds.
        let mut record = Vec::new();
        record.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        record.extend_from_slice(b"hello");
        let payload_len = record.len() - 8;
        assert_eq!(payload_len, 5);
        assert_eq!(&record[0..8], &0x0102_0304_0506_0708u64.to_be_bytes()); // ts
        assert_eq!(&record[8..], b"hello"); // payload
    }
}
