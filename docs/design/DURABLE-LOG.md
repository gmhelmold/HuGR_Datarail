# DURABLE-LOG — fsync-durable, single-node WAL at O(1)-on-total-volume RAM

> Goal (owner, 2026-06-24): a durable substrate that is **fsync-durable (survives power-loss, like Kafka
> acks=all), adds ~0 extra memory (RAM flat regardless of stored/in-flight volume), is seamless (drop-in
> `Substrate`), warp-speed under load, and ultra-light.** This is the engineering that turns the adversarial
> audit's "datarail is lean but doesn't really persist" into "datarail persists durably AND stays ~40-90× leaner
> than Kafka — measured, same work, same ruler."

## The core idea — why durability need not cost RAM

Kafka couples durability to RAM: it keeps the hot working set in the OS **page cache** (its deliberate
"let-the-page-cache-be-the-memory" design) + a multi-GB JVM heap. Its RSS grows with retention/throughput.

A write-ahead log does NOT need that. Durability = *bytes safely on stable storage*, which is achieved by
**sequential append + fsync** — an operation whose RAM cost is a single fixed write buffer. Reading back is a
sequential scan with a single fixed read buffer. The OS page cache may hold recent pages, but that is
**reclaimable kernel memory, not the process's RSS** — it costs us nothing and the kernel evicts it under
pressure. So: **durability on disk (abundant) + RAM = two fixed buffers + O(1) cursors (≈ constant).**

## Architecture (`datarail-substrate-wal`, a new crate implementing `Substrate`)

```
<dir>/
  000000000001.seg   ┐ append-only segment files, sealed cofres framed sequentially,
  000000000002.seg   ┘ rotated at SEGMENT_BYTES; GC'd once fully acked.
  cursor             ← tiny checkpoint: (read_seg, read_off, ack_seg, ack_off), fsync'd atomically (write-tmp+rename)
```

**On-disk frame** (per cofre): `[u32 len][cofre wire bytes][u32 crc32(len‖bytes)]`.
- `len` ≤ `MAX_COFRE_WIRE_LEN` (parse-safety, rejects a corrupt/hostile length).
- CRC detects a **torn write** (power-loss mid-append) on recovery → the partial tail is truncated.

### Write path — group-commit fsync (the warp-speed durability lever)
`send(cofre)` appends `frame(cofre)` into a **fixed-capacity write buffer** (reused, never grows). It does NOT
fsync per message. A flush is triggered by EITHER a byte threshold (buffer ≥ `FLUSH_BYTES`, e.g. 1 MiB) OR a
time window (`FLUSH_MICROS`, e.g. 1000 µs) — whichever first. `flush()`:
1. `write_all(buf)` to the active segment (one `write(2)`),
2. **`file.sync_all()`** ← the durability point (an fsync; on Linux+barriers this is on stable storage — see the durability boundary below),
3. advance the durable write offset; **clear (not free) the buffer**,
4. rotate to a new segment (its dir-entry fsync'd) if over `SEGMENT_BYTES`.

**One fsync amortized over a whole batch of cofres** = group-commit durability at high throughput (as databases and Kafka's own log do). At the SUBSTRATE layer the cofre is durable after step 2. **End-to-end through the OMB shim, however, the producer is acked earlier — at the ingress→worker handoff (acks=1), before the seal+fsync** — so the strong end-to-end guarantee is acks=1; the WAL provides acks=all-grade durability at the substrate, not (yet) end-to-end.

### Read path — O(1) sequential cursor, no id-set
`recv()` reads the next frame at `read_off` from disk (`read_exact` into a reused read buffer), verifies the
CRC, decodes, advances `read_off` in RAM, returns the cofre. **Exactly-once is the cursor, not a `HashSet`:** a
record is deliverable iff its offset ≥ the committed read cursor; the cursor only advances. There is **no
in-RAM index of delivered ids** (that was the demo objectstore's unbounded `HashSet`/`Vec` flaw the audit
flagged) — the offset *is* the dedup state. O(1).

### ack / GC — bounded disk, bounded RAM
`ack(cofre_id)` advances the **ack watermark** offset. When the watermark passes a segment's end, that segment
file is **deleted** (GC). Disk is bounded by the un-acked retention window; RAM is unaffected. The cursor
checkpoint (`read`/`ack` offsets) is fsync'd via write-tmp+rename periodically and on close.

### Crash recovery (fsync durability contract)
On `open()`: read the `cursor` checkpoint (read/ack offsets). Scan the active segment **forward from the last
checkpoint**, validating each frame's CRC; set the durable write offset to the end of the last **intact** frame
and **truncate** any torn tail (a frame whose write was interrupted by power-loss). Result: every cofre whose
`flush()` returned (fsync'd) is recovered on a filesystem honoring fsync ordering; a half-written tail is dropped (it
was never acked). This is **at-least-once at the substrate** (a crash between downstream-commit and cursor-checkpoint
may re-deliver a few cofres) → composed with the terminal's effectively-once gate = **effectively-once end-to-end**,
exactly as the existing resumable-socket path already proves. Physical power-loss evidence remains environment-specific.

## The RAM invariant (the masterpiece guarantee — must be TESTED, not asserted)
Process RSS attributable to the substrate = `write_buf cap + read_buf cap + ~3 file handles + fixed cursor
struct` ≈ **a couple of MiB, FLAT** — independent of (a) total bytes stored and (b) number of cofres. Storing 1 TB across 10^9 cofres uses the **same** RAM as storing 1 MB. **HONEST CAVEAT (durability audit):** the ack-side bookkeeping (`inflight`/`seg_inflight` maps, for ack-by-id → GC) is **O(in-flight, delivered-but-un-acked window)** — NOT O(1) and NOT O(total). It is bounded by consumer lag (small for a draining consumer) and is RECLAIMED on ack. **Verification (gates):** `ram_flat_across_full_send_recv_ack_cycle` (total-volume independence over the FULL cycle, not just send) + `unacked_backlog_ram_is_bounded_by_inflight_and_reclaimed_on_ack` (the honest O(in-flight) cost). The earlier send-only gate was rigged and is replaced.

## Performance levers (warp speed under load)
1. **Group-commit fsync** — amortize the ~ms fsync over a batch ⇒ throughput is bounded by sequential write
   bandwidth, not fsync latency.
2. **Directory fsync** on segment create/rotate and after the cursor rename — so a create/rename is crash-safe (without it, power-loss can lose a fsync'd segment's dir-entry). (Pre-allocation via `fallocate` is a possible future nicety; not currently implemented.)
3. **Zero per-message allocation** — reused write/read buffers; frame in place.
4. **Hot-path RNG fix (separate, but multiplies this):** `random_32` currently `open("/dev/urandom")` **2× per
   cofre**, which *serializes across threads* on the kernel entropy path (audit Agent 4). Replace with a
   **thread-local CSPRNG** (ChaCha20, seeded once from OS entropy — cryptographically equivalent, what
   `rand::thread_rng` does) ⇒ removes 2 syscalls/cofre and the cross-thread serialization. This is the single
   biggest "performance under load" win the audit surfaced; it is sound because the per-cofre data key + nonce
   only need a CSPRNG, not a fresh kernel read each time.

## Honesty boundaries (carry into the eventual claim)
- This implements **fsync durability** for a single node; the Docker device-mapper cut harness exercises abrupt I/O
  loss, but does not prove physical power-loss ordering. **Replication (RF≥3, node-loss safe)** is a
  separate axis — provided by pointing the segment dir at a replicated store (S3/GCS/CoreLink) or a future
  replicated-WAL mode. We will claim "fsync-durable, single-node" precisely, not "Kafka RF=3" unless measured.
- The fair comparison is **datarail-WAL-durable vs Kafka-acks=all**, both measured with the **same ruler** (both
  containerized, cgroup `memory.current` *including* page cache, peak+avg, post-warm-up). Only then does a
  "durable AND ~Nx leaner" number get claimed.

## Durability boundary (honest — durability audit 2026-06-24)
- Uses std `File::sync_all` (fsync). On **Linux + ext4/xfs with write barriers** this is true power-loss
  durability. On **macOS** std fsync does NOT flush the drive write-cache (that needs `F_FULLFSYNC`, unavailable
  in safe std) — so the dev laptop is NOT a power-loss-durability environment. On a **no-barrier container FS**
  (overlayfs/tmpfs) fsync may not survive host power-loss either. Claim precisely: "fsync-durable on
  Linux/ext4+barriers", not "power-loss-safe everywhere".
- **Single-node only.** No replication (RF=1). Survives a *process* crash and (on a barrier'd FS) a *power*
  loss, but NOT disk/node loss. "Kafka-grade" in the RF≥3 sense is NOT claimed.
- Recovery scans the active segment for a torn tail (truncates it); a CRC failure inside a SEALED segment is a
  hard error (not silently skipped). A lost cursor + GC is survived by recv's skip-forward over missing segments.
- `scripts/durability-device-mapper.sh` is the reproducible cut-I/O probe. Set `DATARAIL_DURABILITY_FAULT_MODE=flakey`
  on a Linux runner to require `dm-flakey`, ext4/xfs, and write barriers; `.github/workflows/durability-linux.yml`
  runs that mode manually. `reordered_cursor_rename_plus_gc...` and
  `missing_cursor_entry...` model stale/lost directory-entry visibility; directory-fsync failures fail closed without
  consuming the ack. Final `DUR-01` physical power-loss closure still needs a filesystem/backend that injects
  fsync/rename reordering and directory-entry loss.
