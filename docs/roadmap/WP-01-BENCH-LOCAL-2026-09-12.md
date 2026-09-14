# WP-01 Local A/B Evidence — 2026-09-12

**Status:** directional local evidence only; not independent benchmark evidence.

**Command:**

```text
cargo test --release -p datarail-cli --test kafka_per_partition_scaling per_partition_scaling_interleaved_benchmark -- --ignored --nocapture
cargo test --release -p datarail-cli --no-default-features --test kafka_per_partition_scaling per_partition_scaling_interleaved_benchmark -- --ignored --nocapture
```

**Workload:** real `datarail kafka-broker` child process; 512-byte records; 200 records for serial one-partition
case; 400 records for parallel two-partition case; two serial and two parallel runs interleaved inside each build.

| Build | Serial mean | Parallel mean | Ratio |
|---|---:|---:|---:|
| Default `per_partition_locking` | 414 records/s | 696 records/s | **1.684x** |
| `--no-default-features` rollback | 572 records/s | 508 records/s | **0.888x** |

The default build cleared the local 1.5x directional target once. The rollback build showed negative scaling. Sample is
small, host conditions are uncontrolled, and no RSS/CI data was collected. Do not copy these numbers into
`BENCH-INDEPENDENT-2026-07-01.md` or product claims.

## Second Run With Batch p99

The harness then gained per-produce-batch latency capture. A second serial run produced these raw observations:

| Build | Serial records/s | Serial p99 ms | Parallel records/s | Parallel p99 ms | Ratio |
|---|---:|---:|---:|---:|---:|
| Default locking, run 2 | 215, 245 | 296.969, 140.799 | 246, 283 | 285.275, 326.846 | **1.154x** |
| Rollback, run 2 | 201, 245 | 383.333, 138.417 | 272, 283 | 270.329, 211.620 | **1.245x** |

p99 is per produce batch, pooled across workers for parallel cases. Variance confirms this harness is diagnostic, not
acceptance-grade: no 95% CI, RSS sample, or independent product claim follows from these runs.

## Contention Stress

`ten_thousand_concurrent_partition_operations_complete` completed 10,000 operations with concurrent produce, fetch,
and reverse-order transaction commits in both builds: default `184.65s`; rollback `191.40s`. This proves completion
under this workload, not absence of all deadlocks or crash atomicity.
