# WP-01 Rollback

## Build Modes

Normal build enables per-partition locking:

```sh
cargo build --release -p datarail-cli
```

Rollback build disables the feature and wraps the same store behind one global mutex:

```sh
cargo build --release -p datarail-cli --no-default-features
```

The two modes use the same wire and storage contracts. The rollback mode is for comparison and emergency
reproduction; it does not remove already-written data or change logical offsets.

## Verification

Run both build modes before switching a deployment:

```sh
cargo test --release -p datarail-cli --no-default-features
cargo test --release -p datarail-cli
cargo clippy --workspace --all-targets -- -D warnings
```

The live broker must be stopped before replacing its binary. Keep its data directory unchanged. Start replacement
binary against the same `--data-dir`, then verify `ListOffsets` and fetch for every affected partition.

## Checkpoints

Create a named checkpoint only after its scoped tests pass:

```sh
git tag wp1-t<task>-checkpoint
```

Do not create or move tags after publishing. Inspect `git show --stat <tag>` and `git diff --name-only <tag>..HEAD`
before using a checkpoint.

## Revert

Preferred shared-branch rollback: revert the commits after a known-good checkpoint, preserving history:

```sh
git revert <checkpoint>..HEAD
```

Disposable worktree only: reset to checkpoint after confirming no work must be preserved:

```sh
git reset --hard wp1-t<task>-checkpoint
```

After rollback, rerun build-mode verification and the real Kafka wire smoke tests. Record checkpoint, binary mode,
data directory, test command, and result in `WP-01-STATE.md`.
