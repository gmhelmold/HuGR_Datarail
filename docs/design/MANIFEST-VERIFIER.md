# Standalone Manifest Verifier

`datarail-manifest` exposes offline delivery-receipt verification without importing CLI code.

## Public surface

- `DeliveryReceipt`: typed receipt bundle containing payload bytes, route/stream/sequence/epoch, inclusion proof,
  signed tree head, and pinned source/destination verifying keys.
- `verify_receipt`: verifies payload content address, STH signature, proof metadata and Merkle path, ack signature,
  ack position, and ack root binding.
- `InclusionProof`, `SignedTreeHead`, `DestAck`: receipt evidence types.
- `leaf_hash`, `root_from_path`, `verify_inclusion`, `verify_sth`, and `verify_ack`: composable checks.

`DeliveryProof` and `verify_delivery` remain aliases/entry points for existing callers. New consumers should use
the receipt names.

## Verification

Consumer pins source and destination Ed25519 verifying keys, receives the payload plus receipt evidence, then calls:

```rust
use datarail_manifest::{verify_receipt, DeliveryReceipt};

verify_receipt(&DeliveryReceipt {
    carga: payload,
    route_id: &route_id,
    stream_id: &stream_id,
    seq,
    epoch,
    proof: &inclusion,
    sth: &sth,
    source_vk: &source_vk,
    ack: &ack,
    dest_vk: &dest_vk,
})?;
```

No serialization or network protocol is defined here. Callers may serialize these fixed-layout fields in their own
transport, then reconstruct the typed values before verification.
