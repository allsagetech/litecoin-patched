# Validity Sidechain ZK Demo

This directory contains a separate toy zk prototype.

It exists to generate real Groth16 artifacts for a minimal demo circuit with
validity-sidechain-shaped public inputs.

It does not make the node trustless.

What it is:

- a standalone Go module
- a toy Groth16 prover/verifier flow using `gnark`
- a generator for demo artifacts and proof vectors
- helper commands for external proving and verification

What it is not:

- the Litecoin consensus verifier backend
- the real validity-sidechain circuit
- a substitute for the real `batch_vk.bin` and proof vectors needed by
  `src/validitysidechain/verifier.cpp`

Generated outputs land under `generated/toy_batch_transition_bls12_381_v1/`.

To regenerate:

```powershell
cd contrib/validitysidechain-zk-demo
go run ./cmd/generate-demo | python materialize_bundle.py
go run ./cmd/export-native-bundle | python materialize_bundle.py
go run ./cmd/generate-real-bundle | python materialize_bundle.py
go run ./cmd/generate-real-bundle -profile groth16_bls12_381_poseidon_v2 | python materialize_bundle.py
```

Helper commands:

```powershell
go run ./cmd/prove-batch
go run ./cmd/verify-batch
go run ./cmd/derive-batch
```

These commands read a single JSON request from stdin and emit a single JSON
response on stdout for the experimental external-profile integration in
`src/validitysidechain/verifier.cpp`. `derive-batch` returns the same
profile-derived public inputs the prover path uses for test and tooling
workflows.

For the real Poseidon profiles, the request contract now also carries the
node's current chainstate roots and the canonical withdrawal-witness policy.
For `groth16_bls12_381_poseidon_v2`, `derive-batch` and `prove-batch` now
require those current roots plus explicit `consumed_queue_entries`,
`withdrawal_leaves`, and `data_chunks_hex` vectors, and `derive-batch` now
derives `l1_message_root_after`, `queue_prefix_commitment`, `withdrawal_root`,
`data_root`, and `data_size` from that witness surface instead of trusting
caller-supplied values.

The native bundle encoder and C++ verifier now carry Groth16 commitment
metadata. The shipped successor profile `groth16_bls12_381_poseidon_v3` uses
that path for an explicitly bounded contract: up to two consumed queue
entries, up to two withdrawal leaves, and up to two published data chunks are
bound in-circuit, with any non-final DA chunk fixed at 64 bytes so the bounded
witness layout still hashes to the real published `data_root`. The node now
treats `v3` as the recommended profile for new registrations while leaving
canonical `v2` in place until the successor contract is generalized, and the
`v3` helper request is now current-chainstate-bound like `v2`.

`verify-batch` now supports both the toy external profile and the experimental
native real bundles `groth16_bls12_381_poseidon_v1` and
`groth16_bls12_381_poseidon_v2`, plus the bounded commitment-aware successor
profile `groth16_bls12_381_poseidon_v3`.

For the functional test harness, use the wrapper script:

```powershell
python run_tool.py prove
python run_tool.py verify
python run_tool.py derive
```

The wrapper fixes the working directory and forwards stdin/stdout so the node
can invoke the helper commands through `-validityprovercommand` and
`-validityverifiercommand`.

The native toy artifact exporter converts the gnark-generated toy proof and
verifying key into the node's native Groth16 encoding under:

- `artifacts/validitysidechain/native_blst_groth16_toy_batch_transition_v1/`
