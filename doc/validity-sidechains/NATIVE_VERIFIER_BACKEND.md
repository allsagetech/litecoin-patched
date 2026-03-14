# Native Verifier Backend Selection

This file records the selected native pairing backend for the intended
trustless validity-sidechain verifier path.

## Selected Backend

- library: `blst`
- upstream: `https://github.com/supranational/blst`
- pinned upstream commit: `dafa98f749869f7ab63ab31074626b7dfc70b5b3`
- vendored source location: `external/blst/`

## Why This Backend

`blst` is the best fit for this repo's trustless target because it is:

- native C with C++ bindings, which matches the node's consensus implementation
- focused specifically on BLS12-381 field, curve, and pairing operations
- small enough to vendor and audit as a consensus dependency
- suitable as the low-level backend for an in-process Groth16 verifier

It does not provide a ready-made validity-sidechain verifier on its own. It is
the pairing/curve backend, not the full circuit-specific Groth16 integration.

## What This Does Not Solve

Vendoring `blst` does not by itself complete trustlessness. The following still
remain:

- the real `groth16_bls12_381_poseidon_v1` verifier implementation in
  `src/validitysidechain/verifier.*`
- real verifier-key parsing and proof parsing for the final profile
- the real batch circuit and proving assets
- the final public-input binding and queue-prefix semantics from
  `PROPOSED_ZK_SYSTEM.md`
- replacement of scaffold withdrawal and escape-exit semantics with final
  proof-backed semantics

## Intended Next Steps

1. Add a thin internal `blst` wrapper layer under `src/validitysidechain/`
   for BLS12-381 point, scalar, and pairing operations actually needed by
   Groth16 verification.
2. Define the on-disk verifying-key format for
   `groth16_bls12_381_poseidon_v1/batch_vk.bin`.
3. Implement native proof and verifying-key decoding.
4. Implement the fixed Groth16 verification equation over `blst`.
5. Replace the current `planned_native_groth16` hard-fail path with the real
   in-process verifier.

Until those steps land with real assets, the branch remains non-trustless.
