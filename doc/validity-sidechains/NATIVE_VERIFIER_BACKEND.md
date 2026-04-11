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

## What This Does Now

- vendors `blst` directly in-tree under `external/blst/`
- compiles a portable native `blst` static library into the node build
- exposes a validity-sidechain backend smoke test that checks generator
  validation, serialization, pairing context sizing, and a non-trivial pairing
  result
- adds a native parser layer for the proposed Groth16 proof blob and verifying
  key blob formats, with `blst`-validated G1/G2 compressed point checks
- adds the in-process Groth16 pairing equation over that parsed proof /
  verifying-key format, with synthetic algebraic unit coverage
- currently interprets each batch public input as one BLS12-381 scalar field
  element, which means the final real profile must keep those values
  field-sized or move to a decomposed-input profile version

## What This Does Not Solve

Vendoring `blst` does not by itself complete trustlessness. The following still
remain:

- the real batch circuit and proving assets
- the final public-input binding and queue-prefix semantics from
  `PROPOSED_ZK_SYSTEM.md`
- replacement of scaffold withdrawal and escape-exit semantics with final
  proof-backed semantics

## Intended Next Steps

1. Finalize the canonical `groth16_bls12_381_poseidon_v2` artifact bundle with
   the intended end-state `batch_vk.bin` and production-semantics proof
   vectors. Treat `v1` as scalar-limited migration coverage only.
2. Wire the final circuit/public-input semantics to the canonical `v2` assets.
3. Replace the remaining scaffold state-transition and exit semantics with the
   final proof-backed path.

Until those steps land with real assets, the branch remains non-trustless.
