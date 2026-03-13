# Validity Sidechain ZK Demo

This directory contains a separate toy zk prototype.

It exists to generate real Groth16 artifacts for a minimal demo circuit with
validity-sidechain-shaped public inputs.

It does not make the node trustless.

What it is:

- a standalone Go module
- a toy Groth16 prover/verifier flow using `gnark`
- a generator for demo artifacts and proof vectors

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
```
