# Placeholder Artifact Bundle

This directory exists so the expected artifact layout is present in-tree.

It is not a real Groth16 verifier bundle.

Current contents are placeholders only:

- `profile.json` fixes the intended consensus tuple and public-input shape
- `batch_vk.bin` is a sentinel placeholder, not a real verifying key
- `valid/` and `invalid/` contain vector schemas and placeholder cases

Trustlessness is still blocked until this directory is replaced with:

- a real trusted-setup / verifier-key output
- real valid and invalid proof vectors produced by the matching prover
- a real Groth16 verifier backend in `src/validitysidechain/verifier.cpp`
