This bundle contains real Groth16 proving and verifying material for the
experimental toy batch-transition circuit used by the external
`gnark_groth16_toy_batch_transition_v1` profile.

It is not the planned native Poseidon/state-transition verifier, and it does
not by itself make the branch trustless. The circuit proves only the toy
arithmetic relation exercised by the helper commands in
`contrib/validitysidechain-zk-demo`.

The node can consume this bundle when started with:

- `-validityartifactsdir=<repo>/artifacts`
- `-validityverifiercommand=<cmd>`
- `-validityprovercommand=<cmd>` for wallet auto-proof generation
