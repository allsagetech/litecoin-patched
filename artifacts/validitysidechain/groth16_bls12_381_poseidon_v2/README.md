Committed artifact bundle for the decomposed-input Poseidon Groth16 profile.

This bundle keeps the current experimental transition semantics, but it now
proves a bounded in-circuit queue-prefix and withdrawal witness relation for up
to two consumed queue entries and two withdrawal leaves.

It also keeps the 128-bit public-input limb layout for the queue, withdrawal,
and DA roots so those values no longer need to fit a single BLS12-381 scalar.

The proving key for this circuit is not kept in-tree; regenerate it locally
when auto-prover coverage is needed.
