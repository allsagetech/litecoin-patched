Committed artifact bundle for the decomposed-input Poseidon Groth16 profile.

This bundle keeps the current experimental host-validated queue and withdrawal
fixtures, but it upgrades the public-input layout to 128-bit limbs for the
queue, withdrawal, and DA roots so those values no longer need to fit a single
BLS12-381 scalar.
