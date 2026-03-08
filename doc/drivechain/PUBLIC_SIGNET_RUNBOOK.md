# Drivechain Public Signet Runbook

This document separates the in-repo signet deliverables from the external
operator work required to run a public drivechain burn-in network.

## 1. In-Repo Deliverables

- Drivechain is active on signet builds from first block, so signet burn-in does
  not depend on mining to a distant activation height.
- Functional coverage includes:
  - basic signet behavior (`feature_signet.py`)
  - drivechain-on-signet smoke coverage (`feature_drivechain_signet.py`)
- CI runs both signet tests before the broader drivechain suite.

## 2. External Public Signet Prerequisites

These items are required for a real public signet launch and cannot be completed
solely by changing this repository:

- A published signet challenge and launch announcement.
- Canonical bootstrap instructions for fresh nodes.
- At least one maintained seed path for peer discovery:
  - baked-in seed list in release builds, or
  - published `-signetseednode=` endpoints operated by the launch team.
- Independent miners able to produce and relay signet blocks for the chosen
  challenge.
- Monitoring for:
  - block production stalls,
  - peer discovery health,
  - drivechain bundle approval/execution progress,
  - wallet/RPC error rates.

## 3. Burn-In Checklist

- Launch at least two independent seed operators.
- Launch at least two independent miners.
- Publish the exact node configuration used by operators:
  - `-signetchallenge=<hex>`
  - any required `-signetseednode=<host[:port]>`
- Confirm the following on the public network:
  - sidechain registration,
  - escrow funding,
  - bundle commit,
  - vote accumulation,
  - execute after approval/finalization,
  - restart and reorg handling.

## 4. Evidence To Archive

- Signet challenge and launch date.
- Seed endpoints and operator owners.
- Miner/operator roster.
- Representative txids and block hashes for register/deposit/commit/execute.
- Any incidents, mitigations, and unresolved follow-up items.

## 5. Production Readiness Boundary

Repository work is only one part of public signet readiness. Production release
remains blocked until:

- burn-in evidence exists,
- external security review is signed off, and
- release approval is recorded in
  `doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md`.
