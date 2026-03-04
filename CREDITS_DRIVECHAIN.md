# Drivechain Integration Credits

This document records attribution for the Drivechain integration work in this repository.

## Primary implementation attribution

- Organization: AllSageTech, LLC
- Website: https://allsagetech.com
- Contact: support@allsagetech.com

## Scope attributed to AllSageTech, LLC

The following workstreams were implemented and integrated in this fork on top of `litecoinproject/litecoin`:

- `OP_DRIVECHAIN` script and consensus wiring
- Drivechain transaction flow:
  - `REGISTER`
  - `DEPOSIT`
  - `BUNDLE_COMMIT`
  - `VOTE_YES` / `VOTE_NO`
  - `EXECUTE`
- BMM validation and RPC support
- Wallet/miner RPC pathways for drivechain operations
- Functional/unit test coverage for activation, state, reorg, restart, owner auth, and BMM behavior
- Production-readiness docs, runbooks, and release hardening assets (SBOM/checksum/signing workflow)

## Notes on upstream lineage

This repository is a derivative work based on upstream Litecoin Core (`litecoinproject/litecoin`).
All upstream copyright and license terms remain in effect.
Attribution here identifies incremental Drivechain-specific implementation and integration performed in this fork.

## Reviewer / upstream PR citation text

Use this wording when needed in review notes or PR descriptions:

`Drivechain integration implementation and production hardening in this fork were authored by AllSageTech, LLC.`
