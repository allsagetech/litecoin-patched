# Legacy Drivechain External Security Sign-Off

Use this file as the manual release gate for external review and sign-off
criteria for the legacy Drivechain implementation.
All `PENDING` values below must be completed before a release tag push.

Validation rules enforced by `contrib/devtools/drivechain_production_gate.py`:
- Fields listed below must exist exactly once.
- Placeholder values are rejected (`PENDING`, `NOT APPROVED`, `TBD`, `TODO`, `N/A`, `UNKNOWN`, `NONE`).
- `Date`, `Effective date`, and `Approval date` must use `YYYY-MM-DD`.
- `Approval status` must be `APPROVED`.
- `Unresolved High/Critical findings` must be `NO`.
- Status values may be written as bare text or wrapped in markdown backticks.

## 1. Independent Review

- Reviewer/firm: `PENDING`
- Scope: `PENDING (must include consensus safety, activation behavior, state machine paths, authz boundaries, reorg/restart/persistence, mempool/consensus alignment, and release pipeline safety)`
- Report link: `PENDING`
- Date: `PENDING (YYYY-MM-DD)`
- Unresolved High/Critical findings: `YES`

## 2. Bug Bounty / Security Program

- Program URL: `SECURITY.md`
- In-scope components: `Drivechain consensus logic, RPC surface, wallet drivechain RPCs, release pipeline`
- Disclosure SLA: `Security reports acknowledged within 3 business days`
- Effective date: `2026-03-04`

## 3. Release Sign-Off

- Release candidate tag: `PENDING`
- Approved by: `PENDING`
- Approval date: `PENDING (YYYY-MM-DD)`
- Approval status: `PENDING`
- Notes: `Mainnet release is blocked until this file is updated to Approval status: APPROVED and unresolved High/Critical findings are NO.`
