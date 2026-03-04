#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

import pathlib
import os
import re
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def must_exist(path: str, errors: list[str]) -> None:
    full = REPO_ROOT / path
    if not full.exists():
        errors.append(f"Missing required file: {path}")


def require_contains(path: str, token: str, errors: list[str]) -> None:
    full = REPO_ROOT / path
    if not full.exists():
        errors.append(f"Missing required file: {path}")
        return
    content = full.read_text(encoding="utf-8")
    if token not in content:
        errors.append(f"{path} missing token: {token}")


def main() -> int:
    errors: list[str] = []

    required_docs = [
        "doc/drivechain/LIP-drivechain.md",
        "doc/drivechain/OPERATIONS.md",
        "doc/drivechain/SECURITY_REVIEW_CHECKLIST.md",
        "doc/drivechain/PRODUCTION_READINESS.md",
        "doc/drivechain/INCIDENT_RESPONSE_RUNBOOK.md",
        "doc/drivechain/STAGED_ROLLOUT_PLAN.md",
        "doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md",
    ]
    for path in required_docs:
        must_exist(path, errors)

    enforce_external_signoff = os.getenv("DRIVECHAIN_ENFORCE_EXTERNAL_SIGNOFF", "0") == "1"
    signoff_path = REPO_ROOT / "doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md"
    if enforce_external_signoff:
        if not signoff_path.exists():
            errors.append("External security sign-off file is required for release gating")
        else:
            signoff = signoff_path.read_text(encoding="utf-8")
            if not re.search(r"^- Approval status:\s*APPROVED\s*$", signoff, flags=re.MULTILINE):
                errors.append("External security sign-off is not approved (expected '- Approval status: APPROVED')")
            if not re.search(r"^- Unresolved High/Critical findings:\s*NO\s*$", signoff, flags=re.MULTILINE):
                errors.append("External security sign-off still has unresolved High/Critical findings")

    lip_path = REPO_ROOT / "doc/drivechain/LIP-drivechain.md"
    if lip_path.exists():
        lip = lip_path.read_text(encoding="utf-8")
        if not re.search(r"^Status:\s*Final\s*$", lip, flags=re.MULTILINE):
            errors.append("LIP-drivechain.md must have 'Status: Final'")
        for required_line in ("| 0x04 | VOTE_NO |", "| 0x05 | REGISTER |"):
            if required_line not in lip:
                errors.append(f"LIP-drivechain.md missing tag mapping: {required_line}")

    workflow = " .github/workflows/build-release.yaml".strip()
    critical_tests = [
        "run_one drivechain_softfork_activation_boundary.py",
        "run_one drivechain_softfork_reorg_deactivation.py",
        "run_one drivechain_reorg_state_rollback.py",
        "run_one drivechain_reorg_snapshot_fallback.py",
        "run_one drivechain_register_mempool_conflict.py",
        "run_one drivechain_register_confirmation_required.py",
    ]
    for token in critical_tests:
        require_contains(workflow, token, errors)

    release_integrity_tokens = [
        "drivechain-production-gates",
        "SHA256SUMS",
        "SBOM.spdx.json",
        "generate_spdx_sbom.py",
    ]
    for token in release_integrity_tokens:
        require_contains(workflow, token, errors)

    cirrus_tokens = [
        "sanitizers: thread",
        "sanitizers: memory",
        "sanitizers: address/leak",
        "sanitizers: fuzzer,address,undefined",
    ]
    for token in cirrus_tokens:
        require_contains(".cirrus.yml", token, errors)

    must_exist("src/test/fuzz/drivechain_script.cpp", errors)
    must_exist("src/test/drivechain_script_tests.cpp", errors)
    must_exist("contrib/devtools/generate_spdx_sbom.py", errors)

    if errors:
        print("Drivechain production gate check FAILED:")
        for item in errors:
            print(f" - {item}")
        return 1

    print("Drivechain production gate check PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
