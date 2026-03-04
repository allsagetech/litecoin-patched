#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

import contextlib
import io
import os
import pathlib
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from contrib.devtools import drivechain_production_gate as gate


def write_file(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def render_signoff(
    reviewer: str = "External Security Co",
    scope: str = "Consensus, activation behavior, authz boundaries, and release pipeline",
    report_link: str = "https://example.com/reports/drivechain-final.pdf",
    review_date: str = "2026-03-04",
    unresolved_high_critical: str = "NO",
    program_url: str = "SECURITY.md",
    in_scope_components: str = "Consensus logic, RPC surface, release pipeline",
    disclosure_sla: str = "Initial triage within 3 business days",
    effective_date: str = "2026-03-04",
    release_candidate_tag: str = "v0.1.0-rc1",
    approved_by: str = "Release Council",
    approval_date: str = "2026-03-05",
    approval_status: str = "APPROVED",
) -> str:
    return textwrap.dedent(
        f"""\
        # Drivechain External Security Sign-Off

        ## 1. Independent Review

        - Reviewer/firm: `{reviewer}`
        - Scope: `{scope}`
        - Report link: `{report_link}`
        - Date: `{review_date}`
        - Unresolved High/Critical findings: `{unresolved_high_critical}`

        ## 2. Bug Bounty / Security Program

        - Program URL: `{program_url}`
        - In-scope components: `{in_scope_components}`
        - Disclosure SLA: `{disclosure_sla}`
        - Effective date: `{effective_date}`

        ## 3. Release Sign-Off

        - Release candidate tag: `{release_candidate_tag}`
        - Approved by: `{approved_by}`
        - Approval date: `{approval_date}`
        - Approval status: `{approval_status}`
        - Notes: `Release approved by independent review`
        """
    )


def build_minimal_repo(root: pathlib.Path, signoff: str) -> None:
    write_file(
        root / "doc/drivechain/LIP-drivechain.md",
        textwrap.dedent(
            """\
            # LIP Drivechain
            Status: Final

            | Tag | Name |
            | 0x04 | VOTE_NO |
            | 0x05 | REGISTER |
            """
        ),
    )
    for doc in (
        "OPERATIONS.md",
        "SECURITY_REVIEW_CHECKLIST.md",
        "PRODUCTION_READINESS.md",
        "INCIDENT_RESPONSE_RUNBOOK.md",
        "STAGED_ROLLOUT_PLAN.md",
    ):
        write_file(root / f"doc/drivechain/{doc}", "# placeholder\n")
    write_file(root / "doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md", signoff)

    write_file(
        root / ".github/workflows/build-release.yaml",
        textwrap.dedent(
            """\
            jobs:
              drivechain-production-gates: {}
              release:
                steps:
                  - run: |
                      run_one drivechain_softfork_activation_boundary.py
                      run_one drivechain_softfork_reorg_deactivation.py
                      run_one drivechain_reorg_state_rollback.py
                      run_one drivechain_reorg_snapshot_fallback.py
                      run_one drivechain_register_mempool_conflict.py
                      run_one drivechain_register_confirmation_required.py
                      echo SHA256SUMS
                      echo SBOM.spdx.json
                      echo generate_spdx_sbom.py
            """
        ),
    )

    write_file(
        root / ".cirrus.yml",
        textwrap.dedent(
            """\
            sanitizers: thread
            sanitizers: memory
            sanitizers: address/leak
            sanitizers: fuzzer,address,undefined
            """
        ),
    )

    write_file(root / "src/test/fuzz/drivechain_script.cpp", "// placeholder\n")
    write_file(root / "src/test/drivechain_script_tests.cpp", "// placeholder\n")
    write_file(root / "contrib/devtools/generate_spdx_sbom.py", "# placeholder\n")


class DrivechainProductionGateTest(unittest.TestCase):
    def run_gate(self, root: pathlib.Path) -> tuple[int, str]:
        previous_root = gate.REPO_ROOT
        previous_enforce = os.environ.get("DRIVECHAIN_ENFORCE_EXTERNAL_SIGNOFF")
        try:
            gate.REPO_ROOT = root
            os.environ["DRIVECHAIN_ENFORCE_EXTERNAL_SIGNOFF"] = "1"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = gate.main()
            return result, stdout.getvalue()
        finally:
            gate.REPO_ROOT = previous_root
            if previous_enforce is None:
                os.environ.pop("DRIVECHAIN_ENFORCE_EXTERNAL_SIGNOFF", None)
            else:
                os.environ["DRIVECHAIN_ENFORCE_EXTERNAL_SIGNOFF"] = previous_enforce

    def test_is_pending_detects_disallowed_placeholders(self) -> None:
        for value in ("PENDING", "pending (YYYY-MM-DD)", "NOT APPROVED", "TBD", "N/A", "todo"):
            with self.subTest(value=value):
                self.assertTrue(gate._is_pending(value))

    def test_is_pending_ignores_substring_matches(self) -> None:
        self.assertFalse(gate._is_pending("https://example.com/reports/depending-on-chain-state.pdf"))

    def test_extract_signoff_values_supports_duplicates_and_backticks(self) -> None:
        signoff = textwrap.dedent(
            """\
            - Reviewer/firm: `Firm A`
            - Reviewer/firm: `Firm B`
            """
        )
        self.assertEqual(gate._extract_signoff_values(signoff, "Reviewer/firm"), ["Firm A", "Firm B"])

    def test_main_passes_with_complete_signoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            build_minimal_repo(root, render_signoff())
            code, output = self.run_gate(root)
        self.assertEqual(code, 0, output)
        self.assertIn("Drivechain production gate check PASSED", output)

    def test_main_rejects_duplicate_field_and_bad_dates(self) -> None:
        signoff = render_signoff(review_date="2026-13-04", approval_date="2026/03/05")
        signoff += "- Reviewer/firm: `Duplicate Reviewer`\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            build_minimal_repo(root, signoff)
            code, output = self.run_gate(root)
        self.assertEqual(code, 1)
        self.assertIn("field 'Reviewer/firm' appears multiple times", output)
        self.assertIn("field 'Date' must use YYYY-MM-DD format", output)
        self.assertIn("field 'Approval date' must use YYYY-MM-DD format", output)

    def test_main_rejects_explicit_placeholder_values(self) -> None:
        signoff = render_signoff(report_link="TBD", approved_by="NOT APPROVED (security sign-off pending)")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            build_minimal_repo(root, signoff)
            code, output = self.run_gate(root)
        self.assertEqual(code, 1)
        self.assertIn("field 'Report link' is still pending", output)
        self.assertIn("field 'Approved by' is still pending", output)


if __name__ == "__main__":
    unittest.main()
