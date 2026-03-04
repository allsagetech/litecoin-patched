#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import uuid


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a minimal SPDX 2.3 JSON SBOM for release artifacts."
    )
    parser.add_argument("--input-dir", required=True, help="Artifact directory to inventory")
    parser.add_argument("--output", required=True, help="Output SPDX JSON path")
    parser.add_argument("--package-name", required=True, help="SPDX package name")
    parser.add_argument("--package-version", required=True, help="SPDX package version")
    return parser.parse_args()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def spdx_id(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in value)
    return "SPDXRef-" + cleaned.strip("-")


def file_type_for(path: pathlib.Path) -> str:
    text_suffixes = {".txt", ".md", ".json", ".asc", ".sha256"}
    return "TEXT" if path.suffix.lower() in text_suffixes else "BINARY"


def main() -> int:
    args = parse_args()

    input_dir = pathlib.Path(args.input_dir).resolve()
    output_path = pathlib.Path(args.output).resolve()

    files = sorted(p for p in input_dir.rglob("*") if p.is_file())
    if not files:
        raise RuntimeError(f"No files found under {input_dir}")

    package_id = spdx_id(args.package_name)
    created = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    namespace = f"https://spdx.org/spdxdocs/{args.package_name}-{uuid.uuid4()}"

    spdx_files = []
    relationships = []
    for path in files:
        rel = path.relative_to(input_dir).as_posix()
        file_id = spdx_id("file-" + rel)
        spdx_files.append(
            {
                "fileName": "./" + rel,
                "SPDXID": file_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256_file(path)}],
                "fileTypes": [file_type_for(path)],
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": package_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{args.package_name}-sbom",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": ["Tool: contrib/devtools/generate_spdx_sbom.py"],
        },
        "packages": [
            {
                "name": args.package_name,
                "SPDXID": package_id,
                "versionInfo": args.package_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        ],
        "files": spdx_files,
        "relationships": relationships,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
