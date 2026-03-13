#!/usr/bin/env python3
import base64
import json
import sys
from pathlib import Path


def decode_file(entry):
    encoding = entry["encoding"]
    contents = entry["contents"]
    if encoding == "utf8":
        return contents.encode("utf-8")
    if encoding == "base64":
        return base64.b64decode(contents)
    raise ValueError(f"unsupported encoding: {encoding}")


def main():
    bundle = json.load(sys.stdin)
    output_root = Path(bundle["output_root"])

    for entry in bundle["files"]:
        path = output_root / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(decode_file(entry))


if __name__ == "__main__":
    main()
