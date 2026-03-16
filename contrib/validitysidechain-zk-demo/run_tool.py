#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path


def main():
    command_map = {
        "prove": "prove-batch",
        "verify": "verify-batch",
        "derive": "derive-batch",
    }
    if len(sys.argv) != 2 or sys.argv[1] not in command_map:
        print("usage: run_tool.py [prove|verify|derive]", file=sys.stderr)
        return 1

    script_dir = Path(__file__).resolve().parent
    command = ["go", "run", f"./cmd/{command_map[sys.argv[1]]}"]
    request = sys.stdin.buffer.read()

    completed = subprocess.run(
        command,
        cwd=script_dir,
        input=request,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=os.environ.copy(),
    )

    if completed.stdout:
        sys.stdout.buffer.write(completed.stdout)
    if completed.stderr:
        sys.stderr.buffer.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
