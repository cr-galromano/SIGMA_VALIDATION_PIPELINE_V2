#!/usr/bin/env python3
"""
Convert macOS Unified Log JSON output to SIGMA-compatible JSONL.

Usage:
    log show --style json --predicate '...' | python3 scripts/mac_unified_to_sigma.py
    python3 scripts/mac_unified_to_sigma.py input.json output.jsonl

Input: JSON array from `log show --style json`
Output: JSONL where each line is a SIGMA process_creation event:
    {"Image": "/usr/bin/ls", "CommandLine": "", "ProcessId": 1234,
     "UtcTime": "...", "type": "process_creation"}

Limitation:
    CommandLine is NOT available in the Unified Log — requires ESF or OpenBSM audit.
    For good-pool purposes this is acceptable: rules that check CommandLine simply
    won't fire (no false positives). Bad-pool capture needs OpenBSM.
"""
import sys
import json
from pathlib import Path


def convert(entries: list) -> list:
    seen = set()
    records = []

    for entry in entries:
        image = entry.get("processImagePath", "")
        if not image or not image.startswith("/"):
            continue

        pid = entry.get("processID", 0)
        key = (image, pid)
        if key in seen:
            continue
        seen.add(key)

        records.append({
            "type": "process_creation",
            "Image": image,
            "CommandLine": "",
            "ProcessId": pid,
            "User": "",
            "UtcTime": entry.get("timestamp", ""),
        })

    return records


def main():
    if len(sys.argv) == 3:
        in_path, out_path = sys.argv[1], sys.argv[2]
        raw = Path(in_path).read_text(errors="replace").strip()
        try:
            entries = json.loads(raw) if raw else []
        except json.JSONDecodeError as e:
            print(f"WARNING: JSON parse error: {e}", file=sys.stderr)
            entries = []
        records = convert(entries)
        with open(out_path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        print(f"Converted {len(records)} unique process entries → {out_path}",
              file=sys.stderr)
    elif len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == "-"):
        raw = sys.stdin.read().strip()
        try:
            entries = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            entries = []
        for r in convert(entries):
            print(json.dumps(r))
    else:
        print(f"Usage: {sys.argv[0]} [input.json output.jsonl]", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
