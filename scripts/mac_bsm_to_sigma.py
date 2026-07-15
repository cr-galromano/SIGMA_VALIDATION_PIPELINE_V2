#!/usr/bin/env python3
"""
Convert macOS OpenBSM praudit XML output to SIGMA-compatible JSONL.

Usage:
    praudit -x /var/audit/<file> | python3 scripts/mac_bsm_to_sigma.py > output.jsonl
    python3 scripts/mac_bsm_to_sigma.py input.xml output.jsonl

Output format (one JSON object per line):
    {"Image": "/usr/bin/ls", "CommandLine": "ls -la /tmp",
     "ProcessId": 1234, "ParentProcessId": 5678,
     "User": "501", "UtcTime": "...", "type": "process_creation"}

Limitations:
    - CommandLine requires policy:argv in /etc/security/audit_control
    - User is the numeric UID (no /etc/passwd lookup in headless CI)
    - ParentProcessId is not always present in BSM records
"""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_bsm_xml(xml_text: str) -> list:
    """Parse praudit -x output into a list of SIGMA process_creation records."""
    records = []

    # praudit -x produces a stream of <record> elements, sometimes without
    # a root wrapper. Wrap in a root to make it valid XML.
    wrapped = f"<audit>{xml_text}</audit>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as e:
        # Try stripping the doctype / file header lines and retry
        lines = [l for l in xml_text.splitlines()
                 if not l.startswith("<?") and not l.startswith("<!") and
                 not l.startswith("<file>") and not l.startswith("</file>")]
        try:
            root = ET.fromstring(f"<audit>{''.join(lines)}</audit>")
        except ET.ParseError:
            print(f"WARNING: could not parse BSM XML: {e}", file=sys.stderr)
            return []

    for record in root.findall("record"):
        event = record.get("event", "")
        # Only care about exec events
        if "execve" not in event.lower() and "exec" not in event.lower():
            continue

        # Extract path (executable)
        path_el = record.find("path")
        image = path_el.text.strip() if path_el is not None and path_el.text else ""
        if not image:
            continue

        # Extract exec args (first arg is program name, rest are arguments)
        args = [el.text for el in record.findall("exec-arg")
                if el.text is not None]
        command_line = " ".join(args) if args else image

        # Extract subject fields
        subject = record.find("subject")
        pid = 0
        ppid = 0
        uid = ""
        if subject is not None:
            pid = int(subject.get("pid", "0"))
            ppid = int(subject.get("ppid", "0"))
            uid = subject.get("uid", "")

        # Timestamp from record attributes
        time_str = record.get("time", "")
        msec_str = record.get("msec", "").strip().lstrip("+ ").strip()

        sigma_record = {
            "type": "process_creation",
            "Image": image,
            "CommandLine": command_line,
            "ProcessId": pid,
            "ParentProcessId": ppid,
            "User": uid,
            "UtcTime": f"{time_str}.{msec_str}ms" if msec_str else time_str,
        }
        records.append(sigma_record)

    return records


def main():
    if len(sys.argv) == 3:
        in_path, out_path = sys.argv[1], sys.argv[2]
        xml_text = Path(in_path).read_text(errors="replace")
        records = parse_bsm_xml(xml_text)
        with open(out_path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        print(f"Converted {len(records)} execve records → {out_path}", file=sys.stderr)
    elif len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == "-"):
        xml_text = sys.stdin.read()
        records = parse_bsm_xml(xml_text)
        for r in records:
            print(json.dumps(r))
        print(f"Converted {len(records)} execve records", file=sys.stderr)
    else:
        print(f"Usage: {sys.argv[0]} [input.xml output.jsonl]", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
