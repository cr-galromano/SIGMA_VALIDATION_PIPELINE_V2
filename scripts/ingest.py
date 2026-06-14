#!/usr/bin/env python3
"""
SVP corpus ingest — technique-agnostic replacement for ingest_sample.sh

Usage:
    # Bad pool
    python scripts/ingest.py <sample.log> <sample.meta>

    # Good pool
    python scripts/ingest.py --good-pool <sample.log|evtx> <sample.meta>

Meta file format (key: value, one per line, # comments ignored):
    Bad pool fields:
        FILE, TECHNIQUE, TECHNIQUE_NAME, TACTIC, PLATFORM, FORMAT,
        SOURCE, EVENTS, TOOLS_RUN, HOST, OS, CAPTURE_DATE,
        SIGNED_OFF_BY, SIGN_OFF_DATE, PII_SCRUB_METHOD, REFERENCE_RULE

    Good pool fields:
        FILE, POOL, PLATFORM, FORMAT, EVENTS, HOST, OS, DOMAIN_JOINED,
        LOGGING_CONFIG, CAPTURE_DATE, CAPTURE_WINDOW, REVIEWED_BY,
        REVIEW_DATE, PII_SCRUB_METHOD, NOTES
"""
import sys
import os
import re
import json
import hashlib
import shutil
import argparse
import subprocess
import tempfile
from pathlib import Path

SVP_ROOT      = Path(__file__).resolve().parent.parent
VENV_PYTHON   = SVP_ROOT / "venv" / "bin" / "python"
ZIRCOLITE_PY  = SVP_ROOT / "scanner" / "zircolite" / "zircolite.py"
ZIRCOLITE_CFG = SVP_ROOT / "scanner" / "zircolite" / "config" / "config.yaml"
CORPUS_BASE   = SVP_ROOT / "corpora"
CORPUS_VERSION = "v2026.06.1"

PLATFORM_FLAGS = {
    "linux-auditd":    ["--auditd"],
    "linux-sysmon":    ["--sysmon4linux"],
    "windows-sysmon":  ["--pipeline", "sysmon", "--pipeline", "windows-logsources"],
    "windows-evtx":    ["--pipeline", "sysmon", "--pipeline", "windows-logsources"],
}

def read_meta(path: str) -> dict:
    meta = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            m = re.match(r'^([A-Z_]+):\s*(.*?)(?:\s*#.*)?$', line)
            if m:
                meta[m.group(1)] = m.group(2).strip()
    return meta

def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def zircolite_flags(platform: str, fmt: str) -> list:
    key = f"{platform}-{fmt}".lower().replace(" ", "-")
    if key in PLATFORM_FLAGS:
        return PLATFORM_FLAGS[key]
    if platform == "linux":
        return ["--auditd"]
    return ["--pipeline", "sysmon", "--pipeline", "windows-logsources"]

def run_zircolite(rule: str, events: str, flags: list, timeout: int = 120) -> tuple:
    cmd = [str(VENV_PYTHON), str(ZIRCOLITE_PY),
           "--events", events, "--ruleset", rule,
           "--config", str(ZIRCOLITE_CFG), "--nolog"] + flags
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, cwd=str(SVP_ROOT))
    combined = proc.stderr + "\n" + proc.stdout
    # Strip ANSI/Rich markup before parsing
    clean = re.sub(r'\x1b\[[0-9;]*m', '', combined)
    clean = re.sub(r'\[[^\]]{1,40}\]', '', clean)
    rules = events_proc = detections = 0
    m = re.search(r'Converted\s+([\d,]+)\s+rules', clean)
    if m: rules = int(m.group(1).replace(',', ''))
    m = re.search(r'Total events processed:\s*([\d,]+)', clean)
    if m: events_proc = int(m.group(1).replace(',', ''))
    m = re.search(r'Detections\s+([\d,]+)', clean)
    if m: detections = int(m.group(1).replace(',', ''))
    return rules, events_proc, detections

def load_manifest():
    path = CORPUS_BASE / CORPUS_VERSION / "manifest.json"
    with open(path) as f:
        return json.load(f), path

def save_manifest(manifest: dict, path: Path):
    with open(path, 'w') as f:
        json.dump(manifest, f, indent=2)
        f.write('\n')

def ingest_bad_pool(sample_file: str, meta: dict):
    technique    = meta.get("TECHNIQUE", "").upper()
    tech_name    = meta.get("TECHNIQUE_NAME", "")
    tactic       = meta.get("TACTIC", "unknown")
    platform     = meta.get("PLATFORM", "linux").lower()
    fmt          = meta.get("FORMAT", "auditd").lower()
    source       = meta.get("SOURCE", "detonation")
    events_count = int(meta.get("EVENTS", "0"))
    tools_run    = meta.get("TOOLS_RUN", "")
    capture_date = meta.get("CAPTURE_DATE", "")
    pii_scrub    = meta.get("PII_SCRUB_METHOD", "")
    ref_rule_rel = meta.get("REFERENCE_RULE", "")

    if not technique:
        print("ERROR: TECHNIQUE not set in meta file", file=sys.stderr)
        return False

    # Resolve reference rule
    if ref_rule_rel:
        ref_rule = (SVP_ROOT / ref_rule_rel).resolve()
    else:
        # Try to find automatically
        ref_rule = SVP_ROOT / f"rules/reference/{platform}/{technique}" / f"ref_{technique.lower().replace('.', '_')}.yml"

    if not ref_rule.exists():
        print(f"ERROR: Reference rule not found: {ref_rule}", file=sys.stderr)
        print(f"  Create it at: {ref_rule}", file=sys.stderr)
        return False

    # Compute SHA-256
    digest = sha256(sample_file)
    print(f"[2/5] SHA-256: {digest}")

    # Run reference rule verification
    print("[3/5] Verifying reference rule fires...")
    flags = zircolite_flags(platform, fmt)
    rules_loaded, evts_processed, detections = run_zircolite(
        str(ref_rule), sample_file, flags)

    if rules_loaded == 0 or evts_processed == 0 or detections == 0:
        print(f"ERROR: Reference rule produced zero detections.", file=sys.stderr)
        print(f"  rules_loaded={rules_loaded} events_processed={evts_processed} detections={detections}", file=sys.stderr)
        return False
    print(f"  Reference rule fired: {detections} detection(s). Sample accepted.")

    # Copy to corpus
    print("[4/5] Copying to corpus...")
    corpus_dir   = CORPUS_BASE / CORPUS_VERSION
    dest_dir     = corpus_dir / "bad-pool" / platform / technique
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file    = dest_dir / Path(sample_file).name
    shutil.copy2(sample_file, dest_file)
    rel_path     = f"bad-pool/{platform}/{technique}/{dest_file.name}"
    print(f"  Copied to {dest_file}")

    # Update manifest
    print("[5/5] Updating manifest.json...")
    manifest, manifest_path = load_manifest()
    platform_pool = manifest.setdefault("bad_pool", {}).setdefault(platform, {})

    if technique not in platform_pool:
        platform_pool[technique] = {
            "tactic": tactic,
            "technique_name": tech_name,
            "format": fmt,
            "logsource": _logsource(platform, fmt),
            "pipeline": _pipeline(platform, fmt),
            "reference_rule": ref_rule_rel or str(ref_rule.relative_to(SVP_ROOT)),
            "reference_rule_status": "verified",
            "sample_count": 0,
            "samples": []
        }

    tech_entry = platform_pool[technique]
    # Remove existing entry for this file if re-ingesting
    tech_entry["samples"] = [s for s in tech_entry["samples"] if s.get("file") != rel_path]
    tech_entry["samples"].append({
        "file": rel_path,
        "source": source,
        "events": events_count,
        "description": f"Real detonation capture: {tools_run}",
        "capture_date": capture_date,
        "reference_rule_verified": True,
        "sha256": digest
    })
    tech_entry["sample_count"] = len(tech_entry["samples"])
    tech_entry["reference_rule_status"] = "verified"

    save_manifest(manifest, manifest_path)
    print("  manifest.json updated")
    return True


def ingest_good_pool(sample_file: str, meta: dict):
    platform     = meta.get("PLATFORM", "linux").lower()
    fmt          = meta.get("FORMAT", "auditd").lower()
    events_count = int(meta.get("EVENTS", "0"))
    host         = meta.get("HOST", "")
    os_info      = meta.get("OS", "")
    domain_joined = meta.get("DOMAIN_JOINED", "false").lower()
    logging_cfg  = meta.get("LOGGING_CONFIG", "")
    capture_date = meta.get("CAPTURE_DATE", "")
    capture_window = meta.get("CAPTURE_WINDOW", "")
    reviewed_by  = meta.get("REVIEWED_BY", "")
    review_date  = meta.get("REVIEW_DATE", "")
    pii_scrub    = meta.get("PII_SCRUB_METHOD", "")
    notes        = meta.get("NOTES", "")

    for field, val in [("REVIEWED_BY", reviewed_by), ("REVIEW_DATE", review_date)]:
        if not val or val == "__FILL_IN__":
            print(f"ERROR: {field} not set in meta file", file=sys.stderr)
            return False

    print(f"[2/5] SHA-256: {sha256(sample_file)}")

    # Anomaly scan against all evaluation rules for this platform
    print("[3/5] Anomaly scan...")
    if platform == "linux":
        rule_dir = SVP_ROOT / "rules/samples/linux"
        flags = ["--auditd"] if fmt == "auditd" else ["--sysmon4linux"]
    else:
        rule_dir = SVP_ROOT / "rules/samples/windows"
        flags = ["--pipeline", "sysmon", "--pipeline", "windows-logsources"]

    eval_rules = list(rule_dir.glob("*.yml"))
    if eval_rules:
        rules_str = " ".join(str(r) for r in eval_rules)
        cmd = [str(VENV_PYTHON), str(ZIRCOLITE_PY),
               "--events", sample_file,
               "--ruleset"] + [str(r) for r in eval_rules] + [
               "--config", str(ZIRCOLITE_CFG), "--nolog"] + flags
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=180, cwd=str(SVP_ROOT))
        combined = proc.stderr + "\n" + proc.stdout
        clean = re.sub(r'\[[^\]]{1,40}\]', '', re.sub(r'\x1b\[[0-9;]*m', '', combined))
        m = re.search(r'Detections\s+([\d,]+)', clean)
        hits = int(m.group(1).replace(',', '')) if m else 0
        if hits > 0:
            print(f"ERROR: Anomaly scan found {hits} hits — capture window may not be clean.", file=sys.stderr)
            print(combined, file=sys.stderr)
            return False
        print("  Clean — no evaluation-rule hits.")
    else:
        print("  WARNING: no evaluation rules found — skipping anomaly scan")

    # Copy to corpus
    print("[4/5] Copying to corpus...")
    corpus_dir = CORPUS_BASE / CORPUS_VERSION
    if platform == "linux":
        source_dir_name = "server-baseline-real"
        log_filename    = "audit.log"
    else:
        source_dir_name = "github-actions-baseline"
        log_filename    = "sysmon_baseline" + Path(sample_file).suffix

    dest_dir = corpus_dir / "good-pool" / platform / source_dir_name
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / log_filename
    shutil.copy2(sample_file, dest_file)
    source_dir_rel = f"good-pool/{platform}/{source_dir_name}"
    print(f"  Copied to {dest_file}")

    # Write provenance.json
    prov = {
        "system_type": "linux-server" if platform == "linux" else "windows-server",
        "os": os_info,
        "domain_joined": domain_joined == "true",
        "logging_config": logging_cfg,
        "capture_method": "live capture",
        "capture_date": capture_date,
        "capture_window": capture_window,
        "events": events_count,
        "format": fmt,
        "pii_scrubbed": True,
        "scrub_method": pii_scrub,
        "reviewed_by": reviewed_by,
        "review_date": review_date,
        "signed_off": True,
        "notes": notes or f"Real capture from {host}."
    }
    with open(dest_dir / "provenance.json", 'w') as f:
        json.dump(prov, f, indent=2)
        f.write('\n')
    print("  Wrote provenance.json (signed_off: true)")

    # Update manifest
    print("[5/5] Updating manifest.json...")
    manifest, manifest_path = load_manifest()
    platform_pool = manifest.setdefault("good_pool", {}).setdefault(platform, [])
    platform_pool = [e for e in platform_pool if e.get("source_dir") != source_dir_rel]
    platform_pool.append({
        "source_dir": source_dir_rel,
        "system_type": prov["system_type"],
        "format": fmt,
        "events": events_count,
        "provenance": f"{source_dir_rel}/provenance.json"
    })
    manifest["good_pool"][platform] = platform_pool
    save_manifest(manifest, manifest_path)
    print("  manifest.json updated")
    return True


def _logsource(platform: str, fmt: str) -> dict:
    if platform == "linux" and fmt == "auditd":
        return {"product": "linux", "service": "auditd"}
    if platform == "linux":
        return {"product": "linux", "service": "sysmon"}
    return {"category": "process_creation", "product": "windows"}

def _pipeline(platform: str, fmt: str) -> list:
    if platform == "windows":
        return ["sysmon", "windows-logsources"]
    return []


def main():
    parser = argparse.ArgumentParser(description="SVP corpus ingest")
    parser.add_argument("sample", help="Path to the captured log/evtx file")
    parser.add_argument("meta",   help="Path to the .meta provenance file")
    parser.add_argument("--good-pool", action="store_true")
    parser.add_argument("--corpus-version", default=CORPUS_VERSION)
    args = parser.parse_args()

    global CORPUS_VERSION
    CORPUS_VERSION = args.corpus_version

    if not Path(args.sample).exists():
        print(f"ERROR: sample file not found: {args.sample}", file=sys.stderr)
        sys.exit(1)
    if not Path(args.meta).exists():
        print(f"ERROR: meta file not found: {args.meta}", file=sys.stderr)
        sys.exit(1)

    meta = read_meta(args.meta)
    print(f"[1/5] Reading provenance metadata...")
    for k in ("PLATFORM", "FORMAT"):
        if k not in meta:
            print(f"ERROR: required field '{k}' missing from meta file", file=sys.stderr)
            sys.exit(1)

    print(f"  platform={meta['PLATFORM']}  format={meta['FORMAT']}")

    if args.good_pool:
        ok = ingest_good_pool(args.sample, meta)
    else:
        ok = ingest_bad_pool(args.sample, meta)

    if not ok:
        sys.exit(1)

    print()
    print("Ingest complete.")


if __name__ == "__main__":
    main()
