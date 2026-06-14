#!/usr/bin/env python3
"""
SVP Validation Service — Phase 2 + 3

Public API:
    validate(rule_path, corpus_version="v2026.06.1") -> dict
    lint_rule(rule_path) -> list[dict]

CLI:
    python scripts/validate.py <rule.yml> [--corpus-version v2026.06.1]

Exit codes: 0=PASS  1=FAIL  2=VOID  3=error
"""
import sys
import re
import json
import subprocess
import argparse
import tempfile
from pathlib import Path
from datetime import datetime, timezone

# ── paths ──────────────────────────────────────────────────────────────────────
SVP_ROOT      = Path(__file__).resolve().parent.parent
VENV_PYTHON   = SVP_ROOT / "venv" / "bin" / "python"
ZIRCOLITE_PY  = SVP_ROOT / "scanner" / "zircolite" / "zircolite.py"
ZIRCOLITE_CFG = SVP_ROOT / "scanner" / "zircolite" / "config" / "config.yaml"
CORPUS_BASE   = SVP_ROOT / "corpora"

EXIT_PASS  = 0
EXIT_FAIL  = 1
EXIT_VOID  = 2
EXIT_ERROR = 3

# ── logsource routing ──────────────────────────────────────────────────────────
LOGSOURCE_MAP = {
    ("linux",   "auditd"): ("auditd",       ["--auditd"]),
    ("linux",   "sysmon"): ("sysmon4linux",  ["--sysmon4linux"]),
    ("linux",   None):     ("sysmon4linux",  ["--sysmon4linux"]),
    ("windows", "sysmon"): ("windows",      ["--pipeline", "sysmon",
                                              "--pipeline", "windows-logsources"]),
    ("windows", None):     ("windows",      ["--pipeline", "sysmon",
                                              "--pipeline", "windows-logsources"]),
}
FORMAT_PLATFORM      = {"auditd": "linux", "sysmon4linux": "linux", "windows": "windows"}
FORMAT_CORPUS_FORMAT = {"auditd": "auditd", "sysmon4linux": "sysmon-linux",
                        "windows": "sysmon-json"}
FORMAT_ANCHOR_KEY    = {"auditd": "auditd", "sysmon4linux": "sysmon-linux",
                        "windows": "windows-sysmon"}
FORMAT_LOG_GLOB      = {"auditd": "*.log", "sysmon4linux": "*.log", "windows": "*.json"}


def resolve_logsource(logsource: dict):
    product = logsource.get("product", "").lower()
    service = (logsource.get("service") or "").lower() or None
    for key in [(product, service), (product, None)]:
        if key in LOGSOURCE_MAP:
            return LOGSOURCE_MAP[key]
    return None, None


# ── Zircolite wrapper ──────────────────────────────────────────────────────────
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
_RICH_RE  = re.compile(r'\[[^\]]{1,40}\]')

def _strip(text: str) -> str:
    return _RICH_RE.sub('', _ANSI_RE.sub('', text))

def _int(s: str) -> int:
    return int(s.replace(',', '').replace(' ', ''))

def _parse(raw: str) -> dict:
    text = _strip(raw)
    rules = events = detections = 0
    m = re.search(r'Converted\s+([\d,]+)\s+rules', text)
    if m:
        rules = _int(m.group(1))
    m = re.search(r'Total events processed:\s*([\d,]+)', text)
    if m:
        events = _int(m.group(1))
    m = re.search(r'Detections\s+([\d,]+)', text)
    if m:
        detections = _int(m.group(1))
    return {"rules_converted": rules, "events_processed": events, "detections": detections}


def run_zircolite(rule: str, events_path: str, extra_flags: list, timeout: int = 120):
    cmd = [
        str(VENV_PYTHON), str(ZIRCOLITE_PY),
        "--events",  str(events_path),
        "--ruleset", str(rule),
        "--config",  str(ZIRCOLITE_CFG),
        "--nolog",
    ] + extra_flags
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=str(SVP_ROOT),
        )
        return _parse(proc.stderr + "\n" + proc.stdout), None
    except subprocess.TimeoutExpired:
        return {"rules_converted": 0, "events_processed": 0, "detections": 0}, "timed out"


def is_void(zr: dict) -> bool:
    return zr["rules_converted"] == 0 or zr["events_processed"] == 0


# ── loading ────────────────────────────────────────────────────────────────────
def load_manifest(version: str):
    path = CORPUS_BASE / version / "manifest.json"
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    with open(path) as f:
        return json.load(f), path


def parse_rule(rule_path: str) -> dict:
    import yaml
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    return {
        "id":        rule.get("id", "unknown"),
        "title":     rule.get("title", ""),
        "logsource": rule.get("logsource") or {},
        "tags":      rule.get("tags") or [],
        "status":    rule.get("status", ""),
        "level":     rule.get("level", ""),
    }


def extract_techniques(tags: list) -> list:
    seen, out = set(), []
    for t in tags:
        m = re.match(r'attack\.(t\d{4}(?:\.\d{3})?)', t, re.IGNORECASE)
        if m:
            tech = m.group(1).upper()
            if tech not in seen:
                seen.add(tech)
                out.append(tech)
    return out


# ── Phase 3: lint ──────────────────────────────────────────────────────────────
def lint_rule(rule_path: str) -> list:
    """
    Return a list of lint issues for a SIGMA rule.
    Each issue: {"severity": "error"|"warning"|"info", "code": str, "message": str}
    """
    import yaml
    issues = []

    try:
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
    except Exception as exc:
        return [{"severity": "error", "code": "PARSE_ERROR",
                 "message": f"Failed to parse YAML: {exc}"}]

    if not rule:
        return [{"severity": "error", "code": "EMPTY_RULE",
                 "message": "Rule file is empty or contains no YAML"}]

    # Required fields
    for field in ("id", "title", "description", "logsource", "detection"):
        if not rule.get(field):
            issues.append({"severity": "error", "code": f"MISSING_{field.upper()}",
                           "message": f"Required field '{field}' is missing or empty"})

    # ID format (should be UUID)
    rule_id = rule.get("id", "")
    if rule_id and not re.match(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        str(rule_id), re.IGNORECASE
    ):
        issues.append({"severity": "warning", "code": "INVALID_ID_FORMAT",
                       "message": f"Rule ID '{rule_id}' is not a valid UUID"})

    # Deprecated status
    if rule.get("status") == "deprecated":
        issues.append({"severity": "error", "code": "DEPRECATED",
                       "message": "Rule status is 'deprecated'"})

    # Logsource
    logsource = rule.get("logsource") or {}
    if logsource and not logsource.get("product"):
        issues.append({"severity": "warning", "code": "MISSING_LOGSOURCE_PRODUCT",
                       "message": "logsource.product is not set"})
    if logsource and not logsource.get("service") and not logsource.get("category"):
        issues.append({"severity": "info", "code": "MISSING_LOGSOURCE_SERVICE",
                       "message": "logsource.service and logsource.category are both unset"})

    # Tags / ATT&CK
    tags = rule.get("tags") or []
    techniques = extract_techniques(tags)
    if not tags:
        issues.append({"severity": "warning", "code": "NO_TAGS",
                       "message": "Rule has no tags — ATT&CK technique mapping is missing"})
    elif not techniques:
        issues.append({"severity": "warning", "code": "NO_ATTACK_TECHNIQUE",
                       "message": "Tags present but no ATT&CK technique IDs found (expected attack.tXXXX)"})

    # Level
    valid_levels = {"critical", "high", "medium", "low", "informational"}
    level = rule.get("level", "")
    if not level:
        issues.append({"severity": "warning", "code": "MISSING_LEVEL",
                       "message": "Rule level is not set"})
    elif level.lower() not in valid_levels:
        issues.append({"severity": "warning", "code": "INVALID_LEVEL",
                       "message": f"Unknown level '{level}' — expected one of {sorted(valid_levels)}"})

    # False positives
    if not rule.get("falsepositives"):
        issues.append({"severity": "info", "code": "NO_FALSEPOSITIVES",
                       "message": "No falsepositives field — consider documenting known FPs"})

    return issues


# ── positive controls ──────────────────────────────────────────────────────────
def check_controls(manifest: dict, manifest_path: Path, format_tag: str,
                   extra_flags: list) -> tuple:
    manifest_dir = manifest_path.parent
    anchor_key   = FORMAT_ANCHOR_KEY.get(format_tag)
    anchors      = [a for a in manifest.get("controls", {}).get("anchors", [])
                    if a.get("logsource") == anchor_key]

    checks = []
    void_triggered = False

    for a in anchors:
        anchor_file = (manifest_dir / a["file"]).resolve()
        anchor_rule = (manifest_dir / a["rule"]).resolve()
        expected    = a["expected_detections"]
        zr, err     = run_zircolite(str(anchor_rule), str(anchor_file), extra_flags)
        voided      = bool(err or is_void(zr) or zr["detections"] < expected)
        if voided:
            void_triggered = True
        checks.append({
            "anchor":   str(anchor_file.relative_to(SVP_ROOT)),
            "expected": expected,
            "actual":   zr["detections"],
            "result":   "VOID" if voided else "PASS",
            "error":    err,
        })

    if not anchors:
        checks.append({"anchor": None, "result": "SKIP",
                       "note": f"No anchor defined for '{anchor_key}'"})

    return {"result": "VOID" if void_triggered else "PASS", "checks": checks}, void_triggered


# ── bad pool ───────────────────────────────────────────────────────────────────
def check_bad_pool(rule_path: str, manifest: dict, manifest_path: Path,
                   techniques: list, format_tag: str, extra_flags: list,
                   warnings: list) -> tuple:
    manifest_dir  = manifest_path.parent
    platform      = FORMAT_PLATFORM[format_tag]
    corpus_format = FORMAT_CORPUS_FORMAT[format_tag]
    platform_pool = manifest.get("bad_pool", {}).get(platform, {})

    # Build sample list; when rule is untagged scan everything for inference
    untagged = not techniques
    samples_by_tech: dict = {}  # tech → [sample, ...]

    if untagged:
        for tech, tdata in platform_pool.items():
            if tdata.get("format") == corpus_format:
                verified = [s for s in tdata.get("samples", [])
                            if s.get("reference_rule_verified")]
                if verified:
                    samples_by_tech[tech] = verified
    else:
        for tech in techniques:
            tdata = platform_pool.get(tech)
            if not tdata:
                warnings.append(f"No bad-pool corpus for {tech}")
                continue
            if tdata.get("format") != corpus_format:
                warnings.append(
                    f"Skipping {tech}: corpus format '{tdata.get('format')}' "
                    f"doesn't match rule format '{corpus_format}'"
                )
                continue
            verified = [s for s in tdata.get("samples", [])
                        if s.get("reference_rule_verified")]
            skipped  = len(tdata.get("samples", [])) - len(verified)
            if skipped:
                warnings.append(f"Skipped {skipped} unverified sample(s) in {tech}")
            if verified:
                samples_by_tech[tech] = verified

    all_samples = [(tech, s) for tech, ss in samples_by_tech.items() for s in ss]

    if not all_samples:
        return {
            "result": "FAIL",
            "reason": (
                f"No verified bad-pool samples for technique(s): "
                f"{techniques or 'untagged rule'}"
            ),
            "samples_tested": 0,
            "total_detections": 0,
            "hits": [],
            "inferred_techniques": [],
        }, False

    hits, total, void_triggered = [], 0, False
    inferred: set = set()

    for tech, s in all_samples:
        spath = (manifest_dir / s["file"]).resolve()
        if not spath.exists():
            warnings.append(f"Missing sample: {s['file']}")
            continue
        zr, err = run_zircolite(rule_path, str(spath), extra_flags)
        if err or is_void(zr):
            void_triggered = True
            warnings.append(
                f"VOID on bad-pool {s['file']}: {err or 'rules/events=0'}")
            continue
        total += zr["detections"]
        if zr["detections"] > 0:
            hits.append({"file": s["file"], "detections": zr["detections"]})
            if untagged:
                inferred.add(tech)

    result = "PASS" if total > 0 else "FAIL"
    out = {
        "result": result,
        "samples_tested": len(all_samples),
        "total_detections": total,
        "hits": hits,
    }
    if untagged:
        out["inferred_techniques"] = sorted(inferred)
        if inferred:
            warnings.append(
                f"Inferred techniques from bad-pool hits: {sorted(inferred)} "
                f"— add these as tags and re-run for a confirmed verdict"
            )
    return out, void_triggered


# ── good pool ──────────────────────────────────────────────────────────────────
def check_good_pool(rule_path: str, manifest: dict, manifest_path: Path,
                    format_tag: str, extra_flags: list, warnings: list) -> tuple:
    corpus_dir = manifest_path.parent
    platform   = FORMAT_PLATFORM[format_tag]
    log_glob   = FORMAT_LOG_GLOB[format_tag]
    entries    = manifest.get("good_pool", {}).get(platform, [])

    log_dirs = []
    for entry in entries:
        prov_path = (corpus_dir / entry.get("provenance", "")).resolve()
        if not prov_path.exists():
            warnings.append(f"Provenance file missing: {entry.get('provenance')}")
            continue
        with open(prov_path) as f:
            prov = json.load(f)
        if not prov.get("signed_off"):
            warnings.append(f"Skipping unsigned good-pool: {entry['source_dir']}")
            continue
        log_dirs.append((corpus_dir / entry["source_dir"]).resolve())

    if not log_dirs:
        return {
            "result": "VOID",
            "reason": f"No signed-off good-pool samples for platform '{platform}'",
            "files_tested": 0,
            "total_hits": 0,
            "offenders": [],
        }, True

    offenders, total_hits, files_tested, void_triggered = [], 0, 0, False

    for log_dir in log_dirs:
        log_files = [f for f in log_dir.glob(log_glob)
                     if f.name != "provenance.json"]
        for lf in log_files:
            files_tested += 1
            zr, err = run_zircolite(rule_path, str(lf), extra_flags)
            if err or is_void(zr):
                void_triggered = True
                warnings.append(
                    f"VOID on good-pool {lf.name}: {err or 'rules/events=0'}")
                continue
            total_hits += zr["detections"]
            if zr["detections"] > 0:
                offenders.append({
                    "file": str(lf.relative_to(SVP_ROOT)),
                    "detections": zr["detections"],
                })

    result = "FAIL" if total_hits > 0 else "PASS"
    return {
        "result": result,
        "files_tested": files_tested,
        "total_hits": total_hits,
        "offenders": offenders,
    }, void_triggered


# ── public API ─────────────────────────────────────────────────────────────────
def validate(rule_path: str, corpus_version: str = "v2026.06.1") -> dict:
    """
    Validate a SIGMA rule against the corpus.
    Returns a verdict dict suitable for JSON serialisation.
    Does NOT call sys.exit() — safe to import and call from other modules.
    """
    warnings: list = []

    try:
        manifest, manifest_path = load_manifest(corpus_version)
        rule = parse_rule(rule_path)
    except Exception as exc:
        return {
            "verdict": "VOID",
            "reason": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    format_tag, extra_flags = resolve_logsource(rule["logsource"])
    if format_tag is None:
        return {
            "rule_id":    rule["id"],
            "rule_title": rule["title"],
            "rule_file":  rule_path,
            "verdict":    "VOID",
            "reason":     f"Unsupported logsource: {rule['logsource']}",
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        }

    techniques = extract_techniques(rule["tags"])
    if not techniques:
        warnings.append(
            "Rule has no ATT&CK technique tags — running against all "
            "bad-pool samples to infer technique coverage"
        )

    # Phase 3: lint
    lint_issues = lint_rule(rule_path)

    controls_res, controls_void = check_controls(
        manifest, manifest_path, format_tag, extra_flags)

    bad_res, bad_void = check_bad_pool(
        rule_path, manifest, manifest_path, techniques,
        format_tag, extra_flags, warnings)

    good_res, good_void = check_good_pool(
        rule_path, manifest, manifest_path, format_tag, extra_flags, warnings)

    # VOID > FAIL > PASS
    if controls_void or bad_void or good_void:
        verdict = "VOID"
        if controls_void:
            reason = "Positive control anchor did not fire — pipeline may be broken"
        elif bad_void:
            reason = "VOID trigger during bad-pool run (rules not loaded or events not processed)"
        else:
            reason = good_res.get("reason", "VOID trigger during good-pool run")
    elif bad_res["result"] == "FAIL":
        verdict = "FAIL"
        reason  = bad_res.get("reason") or "Rule did not fire on any bad-pool sample"
    elif good_res["result"] == "FAIL":
        verdict = "FAIL"
        offenders = [o["file"] for o in good_res.get("offenders", [])]
        reason    = f"Rule fired on benign good-pool data: {offenders}"
    else:
        verdict = "PASS"
        reason  = None

    return {
        "rule_id":           rule["id"],
        "rule_title":        rule["title"],
        "rule_file":         rule_path,
        "corpus_version":    corpus_version,
        "verdict":           verdict,
        "reason":            reason,
        "lint":              lint_issues,
        "bad_pool":          bad_res,
        "good_pool":         good_res,
        "positive_controls": controls_res,
        "warnings":          warnings,
        "timestamp":         datetime.now(timezone.utc).isoformat(),
    }


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SVP SIGMA rule validator")
    parser.add_argument("rule", help="Path to a SIGMA rule YAML file")
    parser.add_argument("--corpus-version", default="v2026.06.1")
    parser.add_argument("--lint-only", action="store_true",
                        help="Only run lint checks, skip validation")
    args = parser.parse_args()

    if args.lint_only:
        issues = lint_rule(args.rule)
        print(json.dumps(issues, indent=2))
        errors = [i for i in issues if i["severity"] == "error"]
        return EXIT_ERROR if errors else EXIT_PASS

    result = validate(args.rule, args.corpus_version)
    print(json.dumps(result, indent=2))
    return {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL, "VOID": EXIT_VOID}.get(
        result.get("verdict", "VOID"), EXIT_ERROR
    )


if __name__ == "__main__":
    sys.exit(main())
