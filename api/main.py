"""
SVP API — FastAPI backend
Run: uvicorn api.main:app --reload --port 8000
"""
import sys
import json
import tempfile
import os
from collections import deque
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Make scripts/ importable
SVP_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SVP_ROOT / "scripts"))
import validate as validator

app = FastAPI(title="SVP — SIGMA Validation Pipeline", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory history ring buffer (last 50 results)
_history: deque = deque(maxlen=50)


# ── models ─────────────────────────────────────────────────────────────────────
class ValidateRequest(BaseModel):
    rule_yaml: str
    corpus_version: str = "v2026.06.1"

class LintRequest(BaseModel):
    rule_yaml: str


# ── helpers ────────────────────────────────────────────────────────────────────
def _write_temp_rule(yaml_text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yml", prefix="svp_rule_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(yaml_text)
    except Exception:
        os.unlink(path)
        raise
    return path


# ── endpoints ──────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/api/validate")
def api_validate(req: ValidateRequest):
    if not req.rule_yaml.strip():
        raise HTTPException(status_code=400, detail="rule_yaml is empty")

    tmp = _write_temp_rule(req.rule_yaml)
    try:
        result = validator.validate(tmp, req.corpus_version)
    finally:
        os.unlink(tmp)

    _history.appendleft({
        "rule_id":    result.get("rule_id", "unknown"),
        "rule_title": result.get("rule_title", ""),
        "verdict":    result.get("verdict", "VOID"),
        "timestamp":  result.get("timestamp"),
    })
    return result


@app.post("/api/lint")
def api_lint(req: LintRequest):
    if not req.rule_yaml.strip():
        raise HTTPException(status_code=400, detail="rule_yaml is empty")

    tmp = _write_temp_rule(req.rule_yaml)
    try:
        issues = validator.lint_rule(tmp)
    finally:
        os.unlink(tmp)

    return {"issues": issues, "error_count": sum(1 for i in issues if i["severity"] == "error"),
            "warning_count": sum(1 for i in issues if i["severity"] == "warning")}


@app.get("/api/history")
def api_history():
    return {"results": list(_history)}


@app.get("/api/corpus")
def api_corpus(version: str = "v2026.06.1"):
    try:
        manifest, manifest_path = validator.load_manifest(version)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    corpus_dir = manifest_path.parent

    # Bad pool stats
    bad_pool_stats = []
    for platform, techniques in manifest.get("bad_pool", {}).items():
        for tech_id, tech_data in techniques.items():
            samples = tech_data.get("samples", [])
            verified = sum(1 for s in samples if s.get("reference_rule_verified"))
            bad_pool_stats.append({
                "platform":   platform,
                "technique":  tech_id,
                "technique_name": tech_data.get("technique_name", ""),
                "format":     tech_data.get("format", ""),
                "total_samples":    len(samples),
                "verified_samples": verified,
            })

    # Good pool stats
    good_pool_stats = []
    for platform, entries in manifest.get("good_pool", {}).items():
        for entry in entries:
            prov_path = (corpus_dir / entry.get("provenance", "")).resolve()
            signed_off = False
            if prov_path.exists():
                with open(prov_path) as f:
                    prov = json.load(f)
                signed_off = prov.get("signed_off", False)
            good_pool_stats.append({
                "platform":    platform,
                "source_dir":  entry.get("source_dir", ""),
                "system_type": entry.get("system_type", ""),
                "format":      entry.get("format", ""),
                "events":      entry.get("events", 0),
                "signed_off":  signed_off,
            })

    # Controls
    controls = manifest.get("controls", {}).get("anchors", [])

    return {
        "version":    version,
        "created":    manifest.get("created"),
        "bad_pool":   bad_pool_stats,
        "good_pool":  good_pool_stats,
        "controls":   controls,
        "techniques_covered": len(bad_pool_stats),
        "signed_off_good_pool": sum(1 for g in good_pool_stats if g["signed_off"]),
    }
