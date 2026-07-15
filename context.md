# SIGMA Validation Sandbox — Session Context

**Last updated:** 2026-07-15

---

## What's Been Built (Phases 0–3 + Web UI)

### Phase 0 — Complete
Core loop proven. Zircolite v3.7.6 pinned at `scanner/zircolite/`. PASS/FAIL/VOID verdict model with mandatory positive-control checks established. Anchor fixtures in `controls/`.

### Phase 1 — Complete
Real, signed-off corpus for T1071.004 (Linux auditd, C2 tooling):
- Bad pool: `corpora/v2026.06.1/bad-pool/linux/T1071.004/detonation.log` — 4 real SYSCALL records (curl, wget, base64, ncat), captured via GitHub Actions
- Good pool: `corpora/v2026.06.1/good-pool/linux/server-baseline-real/` — signed off, anomaly-clean

### Phase 2 — Complete
Validation service at `scripts/validate.py`:
- `validate(rule_path, corpus_version)` → verdict dict (importable, no sys.exit)
- `lint_rule(rule_path)` → list of lint issues
- CLI: `python scripts/validate.py <rule.yml> [--lint-only]`
- Exit codes: 0=PASS, 1=FAIL, 2=VOID, 3=error
- First real verdict: `lnx_auditd_susp_c2_commands.yml` → **PASS**

### Phase 3 — Complete
- Lint checks: missing fields, UUID format, ATT&CK tags, deprecated status, level validity
- Technique inference: untagged rules run against all bad-pool samples, inferred techniques reported in verdict
- Both integrated into `validate.py`

### Web App — Complete
Run with: `bash start.sh`
- Backend: FastAPI at `api/main.py` (port 8000) — `/api/validate`, `/api/lint`, `/api/corpus`, `/api/history`
- Frontend: React + Vite + Tailwind at `web/` (port 5173) — Validate tab, Corpus tab, History tab

---

## Phase 1.5 — COMPLETE (corpus expansion + rule validation)

### What was done
- All 4 Linux bad-pool techniques ingested from GHA run 27502103085
  - T1003.008, T1136.001, T1053.003, T1070.002 — all in `corpora/v2026.06.1/bad-pool/linux/`
- Windows good-pool ingested as synthetic placeholder (`good-pool/windows/workstation-baseline/`) — **unsigned/not signed off** (synthetic Zircolite fixtures; contains suspicious events like malware.exe that would cause false FAILs — do not sign off without replacing with a real capture)
- 4 new Linux sample rules added to `rules/samples/linux/` and all verified PASS:
  - `lnx_auditd_create_account.yml` — real SigmaHQ rule (T1136.001): **PASS** (1 detection)
  - `lnx_auditd_crontab_execution.yml` — svp-authored (T1053.003): **PASS** (5 detections)
  - `lnx_auditd_shred_log_destruction.yml` — svp-authored (T1070.002): **PASS** (2 detections)
  - `lnx_auditd_shadow_file_access.yml` — svp-authored (T1003.008): **PASS** (51 detections)

### SigmaHQ coverage gaps found (2026-07-15)
SigmaHQ has **no auditd-based rules** for:
- **T1053.003** (crontab) — only `service: cron` and `category: process_creation` variants exist; neither matches auditd SYSCALL format
- **T1070.002** (shred) — no shred rule at all; closest is dd/dev/null wipe (T1485)
- **T1003.008** (shadow access) — no auditd SYSCALL rule; closest is T1552.001 grep-for-password (process_creation format, different logsource)

Our corpus proves these techniques are detectable via auditd SYSCALL records. The gap is in public rule libraries.

---

## Next Steps

### Immediate — Windows good-pool (blocks Windows PASS verdicts)
The `good-pool/windows/workstation-baseline/` is synthetic and unsigned. Windows rules return VOID until this is replaced with a real capture and signed off. Options:
1. **Re-run the GHA job** (`expand_corpus.yml` Windows job) once the pipeline repo is accessible again
2. **Manual capture**: clean Windows VM, Sysmon v14 + SwiftOnSecurity config, capture ~24h, export, PII review, sign off
3. **Atomic Red Team**: stand up ART detonation environment (Phase 5 prerequisite anyway)

### Near-term — Contribute gaps back to SigmaHQ
We found 3 auditd detection gaps (T1053.003 crontab, T1070.002 shred, T1003.008 shadow access). Our sample rules are proof-of-concept and can be refined for upstream contribution.

---

## Remaining Phases (roadmap)

### Phase 4 — Hub API Integration
- Define API contract: submit-rule, get-verdict, report payloads
- Version-pin rule + corpus per run (reproducibility)
- Define pass/fail gate hub enforces before dissemination
- Surface "not a per-platform guarantee" caveat in all verdict output

### Phase 5 — Hardening & Scale
- Stand up Atomic Red Team detonation VM for Windows technique coverage
- Coverage dashboard (ATT&CK heatmap — which techniques can/can't be validated)
- More corpus depth (Mordor, EVTX-ATTACK-SAMPLES, internal red-team)
- Decide on optional SIEM-backed hybrid validation stage

---

## Key Decisions (Locked)
- **Scanner:** Zircolite v3.7.6 (native SIGMA, no conversion) — pinned at `b37b51eb`
- **Verdict model:** PASS / FAIL / VOID — zero-detection is never auto-PASS
- **Bad-pool threshold:** fires on ≥1 real sample (3+ threshold is a corpus quality warning, not a gate)
- **Good-pool policy:** any hit = FAIL; return offending log lines
- **Deployment:** on-prem VMs (logs stay in-network)
- **Corpus versioning:** immutable once signed; new version tag for any sample change
- **"Passes sandbox" caveat:** means this engine's SIGMA/Zircolite interpretation, not a per-platform guarantee

## Open Items (Policy TBD)
- **Untagged-rule gating:** warn now vs. block later
- **SIEM-backed hybrid stage:** optional future addition for high-confidence rules
- **AI suggestion module:** deferred from Phase 3, will revisit after corpus is deeper
