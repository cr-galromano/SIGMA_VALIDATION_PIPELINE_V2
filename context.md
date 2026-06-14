# SIGMA Validation Sandbox — Session Context

**Last updated:** 2026-06-14

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

## Phase 1.5 — IN PROGRESS (corpus expansion)

### What was done
A GitHub Actions workflow (`expand_corpus.yml`) was pushed and is running/completed:
- **Run ID:** 27502103085
- **4 Linux jobs:** all succeeded ✅
  - T1003.008 — /etc/shadow access (`credential_access` auditd key)
  - T1136.001 — useradd/userdel execution (`account_creation` key)
  - T1053.003 — crontab modification (`cron_mod` key)
  - T1070.002 — shred execution (`log_destruction` key)
- **1 Windows job:** windows-good-pool (Sysmon + SwiftOnSecurity config, 5-min baseline)
  - Status at pause: still running (was ~3 min in, needs ~7 min total)

### What needs to be done FIRST next session

**Step 1 — Ingest the artifacts from run 27502103085**

All 4 Linux artifacts are ready. Windows artifact may or may not be done — check first.

```bash
# Check run status
gh run view 27502103085 --repo cr-galromano/SIGMA_VALIDATION_PIPELINE

# Download all artifacts
mkdir -p /tmp/svp-phase15
gh run download 27502103085 --repo cr-galromano/SIGMA_VALIDATION_PIPELINE --dir /tmp/svp-phase15

# Activate venv
cd /Users/gal.romano/Desktop/SVP && source venv/bin/activate

# Ingest all 4 Linux bad-pool samples
python scripts/ingest.py /tmp/svp-phase15/linux-t1003008/t1003008.log /tmp/svp-phase15/linux-t1003008/t1003008.meta
python scripts/ingest.py /tmp/svp-phase15/linux-t1136001/t1136001.log /tmp/svp-phase15/linux-t1136001/t1136001.meta
python scripts/ingest.py /tmp/svp-phase15/linux-t1053003/t1053003.log /tmp/svp-phase15/linux-t1053003/t1053003.meta
python scripts/ingest.py /tmp/svp-phase15/linux-t1070002/t1070002.log /tmp/svp-phase15/linux-t1070002/t1070002.meta

# Ingest Windows good pool (if job succeeded)
python scripts/ingest.py --good-pool \
  /tmp/svp-phase15/windows-good-pool/sysmon_baseline.evtx \
  /tmp/svp-phase15/windows-good-pool/windows_good_pool.meta

# Commit and push
git add corpora/ && git commit -m "corpus: Phase 1.5 ingest — 4 new Linux techniques + Windows good pool"
git push origin main
```

**Step 2 — Verify coverage improved**
```bash
python scripts/validate.py rules/samples/linux/lnx_auditd_susp_c2_commands.yml  # should still PASS
python scripts/validate.py rules/samples/windows/proc_creation_win_cmdkey_recon.yml  # should be PASS now (if Windows good pool ingested)
```

**Step 3 — Test with real SigmaHQ rules**
Pull some real SigmaHQ rules for the newly covered techniques and run them through the validator. Check coverage, find gaps, iterate.

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
