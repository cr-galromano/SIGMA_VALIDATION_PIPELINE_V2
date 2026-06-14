# SIGMA Validation Sandbox — Session Context

**Date:** 2026-06-11

---

## What We Did Today (Phase 0 — COMPLETE)

Proved the core validation loop end-to-end using Zircolite as the native SIGMA scanner.

- **Validated SIGMA YAML ingestion** across all three log-source targets: Windows EVTX, Linux auditd, and Sysmon-for-Linux.
- **Test rule:** `proc_creation_win_cmdkey_recon.yml` — fired 1 HIGH hit on a crafted cmdkey event; returned 0 hits on the benign control. Good/bad pool model confirmed working.
- **Pinned Zircolite v3.7.6** (commit `b37b51eb`) at `scanner/zircolite/` — not forked, version-pinned for reproducibility.
- **Established PASS / FAIL / VOID verdict model** with mandatory positive-control checks before any verdict is trusted:
  - rules loaded > 0
  - events processed > 0
  - known-triggering anchor event fires
  - Any check failure → VOID, not PASS
- **Codified anchor fixtures** in `controls/` (one per log-source type: Windows, auditd, Sysmon-for-Linux).
- **Findings written** to `reports/phase1-zircolite-validation.md`.
- **Known gap confirmed:** no cloud/network pySigma pipelines in Zircolite — cloud/network logsources will need a second scanner, routed by `logsource.product`/`service` (deferred to Phase 4/5).

---

## What Needs to Be Done

### Phase 1 — Corpora Foundation (IN PROGRESS)
**Goal:** Versioned, labeled corpus the pipeline can rely on.

**Done:**
- [x] Folder + version layout defined (`corpora/v2026.06.1/good-pool/`, `bad-pool/`)
- [x] ATT&CK tagging schema defined; `manifest.json` written and versioned
- [x] Bad pool seeded (synthetic) — Windows T1003.005, T1059.001; Linux T1071.004 (auditd + sysmon-linux)
- [x] Good pool created (synthetic) — Windows workstation-baseline, Linux server-baseline
- [x] Reference rules written for each technique (`rules/reference/`)
- [x] `reports/path-to-first-real-verdict.md` — plan for getting off synthetic samples

**Remaining (blockers for real verdicts — all samples are currently `signed_off: false` / synthetic):**
- [ ] **Linux detonation session** — set up Neo23x0 auditd watchpoints on any Linux host, run curl/wget/nc/ncat, collect real kernel-generated auditd records for T1071.004. Verify reference rule fires (≥3 hits). Sign off provenance (~1h active).
- [ ] **Linux good-pool real capture** — 2-hour baseline from a Linux server with same auditd config (Neo23x0 watchpoints active). Requires SIEM/EDR incident check for the capture window + PII scrub + `signed_off: true` in `provenance.json`. Irreducible human step (~2h elapsed, 1h active).
- [ ] **Windows bad-pool real samples** — current Windows samples (T1003.005, T1059.001) are hand-crafted. EVTX-ATTACK-SAMPLES has no cmdkey entries; Windows path also requires a detonation VM. Defer until Linux first-verdict is proven.
- [ ] **Windows good-pool real capture** — replace synthetic Sysmon fixture with real capture from a clean domain workstation.

**Exit criteria:** `good/` and `bad/` pools on disk, versioned, tag manifest, at least one technique with `signed_off: true` samples on both sides → first real (non-VOID) verdict possible.

---

### Phase 2 — Validation Service
**First-verdict target rule:** `lnx_auditd_susp_c2_commands.yml` (Linux auditd, T1071.004)

Minimum corpus before building the service:
- **Bad pool:** one detonation session on a Linux host with Neo23x0 auditd watchpoints active. Run **5–6 tool invocations** (curl, wget, nc, `python -c`, `/dev/tcp`, curl variant) — tools need not connect, auditd fires on exec. Sign-off: the engineer who ran it.
- **Good pool:** one signed-off **2-hour baseline** from a Linux server with the **same auditd config (Neo23x0 watchpoints confirmed active and logging before the window)**. Sign-off: a security analyst confirming no incidents in the window (irreducible human step).
- Estimated effort: ~2.5h active, ~4h elapsed (2h passive capture runs in parallel).

Then build the service:
- [ ] Wrap Zircolite: rule in → lint/tag check → good-pool run → bad-pool run → verdict JSON out
- [ ] Bake in positive controls (inherited from Phase 0); failing any → VOID
- [ ] Implement verdict logic: good-pool silence test; bad-pool 3+ distinct-sample coverage (or all if <3); specificity check against rest of pool
- [ ] Auto-pair rules to bad-pool samples via `tags: attack.tXXXX`
- [ ] Parallel workers for throughput

**Exit criteria:** Script or CLI: rule in → PASS / FAIL / VOID verdict out.

---

### Phase 3 — Untagged-Rule Handling + AI Suggestions
- [ ] Lint check flags missing tags (warn now, block later — policy TBD)
- [ ] Fallback: cluster rule by which technique's samples it hits → infer tag → apply 3+ bar → mark "inferred/unverified"
- [ ] AI suggestion module: on good-pool failure propose tightened condition; on missing tags propose likely tag
- [ ] Every AI suggestion **must re-run the full pipeline** before being surfaced as valid

**Exit criteria:** Untagged rules get a verdict; failing rules get a re-validated suggestion.

---

### Phase 4 — Hub API Integration
- [ ] Define API contract: submit-rule, get-verdict, report payloads
- [ ] Version-pin rule + pool per run (reproducibility)
- [ ] Define pass/fail gate hub enforces before dissemination
- [ ] Surface "not a per-platform guarantee" caveat in all verdict output

**Exit criteria:** Hub can submit a rule and gate dissemination on the verdict.

---

### Phase 5 — Hardening & Scale (Ongoing)
- [ ] Add Linux corpora depth (auditd / Sysmon-for-Linux)
- [ ] Add second scanner only if cloud/network logsources appear (route by `logsource.product`/`service`)
- [ ] Stand up Atomic Red Team detonation VM for technique-coverage gap-filling
- [ ] Coverage dashboard: which ATT&CK techniques can/can't be validated
- [ ] Decide on optional SIEM-backed hybrid validation stage for high-confidence rules

---

## Open Items (Policy TBD)
- **Untagged-rule gating:** warn now vs. block later — current lean: warn during adoption, block once tagging is the norm
- **Good-pool provenance/review process:** exact sign-off workflow not yet defined
- **SIEM-backed hybrid stage:** optional future addition for high-confidence rules

---

## Key Decisions (Locked)
- **Scanner:** Zircolite (native SIGMA, no conversion) — pinned at v3.7.6 / `b37b51eb`
- **Verdict model:** PASS / FAIL / VOID — zero-detection is never auto-PASS
- **Good-pool policy:** any hit = FAIL; return offending log lines
- **Bad-pool threshold:** 3+ distinct sample hits (or all if technique has <3 samples)
- **Deployment:** on-prem VMs (logs stay in-network)
- **"Passes sandbox" caveat:** means this engine's SIGMA interpretation, not a per-platform guarantee
