# SIGMA Rule Validation Sandbox — Handoff Summary

## Goal
Build a validation pipeline (a "firing range") for SIGMA rules before they ship from the SigmaHQ hub. Each rule is tested against a **good pool** (benign logs — must stay silent) and a **bad pool** (malicious logs — must fire). Eventually connect to the hub via API.

## Key decisions made

**Evaluation engine — native SIGMA, no conversion.**
The org uses SIGMA as the universal language across multiple platforms; we never convert. So the validator must consume raw SIGMA YAML and run it directly against logs.
- Use **Zircolite** as the standalone scanner. It runs SIGMA directly against **Windows (EVTX), Linux auditd, and Sysmon-for-Linux** logs — covering both Windows and Linux validation in one tool. (Chainsaw was considered but is Windows-only and redundant given Zircolite's broader coverage.)
- Only add a second scanner if the hub also ships rules for sources Zircolite doesn't cover (e.g. cloud/CloudTrail, network). In that case, route each rule to the right scanner by its `logsource:` field.
- Caveat to document: "passes the sandbox" = passes *this engine's* SIGMA interpretation, not a per-platform guarantee. Good for catching broken/over-broad/silent rules; not a substitute for per-platform behavior.

**Deployment:** On-prem / VMs (logs are sensitive, stay in-network). Size for parallelism (many rules × many log files) + storage for corpora.

**Zircolite — pin, don't fork (default).** Zircolite is LGPL-3.0; internal-only use imposes no real obligations (no need to publish source/attribution since we don't distribute — just keep the LICENSE file in the internal repo). Forking + renaming adds nothing on its own. Default: use Zircolite as a dependency, **pin a specific version/commit** so upstream changes can't silently alter validation results (supports reproducibility). Only fork if we need to modify the scanner itself (custom output/verdict format, extra input formats, pool-loading tweaks). Renaming is cosmetic — only if wrapping into a branded internal tool. The real win is version-pinning, not the rename.

**Good pool policy:** Any hit = FAIL. Return the offending log line(s) so the author sees what tripped it. Silence = pass.

**Bad pool policy:**
- Samples are tagged with ATT&CK technique(s).
- **Coverage assertion (must-pass):** rule fires on samples matching its claimed technique (auto-paired via SIGMA `tags: attack.tXXXX`).
- **Specificity (informational):** also run against the rest of the bad pool; firing on everything = over-broad flag.
- **Threshold:** require **3+ distinct sample hits**, OR all samples if the technique has fewer than 3 (so a corpus gap doesn't fail a good rule). Same 3+ bar for tagged and untagged rules.

**Untagged rules:**
1. Lint check flags missing tags. Config flag: warn early (don't fight authors during adoption), block once tagging is the norm.
2. Fallback eval: cluster the rule by which technique's samples it hits, infer the technique, then hold it to the same 3+ coverage bar. Verdict marked "coverage inferred / unverified."
3. AI suggests a likely tag from the matched (tagged) samples — advisory only.

**AI suggestion module:** On a good-pool failure, take rule + matching FP log lines (+ bad-pool samples that must keep matching) and propose a tightened condition. Suggest only, never auto-edit. **Any suggestion must be re-run through the full pipeline before it's trusted** — silent on good pool AND still fires on bad pool.

**Corpora strategy:** Start curated + static (versioned, reviewed, labeled). Pin both rule version and pool version per run for reproducibility.

**Where logs come from (sourcing).** Key asymmetry: the bad pool is mostly *downloaded + augmented*, the good pool is mostly *manufactured* in-house.

Bad pool (malicious — must fire):
- **EVTX-ATTACK-SAMPLES** (GitHub) — ready-made, ATT&CK-tagged Windows EVTX attack logs. Best seed to start fast.
- **Atomic Red Team** — run ATT&CK-mapped "atomics" in a throwaway VM with logging on, capture the EVTX/auditd/Sysmon output. This is the engine for filling coverage gaps: rule exists but no sample → run the matching atomic, harvest logs.
- **Internal red-team / IR captures** — highest fidelity (matches our environment), must be scrubbed of sensitive data.
- Other public sets: Mordor / Security-Datasets (OTRF), Splunk Attack Range.

Good pool (benign — must stay silent):
- No public "benign" set fits — "clean" is only meaningful relative to our systems, so we generate it.
- Stand up representative clean VMs (domain controller, workstation, server, Linux host) with the same logging config as prod, capture normal activity (logons, admin tasks, installs, scheduled jobs, normal user behavior), export as the benign baseline.
- Optionally sample real production logs from a known-quiet window — requires review/sign-off (confirm nothing malicious hiding) + PII scrubbing.

Both pools get versioned and labeled once, then reused. Samples must be in a Zircolite-accepted format (EVTX or JSON for Windows; auditd/Sysmon for Linux) — format normalization is part of corpora ingestion.

## Verdict shape (per rule run)

**Three verdict states — PASS / FAIL / VOID.** A zero-detection result is ambiguous: it can mean "rule correctly stayed silent" OR "the run silently broke and never executed." These must not be collapsed. A run that didn't actually execute is VOID (no result), not a PASS.

**Positive controls — required before any verdict is trusted.** Every run must verify:
1. rules loaded count > 0,
2. events processed count > 0 (e.g. Zircolite's "N events filtered" — a broken run shows 0 processed),
3. a known-triggering anchor event fires.
If any check fails → verdict is **VOID**, not PASS. Anchor fixtures live in `controls/` (one per log-source type: Windows, auditd, Sysmon-for-Linux).

Per-pool reporting:
- Good pool: false-positive count + offending log lines (any hit = FAIL; clean + controls passed = PASS).
- Bad pool: claimed-technique coverage (hits / samples), pass/fail vs. 3+ threshold.
- Specificity: hits on unrelated techniques (over-breadth signal).
- Metadata: rule version, pool version, scanner version, tag status (tagged / inferred / unverified).

## Next steps to execute
1. **Stand up Zircolite** — validate it against sample SIGMA rules + sample logs across EVTX, auditd, and Sysmon-for-Linux. Confirm it ingests the hub's exact YAML. Identify any logsources it doesn't cover (cloud/network) that would need a second scanner.
2. **Design the corpora layout** — folder/version structure for good and bad pools; tagging schema keyed to ATT&CK; provenance/sign-off for good-pool samples.
3. **Seed the bad pool** — pull EVTX-ATTACK-SAMPLES, stand up an Atomic Red Team detonation VM for gap-filling.
4. **Build the good pool** — capture benign baseline logs from representative systems (DC, workstation, server) with provenance.
5. **Build the validation service** — queue-driven: ingest rule → lint/tag check → run vs. both pools → compute verdict → write report. On-prem VMs, parallel workers.
6. **Implement threshold + verdict logic** — good-pool silence test, bad-pool 3+ coverage (with small-corpus fallback), specificity check, tag-inference for untagged rules.
7. **AI suggestion module** — FP-driven tightening suggestions + tag inference; mandatory re-validation loop.
8. **API contract (hub <-> validator)** — define submit-rule, get-verdict, report payloads. Version-pin rule + pool per run. Define pass/fail gating the hub enforces before dissemination.
9. **Document the "not a per-platform guarantee" caveat** wherever verdicts are surfaced.

## Open items
- Final block-vs-warn policy for untagged rules (current lean: warn now, block later).
- Exact good-pool provenance/review process.
- Whether to add a later SIEM-backed validation stage (hybrid) for high-confidence rules.

---

## Execution Plan (phased)

Build bottom-up: prove the core loop on a tiny corpus first, then widen pools, then automate, then integrate. Each phase ends in something runnable so we never build ahead of a working foundation.

### Status
- **Phase 0 — COMPLETE (2026-06-11).** Native SIGMA YAML ingestion demonstrated on Windows (`proc_creation_win_cmdkey_recon.yml` fired 1 HIGH on a crafted cmdkey event, 0 on benign control), Linux auditd, and Sysmon-for-Linux. Good/bad model proven. Zircolite v3.7.6 (commit b37b51eb) pinned, not forked, at `scanner/zircolite/`. PASS/FAIL/VOID verdict model + positive-control checks established and codified as `controls/` anchor fixtures. Findings: `reports/phase1-zircolite-validation.md`. Known gap confirmed: no cloud/network pySigma pipelines — route by `logsource.product`/`service` to a second scanner (Phase 4/5).
- **Phase 1 — NEXT.** Corpora foundation.

### Phase 0 — Spike: prove the core loop (start here)
**Goal:** Confirm Zircolite gives us a usable, parseable verdict on one real rule.
- Install/pin Zircolite locally.
- Grab 1 known-malicious EVTX sample + 1 SIGMA rule that should detect it.
- Hand-build a tiny good pool (a few benign EVTX files).
- Run the rule against both by hand; inspect the JSON output.
- Decide the parse contract: how we read "did it hit, how many distinct samples, which log lines."
**Exit:** One rule, run manually, produces hit/no-hit + matched lines we can read programmatically.
**Validates:** Zircolite ingests our YAML as-is; output is parseable; the good/bad model holds.

### Phase 1 — Corpora foundation
**Goal:** A versioned, labeled corpus the pipeline can rely on.
- Define folder + version layout for good and bad pools.
- Define the ATT&CK tagging schema for bad-pool samples.
- Seed bad pool from EVTX-ATTACK-SAMPLES (tagged).
- Build a first good pool: capture benign activity from 1–2 clean VMs (start Windows, add Linux next).
- Write an ingestion/normalization step (whatever format → Zircolite-accepted).
**Exit:** `good/` and `bad/` pools on disk, versioned, with a tag manifest.
**Depends on:** Phase 0 (know the input format Zircolite needs).

### Phase 2 — Validation service (the engine room)

**Entry criteria — get to the first real (non-VOID) verdict first.** All corpus seeds are currently synthetic/not-signed-off, so the service can only return VOID until real signed-off samples exist. Decision: **capture real samples before building the service** (the manual first run teaches the service what to automate; if the clean baseline needs approvals, that's a sequencing constraint code can't solve — learn it early).

First-verdict target rule: `lnx_auditd_susp_c2_commands.yml` (Linux auditd, T1071.004) — chosen because its reference rule (`ref_auditd_susp_activity_key.yml`) is already verified. Minimum corpus:
- **Bad pool:** one detonation session on any Linux host with Neo23x0 auditd watchpoints active. Run **5–6 tool invocations** (curl, wget, nc, plus extras like `python -c`, `/dev/tcp`, a curl variant) — NOT exactly 3. The 3+ threshold has no margin at exactly 3; if one doesn't fire you drop below for a corpus reason, not a rule reason. Tools need not connect — auditd fires on exec, not network success. Sign-off: the engineer who ran it (~15 min docs, no approvals).
- **Good pool:** one signed-off 2-hour baseline from a Linux server, **same auditd config (Neo23x0 watchpoints active and confirmed logging before the window starts)** — otherwise the host never records the events the rule inspects and "silence" is meaningless (closer to VOID than PASS). Sign-off: a security analyst with SIEM/EDR read access confirming no incidents in the window. This is the irreducible human step.
- Effort: ~2.5h active, ~4h elapsed (2h passive capture in parallel).

**Then build the service:**
- Wrap Zircolite in a service: ingest rule → lint/tag check → run vs. good pool → run vs. bad pool → emit verdict JSON.
- **Bake in positive controls (inherited from Phase 0):** every run asserts rules-loaded > 0, events-processed > 0, and the `controls/` anchor fires. Failing any → **VOID**, not PASS. Emit PASS / FAIL / VOID as distinct states.
- Implement verdict logic: good-pool silence test (any hit = FAIL + lines); bad-pool 3+ distinct-sample coverage (or all if <3); specificity pass over rest of pool.
- Auto-pair rule to bad-pool samples via `tags: attack.tXXXX`.
- Parallel workers for throughput.
**Exit:** CLI/API-less service or script: rule in → verdict out (PASS/FAIL/VOID), matching the "Verdict shape" section.
**Depends on:** Phases 0–1.

### Phase 3 — Untagged-rule handling + AI suggestions
**Goal:** Handle rules without tags, and help authors fix failures.
- Lint flags missing tags (config: warn now).
- Fallback: cluster by which technique's samples it hits → infer → apply 3+ bar → mark "inferred/unverified."
- AI suggestion module: on good-pool failure, propose a tightened condition; on missing tags, propose a likely tag.
- **Mandatory:** every AI suggestion re-runs through Phase 2 before being shown as valid.
**Exit:** Untagged rules get a verdict; failing rules get a re-validated suggestion.
**Depends on:** Phase 2.

### Phase 4 — Hub API integration
**Goal:** Wire the validator to the SigmaHQ hub.
- Define API contract: submit-rule, get-verdict, report payloads.
- Version-pin rule + pool per run (reproducibility).
- Define the pass/fail gate the hub enforces before dissemination.
- Surface the "not a per-platform guarantee" caveat in verdict output.
**Exit:** Hub can submit a rule and gate dissemination on the verdict.
**Depends on:** Phase 2 (ideally 3).

### Phase 5 — Hardening & scale (ongoing)
- Add Linux corpora depth (auditd / Sysmon-for-Linux) and a second scanner only if cloud/network logsources appear.
- Atomic Red Team detonation VM to fill technique-coverage gaps on demand.
- Coverage dashboard: which ATT&CK techniques we can/can't validate.
- Decide on optional SIEM-backed hybrid stage for high-confidence rules.

### Recommended first move
Start with **Phase 0** — one rule, one malicious sample, a handful of benign logs, run by hand. It de-risks everything downstream (proves Zircolite eats our YAML and gives parseable output) in hours, not weeks, before we invest in corpora or services.
