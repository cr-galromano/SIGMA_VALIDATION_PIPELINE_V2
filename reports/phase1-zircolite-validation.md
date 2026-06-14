# Phase 1 — Zircolite Validation Findings

**Date:** 2026-06-11  
**Zircolite version:** v3.7.6 (commit b37b51eb)  
**Location:** `scanner/zircolite/` (pinned, not forked)

---

## Results by log format

| Format | Log file | Ruleset | Events | Detections | Result |
|--------|----------|---------|--------|------------|--------|
| Auditd (bad pool) | `corpora/bad-pool/auditd_c2_commands.log` | `lnx_auditd_susp_c2_commands.yml` (native YAML) | 3 | 3 MED | ✅ All fired |
| Auditd (good pool) | `corpora/good-pool/auditd_benign.log` | same | 4 | 0 | ✅ Silent |
| Sysmon-for-Linux | `corpora/bad-pool/sysmon_linux_sample.log` | `rules_linux.json` (compiled) | 2 | 1 LOW (Curl Usage on Linux) | ✅ Auto-detected + fired |
| Windows JSON (bad pool) | `corpora/bad-pool/windows_sysmon_attack.json` | 3× Windows YAML rules | 2 | 0 | ⚠️ See note |
| Windows JSON (good pool) | `corpora/good-pool/windows_events_benign.json` | same | 4 | 0 | ✅ Silent |

**Windows bad-pool note:** The 3 sample Windows rules (7zip password compression, AdPlus memory dump, AgentExecutor abuse) target specific techniques not present in the Winlogbeat fixture. This was a corpus gap, not an ingestion failure — Windows ingestion is now demonstrated in the section below.

---

## Windows fire-confirmation

**Rule:** `proc_creation_win_cmdkey_recon.yml` (SigmaHQ, HIGH severity, `attack.t1003.005`)  
Detection: Sysmon EventID 1, `Image` ends with `\cmdkey.exe`, `CommandLine` contains ` /l` or ` -l`.

**Method:** Inspected the compiled SQL (via `--save-ruleset`) to confirm the exact field names and filters used, then hand-crafted a minimal Sysmon JSON event satisfying those conditions precisely. Both log files use `--pipeline sysmon --pipeline windows-logsources`.

| Log file | Events in | Events processed | Detections | Result |
|----------|-----------|-----------------|------------|--------|
| `corpora/bad-pool/windows_cmdkey_attack.json` | 1 | 1 | **1 HIGH** | ✅ Fired |
| `corpora/good-pool/windows_events_benign.json` | 4 | 2 (2 filtered — wrong channel/EventID) | 0 | ✅ Silent |

The good-pool run's "2 filtered out" line is itself evidence the pipeline ran and the channel/EventID filter is active — if the rule had silently failed to load, there would be 0 events processed, not 2 filtered. **Windows ingestion is now demonstrated, not inferred.**

Compiled SQL for reference (confirms all mapped field names):
```sql
SELECT * FROM logs
WHERE Channel='Microsoft-Windows-Sysmon/Operational'
AND EventID=1
AND (Image LIKE '%\\cmdkey.exe' OR OriginalFileName='cmdkey.exe')
AND (CommandLine LIKE '% -l%' OR CommandLine LIKE '% /l%' OR CommandLine LIKE '% –l%' …)
```

---

## Positive-control design principle (for Phase 2 verdict logic)

**The core problem:** `0 detections` is ambiguous. It means either:
- (A) The rule correctly found nothing — a real result.
- (B) The rule failed to parse, the log was the wrong format, or the pipeline silently errored — a broken run that looks like (A).

You cannot tell them apart from the zero alone. This matters most for the good-pool test (expect 0 = pass): a broken pipeline would pass a malicious rule as "clean."

**Required safeguard: positive controls on every run.** Before trusting any silence as a real pass, the run must prove:

1. **Rules loaded (non-zero).** Zircolite emits `X/Y rules matched` in coverage output. If Y=0, the ruleset failed to load — abort, do not emit a verdict.

2. **Events processed (non-zero).** If `Events: 0` or all events were filtered out and none were ingested, the log format is wrong or the file is empty — abort, do not emit a verdict.

3. **Positive-control fixture fires.** Each run includes a known-triggering anchor event alongside the pool being tested. The anchor must produce ≥1 detection; if it does not, the run is corrupt and the verdict is voided, regardless of what the actual pool returned.

   - Per-logsource anchor fixtures to maintain:
     - Windows Sysmon: `controls/win_cmdkey_anchor.json` (already validated above)
     - Auditd: `controls/auditd_c2_anchor.log` (3 events, all fire on `lnx_auditd_susp_c2_commands`)
     - Sysmon-for-Linux: `controls/sysmon_linux_curl_anchor.log` (fires on `Curl Usage on Linux`)

4. **Report both states explicitly.** Verdicts must distinguish:
   - `PASS (confirmed)` — rule ran, pool was processed, positive-control fired, pool was silent.
   - `FAIL` — rule ran, pool produced ≥1 detection.
   - `VOID` — run did not satisfy checks 1–3; no verdict issued; requires investigation.

---

## Native SIGMA YAML ingestion — confirmed

Zircolite converts YAML rules via pySigma → SQLite backend at runtime. No pre-compilation needed for validation runs. This is the path the hub will use.

Command pattern:
```bash
python zircolite.py --events <logs> --ruleset <rule.yml or dir/> \
  --config config/config.yaml [--auditd | --sysmon4linux]
```

---

## Installed pySigma pipelines

| Pipeline | Covers |
|----------|--------|
| `sysmon` | Windows Sysmon field mapping |
| `windows-logsources` | Windows event channels |
| `windows-audit` | Windows audit log fields |

---

## Bundled ruleset coverage

| Ruleset | Rules | Formats |
|---------|-------|---------|
| `rules_windows_merged.json` | 4,291 | Windows EVTX / JSON |
| `rules_windows_sysmon.json` | 4,291 | Sysmon-specific |
| `rules_linux.json` | 181 | Auditd + Sysmon-for-Linux |

---

## Gaps — logsources Zircolite does NOT cover

No cloud or network pySigma pipelines are installed. Rules with these `logsource` categories need a second scanner:

- `product: aws` / `service: cloudtrail`
- `product: azure`
- `product: gcp`
- `category: network` / `product: zeek`
- `product: okta`, `product: github`, etc.

**Action for step 8 (API contract):** route SIGMA rules to the right scanner by `logsource.product` + `logsource.service` before dispatch.

---

## Config note

`config/fieldMappings.yaml` is deprecated upstream. Use `config/config.yaml` for all runs going forward. Default config is auto-loaded from `config/config.yaml` if present in the working directory.

---

## Caveat (to surface wherever verdicts are shown)

"Passes the sandbox" = rule executes correctly against Zircolite's pySigma/SQLite interpretation.  
This is **not a per-platform guarantee** (Splunk, Elastic, QRadar, etc. may behave differently).  
Good for catching broken/over-broad/silent rules; not a substitute for per-platform UAT.
