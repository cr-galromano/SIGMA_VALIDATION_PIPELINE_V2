# Corpora Contribution Guide

How new samples enter the corpus, how versions are cut, and what sign-off is required.

---

## Directory layout

```
corpora/
  vYYYY.MM.N/              ← one directory per corpus version
    manifest.json          ← machine-readable index (pinned per validation run)
    bad-pool/
      windows/
        TXXXX.YYY/         ← ATT&CK technique ID
          <sample>.<ext>   ← log file in Zircolite-accepted format
      linux/
        TXXXX.YYY/
          <sample>.<ext>
    good-pool/
      windows/
        <system-type>/
          events.<ext>
          provenance.json  ← required; unsigned samples are rejected
      linux/
        <system-type>/
          audit.log
          provenance.json
  controls/                ← positive-control anchors; versioned separately
  CONTRIBUTING.md          ← this file
rules/
  reference/               ← stable acceptance-gate rules, NEVER evaluated
    windows/
      TXXXX.YYY/
        ref_<technique>.yml
    linux/
      TXXXX.YYY/
        ref_<technique>.yml
```

Corpus versions are **immutable once signed off**. Never modify an existing version in place — cut a new one.

---

## Accepted log formats (Zircolite input)

| Log source | Format | File extension |
|------------|--------|----------------|
| Windows Sysmon | JSON Lines (pyevtx or Winlogbeat) | `.json` |
| Windows EVTX | Binary EVTX | `.evtx` |
| Windows EVTX (exported) | XML | `.xml` |
| Linux auditd | Raw auditd text (`type=SYSCALL …`) | `.log` |
| Sysmon for Linux | XML, one event per line | `.log` |

If a sample arrives in another format (CSV, JSONL from a SIEM, etc.), normalize it to one of the above before adding it to the corpus. Normalization scripts go in `scripts/normalize/`.

---

## Adding bad-pool samples

Bad-pool samples are malicious logs. They must be **independently verified** as genuinely representing the claimed technique before they are accepted into the pool.

### The reference-rule contract

**A sample is accepted when it fires against its technique's reference rule — never against the rule under evaluation.**

This is not a formality. If acceptance used the evaluation rule, corpus integrity and rule quality would be circularly dependent: "the sample is good because the rule fires on it, and the rule is good because it fires on the sample." Neither claim would prove anything independently.

Reference rules live in `rules/reference/<platform>/<TXXXX.YYY>/`. They are:
- **Broader** than evaluation rules — they fire on any genuine instance of the technique, not on specific behaviors
- **Stable** — changed only deliberately, not as part of normal rule development
- **Never evaluated** — no rule in `rules/reference/` is ever submitted to the validation pipeline

The current reference rules and what they detect:

| Technique | Reference rule | Fires on |
|-----------|---------------|----------|
| T1003.005 | `rules/reference/windows/T1003.005/ref_cmdkey_any_execution.yml` | Any `cmdkey.exe` execution (Image or OriginalFileName) |
| T1059.001 | `rules/reference/windows/T1059.001/ref_powershell_encoded_flag.yml` | Any PowerShell with `-e`/`-en`/`-enc` flag |
| T1071.004 | `rules/reference/linux/T1071.004/ref_auditd_susp_activity_key.yml` | Any auditd event with `key=susp_activity` |

**If a technique has no reference rule, adding samples for that technique is blocked until one is written and reviewed.** Document the gap in `manifest.json` under `bad_pool.<platform>.<TXXXX>.reference_rule_status: "MISSING — blocker"`. Do not skip or defer.

### Crafting Windows Sysmon samples

Always include `OriginalFileName` in Sysmon EventID 1 (process creation) samples. The `Image` LIKE-pattern match has edge cases with deep path hierarchies; `OriginalFileName` uses exact equality and is more reliable as the detection anchor. Reference rules for Windows techniques always include both conditions in OR — but the sample should satisfy at least one unambiguously.

### 1. Identify the ATT&CK technique

The rule's `tags: attack.tXXXX` field determines which technique directory the sample goes in. If a sample covers multiple techniques, place it in the primary technique directory and list secondary techniques in the manifest.

### 2. Place the sample

```
corpora/vNEXT/bad-pool/<platform>/<TXXXX.YYY>/<descriptive-name>.<ext>
```

Naming convention: `<tool-or-behavior>_<variant>.<ext>`  
Examples: `cmdkey_list.json`, `powershell_encoded_iex.json`, `curl_c2_port4444.log`

### 3. Verify it fires against the reference rule

Run Zircolite against the sample using **only the reference rule** for that technique. Do not use the evaluation rule you're trying to add support for — that check comes later and is not a substitute.

```bash
source venv/bin/activate

# Windows Sysmon
python scanner/zircolite/zircolite.py \
  --events <sample.json> \
  --ruleset rules/reference/windows/<TXXXX.YYY>/ref_<technique>.yml \
  --config scanner/zircolite/config/config.yaml \
  --pipeline sysmon --pipeline windows-logsources \
  --nolog

# Linux auditd
python scanner/zircolite/zircolite.py \
  --events <sample.log> \
  --ruleset rules/reference/linux/<TXXXX.YYY>/ref_<technique>.yml \
  --config scanner/zircolite/config/config.yaml \
  --auditd --nolog
```

**Required outcome:** ≥1 detection. A sample that does not fire against the reference rule is rejected — it either misrepresents the technique, is in the wrong format, or lacks required fields. Fix the sample; do not relax the reference rule.

**If no reference rule exists for the technique:** stop here. The sample cannot be accepted. File a task to write and validate a reference rule first.

### 4. Update the manifest

Add an entry under `bad_pool.<platform>.<TXXXX.YYY>.samples` in the version's `manifest.json`. Populate:
- `file` — relative path from the version root
- `source` — one of: `hand-crafted`, `evtx-attack-samples`, `atomic-red-team`, `internal-redteam`, `mordor`, `splunk-attack-range`
- `events` — event count in the file
- `description` — one line: what the technique/behavior is
- `sha256` — SHA-256 of the file (run `shasum -a 256 <file>`)
- `reference_rule_verified`: `true`

Increment `sample_count` for the technique. Ensure `reference_rule` is set under the technique entry.

---

## Adding good-pool samples

Good-pool samples are benign logs that **must stay silent** against all rules. The good pool is almost entirely generated in-house.

### 1. Capture

Stand up a representative system (DC, workstation, Linux server) with the same logging config used in production. Capture during a **known-quiet window** (no incidents, no red-team activity). Recommended minimum: 4 hours of normal activity.

Export in one of the accepted formats.

### 2. Review

Before the sample enters the corpus:

1. **Anomaly scan** — run the full bad-pool ruleset against the capture. Any hit must be investigated. Either the hit is a false positive (rule is over-broad) or the capture window was not clean. Do not add a capture with unexplained hits.
2. **PII scrub** — strip hostnames, usernames, IP addresses, and any data that shouldn't leave the capture host. Document the scrub method in `provenance.json`.

### 3. Provenance sign-off

Every good-pool source directory requires a `provenance.json`. **Unsigned samples (`signed_off: false`) are never used by the validation service.** Fill all fields:

```json
{
  "system_type": "workstation | domain_controller | linux_server | ...",
  "os": "...",
  "domain_joined": true | false,
  "logging_config": "Sysmon v14 config A | auditd ruleset v2 | ...",
  "capture_method": "live capture | snapshot | hand-crafted | ...",
  "capture_date": "YYYY-MM-DD",
  "capture_window": "HH:MM–HH:MM UTC",
  "events": <integer>,
  "format": "sysmon-json | auditd | evtx | ...",
  "pii_scrubbed": true | false,
  "scrub_method": "<description of what was stripped and how>",
  "reviewed_by": "<name or team>",
  "review_date": "YYYY-MM-DD",
  "signed_off": true,
  "notes": "..."
}
```

---

## Cutting a new corpus version

A new version is required whenever:
- New samples are added or existing samples are modified
- A sample is removed (e.g., found to be mislabeled)
- The positive-control anchors change

**Steps:**
1. Copy the previous version directory: `cp -r corpora/vOLD corpora/vNEW`
2. Make changes in `vNEW` only. Never touch `vOLD`.
3. Update `manifest.json`: bump `"version"`, update `"created"`, update changed entries, recompute `sha256` for any modified files.
4. Run the full validation smoke-test (see below) against the new version.
5. Commit the new version directory. Tag the commit `corpus-vNEW`.

**Version naming:** `vYYYY.MM.N` where N increments within the month.  
Example: `v2026.06.1` → `v2026.06.2` for a second cut in June 2026.

### Smoke-test checklist before tagging

```bash
python3 scripts/verify_corpus.py corpora/vNEW
```

(`scripts/verify_corpus.py` — to be built in Phase 5.)

The verifier must check all of the following. Run them manually until the script exists:

1. **No unverified bad-pool samples.** Every sample in `manifest.json` must have `"reference_rule_verified": true`. Any `false` or missing entry is a blocker — either verify the sample or remove it.
2. **No missing reference rules.** Every technique entry must have a `reference_rule` path that exists on disk. If `reference_rule_status` is `"MISSING — blocker"`, the technique has no samples accepted.
3. **All bad-pool samples fire their reference rule.** Re-run each sample against its technique's reference rule using the command in step 3 above. All must produce ≥1 detection.
4. **All good-pool samples stay silent** against the full bad-pool ruleset (all evaluation rules, not reference rules).
5. **All positive-control anchors fire.** Run each anchor from `manifest.json > controls` and confirm expected detection count.
6. **sha256 values match.** `shasum -a 256` each sample listed in the manifest and compare.

---

## Pinning rule + pool versions per run

Every validation run records both versions:

```json
{
  "rule_id": "07f8bdc2-c9b3-472a-9817-5a670b872f53",
  "rule_version": "2024-03-05",
  "corpus_version": "v2026.06.1",
  "zircolite_commit": "b37b51eb"
}
```

This makes runs reproducible and lets you diff verdicts across corpus or rule versions.
