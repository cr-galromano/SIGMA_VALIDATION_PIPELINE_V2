# Reference Rules

Rules in this directory are **acceptance-gate rules only**. They are never evaluated by the validation service.

## Purpose

When a new bad-pool sample is submitted, it must fire against its technique's reference rule before it is accepted into the corpus. This ensures corpus integrity is independent of any specific evaluation rule — a sample proves it represents the claimed technique regardless of which rule is later tested against it.

## Policy

- **Never submit a rule in `rules/reference/` for evaluation.** If a reference rule ends up in the evaluation queue, every sample that was accepted using that rule becomes circularly dependent on it.
- Reference rules are **intentionally broad** — they catch any genuine instance of the technique, not specific behaviors. They would likely produce false positives in production. That is expected; they are not detection rules.
- Reference rules are **stable**. Change them only when the technique's detection surface fundamentally changes, and only after re-verifying all existing samples for the affected technique.
- Each rule must have a valid UUID `id` and `status: stable`.

## Current reference rules

| Technique | Rule | Fires on |
|-----------|------|----------|
| T1003.005 | `windows/T1003.005/ref_cmdkey_any_execution.yml` | Any `cmdkey.exe` execution |
| T1059.001 | `windows/T1059.001/ref_powershell_encoded_flag.yml` | PowerShell with any `-e`/`-enc` flag |
| T1071.004 | `linux/T1071.004/ref_auditd_susp_activity_key.yml` | Any auditd event with `key=susp_activity` |

## Gaps (blockers)

| Platform | Technique | Format | Status |
|----------|-----------|--------|--------|
| Linux | T1071.004 | Sysmon-for-Linux | **MISSING** — `sysmon_linux_c2_curl.log` cannot be accepted until this is written |

A gap means the corresponding bad-pool sample has `"reference_rule_verified": false` in `manifest.json`. That sample is excluded from all validation runs until the gap is resolved.
