# Path to First Real Verdict

**Date:** 2026-06-11  
**Status:** Planning only — nothing built yet

---

## The problem

Every sample in the corpus is currently `signed_off: false` or synthetic. The validation service can only return VOID for any real rule: either the good-pool positive-control fires (proving the engine ran) but the actual pool data is untrustworthy, or the bad-pool samples were never independently verified against real system behavior. A VOID is not a verdict. The service is fully functional; it is the corpus that blocks us.

---

## What a non-VOID verdict requires

For a single rule to produce a real PASS or FAIL, three things must be true simultaneously:

1. **Good pool**: ≥1 signed-off benign baseline that the rule stays silent on.
2. **Bad pool**: ≥3 real, reference-rule-verified samples for the rule's claimed technique.
3. **Positive control**: the anchor fixtures fire (already working — these are synthetic and permanently trusted).

The output is:
- `PASS (confirmed)` — good pool silent, bad pool ≥3 hits, control fired.
- `FAIL` — rule fires on good pool (FP confirmed).
- `VOID` — any of the above checks failed to complete cleanly.

---

## Which rule to target first

**`lnx_auditd_susp_c2_commands.yml`** (T1071.004, Linux auditd, MEDIUM)

Reason: the Linux path requires no licensed tooling, no Sysmon configuration, and can be detonated on any Linux host in minutes. The Windows alternative (`proc_creation_win_cmdkey_recon.yml`, T1003.005) has no matching sample in EVTX-ATTACK-SAMPLES — the dataset's Credential Access folder contains Mimikatz/LSASS/DCSync/Zerologon entries but no cmdkey — so Windows bad-pool samples also require a detonation VM, eliminating the "ready-made download" advantage.

The Linux rule is the fastest path. The Windows rule is the next logical target once the process is proven.

---

## Minimum corpus: Linux auditd T1071.004

### Bad pool

**Required:** 3 distinct sample events, each from a different tool, so that the 3+ coverage threshold is satisfied by independent evidence rather than three copies of the same event.

| # | Tool | auditd field | Source |
|---|------|-------------|--------|
| 1 | `curl` | `comm=curl key=susp_activity` | Detonation VM (see below) |
| 2 | `wget` | `comm=wget key=susp_activity` | Same VM |
| 3 | `nc` / `ncat` | `comm=ncat key=susp_activity` | Same VM |

These three events can come from a single 10-minute session on one Linux host. They do NOT need to represent a real intrusion — the requirement is that the events are genuine kernel-generated auditd records, not hand-crafted JSON, and that each tool is actually executed on the system.

**What "genuine" means here:** the file must be written by the Linux kernel's audit subsystem in response to a real syscall. Hand-crafted auditd lines (like the current synthetic samples) are acceptable for smoke tests but not for real verdicts — the kernel adds timing, PID, and process context that is hard to forge consistently and that real detections depend on.

**Detonation setup** (30–60 minutes, one-time):

1. Any Linux host or VM (Ubuntu/RHEL/Debian) — throwaway preferred, production acceptable if network-isolated during detonation.
2. Install the Neo23x0/auditd watchpoints for the tools the rule covers. The SIGMA rule's `definition:` field lists them exactly:
   ```
   -w /usr/bin/wget -p x -k susp_activity
   -w /usr/bin/curl -p x -k susp_activity
   -w /bin/nc -p x -k susp_activity
   -w /usr/bin/ncat -p x -k susp_activity
   (etc — full list in the rule's definition field)
   ```
   Add to `/etc/audit/rules.d/sigma-sandbox.rules`, then `auditctl -R` or reboot.
3. Run each tool once: `curl http://192.0.2.1`, `wget http://192.0.2.1`, `ncat -z 192.0.2.1 80`. The IPs don't need to connect — the kernel fires the audit event on exec, not on network success.
4. Collect: `grep 'key=susp_activity' /var/log/audit/audit.log`.
5. Verify: run Zircolite with the reference rule (`ref_auditd_susp_activity_key.yml`) — expect 3 hits.

The detonation VM can be deleted after log collection. Document which VM it was, when it ran, and that the tooling was present (auditd version, kernel version).

### Good pool

**Required:** 1 signed-off benign Linux baseline from a system with the same auditd configuration.

The good pool is what makes silence meaningful. Without it, a zero-hit result on the good pool just means the good-pool files were empty or unprocessed. With a real, signed-off baseline, a zero proves the rule didn't fire on known-normal activity.

**Minimum baseline capture:**

- System: an existing Linux server that is representative of production systems this rule would protect — same OS family, same auditd config (the Neo23x0 watchpoints), same typical workload (developer box, CI runner, sysadmin host, etc.). It does not need to be a dedicated VM; an existing system works if the conditions below are met.
- Capture window: 2 hours minimum during normal working hours. The window must be quiet: no red-team, no pen-test, no known incidents.
- What to capture: `sudo cat /var/log/audit/audit.log` (or rotate and export the current file). The full log is fine; events outside the auditd scope are harmless for the silent-test.
- Tool: nothing fancy. `ssh <host> sudo cat /var/log/audit/audit.log > good-pool/linux/server-baseline/audit.log`.

**Anomaly pre-check before sign-off** (automated, ~5 minutes):

Run the full bad-pool ruleset against the captured baseline. If any rule fires, the capture is not usable until the hit is investigated and resolved — either the rule is over-broad (FAIL, which is actually useful information) or the capture window contained suspicious activity and needs to be recaptured.

```bash
source venv/bin/activate
python scanner/zircolite/zircolite.py \
  --events good-pool/linux/server-baseline/audit.log \
  --ruleset rules/samples/linux/ \
  --config scanner/zircolite/config/config.yaml \
  --auditd --nolog
```

---

## Provenance sign-off: what it requires from a human

### Bad pool sign-off

**Who:** the person who ran the detonation — detection engineer or security analyst.

**What they do:**

1. Confirm the tools were actually executed (check shell history or process list during the run).
2. Confirm the auditd watchpoints were active before execution (show `auditctl -l` output at time of run).
3. Verify reference rule fires (automated — `ref_auditd_susp_activity_key.yml` ≥3 hits).
4. Fill provenance fields in `manifest.json`: source, detonation host, date, auditd config version used.

**Time:** ~15 minutes after the detonation session.  
**No external approval needed** — this is a self-contained technical verification.

### Good pool sign-off

**Who:** a security analyst or detection engineer who has visibility into the source system's security posture — specifically someone who can answer "was anything unusual happening on this host during that 2-hour window?"

This is the harder of the two. It requires:

1. **Incident confirmation**: check SIEM/EDR/SOAR for the host during the capture window. Confirm no open alerts, no active investigations. This step cannot be skipped or delegated to someone without security monitoring access.
2. **Anomaly scan review**: run Zircolite against the capture (above). Review any hits. Determine if each hit is a false positive from an over-broad rule (document it) or actual suspicious activity (recapture).
3. **PII review**: scan for hostnames, usernames, IP addresses that should not leave the environment. For auditd logs, `comm=` values (process names) and `exe=` paths are usually safe; `uid=`, `auid=`, and `ses=` fields may need scrubbing if they map to real employee UIDs. Minimal scrub for initial use: replace real UIDs with synthetic ones (`uid=1001` → `uid=9001`), replace real hostnames with generic labels.
4. **Sign provenance.json**: set `signed_off: true`, fill `reviewed_by` (name or team), `review_date`, `capture_date`, `capture_window`, `pii_scrubbed: true`, `scrub_method`.

**Time:** 1–2 hours total, mostly waiting for SIEM queries and reviewing anomaly scan hits.  
**Blocker:** whoever does this needs SIEM/EDR read access and needs to know the host.

---

## Samples first or service first?

**Samples first.**

Reasons:

1. **The service can only be tested with real samples.** Building it against synthetic fixtures proves the code runs but does not prove it produces trustworthy verdicts. The first integration test that matters requires real data.

2. **The bad-pool detonation and good-pool capture teach you what to automate.** The manual run through Zircolite, the anomaly scan, and the provenance fill are exactly what the service needs to replicate. Doing it once by hand before building the service avoids designing automation for a process you haven't actually run.

3. **Good-pool sign-off has an irreducible human step.** Someone must confirm no incidents occurred during the capture window. That requires SIEM access and judgment, and the service cannot replace it. Designing the service first risks building around an assumption (that sign-off is easy) that turns out not to be.

4. **If samples are hard to get, that blocks everything.** If getting a 2-hour clean Linux capture turns out to require three approvals and a change request, that is a sequencing constraint the service has no way to paper over. Better to learn that now, before the service is built.

The right order: run the Linux detonation → capture a clean baseline → do the manual Zircolite run to confirm the first real verdict → then build the service to automate what you just did by hand.

---

## Effort estimate

| Step | Owner | Estimated time |
|------|-------|---------------|
| Configure auditd watchpoints on detonation VM | Detection engineer | 30 min |
| Run detonation (curl, wget, nc) and collect logs | Detection engineer | 15 min |
| Verify reference rule fires | Detection engineer (automated) | 5 min |
| Fill bad-pool manifest entries | Detection engineer | 15 min |
| Capture 2-hour clean Linux baseline | Anyone with SSH access | 2 hr (passive) |
| Run anomaly scan on baseline | Detection engineer | 10 min |
| SIEM/EDR incident check for capture window | Security analyst | 20 min |
| PII scrub and provenance.json sign-off | Security analyst | 30 min |
| Manual first-run: Zircolite good pool + bad pool | Detection engineer | 15 min |
| **Total active work** | | **~2.5 hours** |
| **Total elapsed (with 2-hr capture window)** | | **~4 hours** |

The 2-hour baseline capture is passive — it runs while the rest of the work happens.
