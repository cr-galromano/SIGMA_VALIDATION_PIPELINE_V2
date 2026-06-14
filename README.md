# SIGMA Validation Pipeline (SVP)

A firing range for SIGMA detection rules. Before a rule ships from the SigmaHQ hub, it must pass two tests: **silence on benign logs** (good pool) and **fire on malicious logs** (bad pool). The verdict is `PASS`, `FAIL`, or `VOID` — zero detections never auto-passes.

**Evaluation engine:** [Zircolite v3.7.6](https://github.com/wagga40/Zircolite) — runs native SIGMA YAML directly, no rule conversion.

---

## Architecture

```
SVP/
├── scanner/zircolite/      # Pinned Zircolite v3.7.6 (git submodule)
├── corpora/                # Versioned, immutable test datasets
│   └── v2026.06.1/
│       ├── bad-pool/       # Malicious samples, organized by ATT&CK technique
│       ├── good-pool/      # Benign baselines
│       └── manifest.json   # technique → samples → provenance index
├── rules/
│   ├── reference/          # Acceptance-gate rules (broad, never evaluated)
│   └── samples/            # Evaluation rules (what gets validated)
├── controls/               # Positive-control anchor fixtures
├── reports/                # Validation run reports
└── scripts/                # Validation service (Phase 2, not yet implemented)
```

### Verdict logic

| Test | Condition | Outcome |
|------|-----------|---------|
| Good pool | Any detection hit | **FAIL** — rule fires on benign logs |
| Good pool | No hits | Silence confirmed |
| Bad pool | ≥ 3 distinct-sample hits | **PASS** |
| Bad pool | < 3 hits (when corpus ≥ 3) | **FAIL** — insufficient coverage |
| Positive control | rules-loaded = 0, events-processed = 0, or anchor doesn't fire | **VOID** — broken run, result discarded |

### Log sources covered

| Platform | Format |
|----------|--------|
| Windows | EVTX, Sysmon JSON |
| Linux | auditd text |
| Linux | Sysmon-for-Linux |

Cloud/network sources (AWS CloudTrail, Azure, Zeek, etc.) are deferred to Phase 4.

---

## Setup

**Requirements:** Python 3.14, git

```bash
git clone --recurse-submodules https://github.com/cr-galromano/SIGMA_VALIDATION_PIPELINE.git
cd SIGMA_VALIDATION_PIPELINE

python -m venv venv
source venv/bin/activate
pip install -r scanner/zircolite/requirements.txt
```

---

## Running a test

```bash
source venv/bin/activate

# Windows — Sysmon JSON
python scanner/zircolite/zircolite.py \
  --events corpora/v2026.06.1/bad-pool/windows/T1003.005/cmdkey_list.json \
  --ruleset rules/samples/windows/proc_creation_win_cmdkey_recon.yml \
  --config scanner/zircolite/config/config.yaml \
  --pipeline sysmon --pipeline windows-logsources \
  --nolog

# Linux — auditd
python scanner/zircolite/zircolite.py \
  --events corpora/v2026.06.1/bad-pool/linux/T1071.004/auditd_c2_curl_wget_nc.log \
  --ruleset rules/samples/linux/lnx_auditd_susp_c2_commands.yml \
  --config scanner/zircolite/config/config.yaml \
  --auditd --nolog
```

---

## Corpora

Corpora are **versioned and immutable once signed off**. Each sample must:

1. Fire against the technique's **reference rule** (acceptance gate — broad, stable, never evaluated)
2. Have a `provenance.json` with `signed_off: true` before it can produce a non-VOID verdict

See [corpora/CONTRIBUTING.md](corpora/CONTRIBUTING.md) for the full intake SOP.

### Reference rules vs. evaluation rules

- **Reference rules** (`rules/reference/`) — intentionally broad; used only to verify that bad-pool samples are real. Never submitted to validation. This prevents circular logic (rule passes because it fires on a sample that was accepted because the same rule fires on it).
- **Evaluation rules** (`rules/samples/`) — what gets validated against the pools.

---

## Roadmap

| Phase | Goal | Status |
|-------|------|--------|
| 0 | Prove end-to-end loop (SIGMA ingestion + verdict model + positive controls) | ✅ Complete |
| 1 | Corpora foundation — versioned pools with provenance | ⏳ Waiting on real signed-off samples |
| 2 | Validation service — CLI: rule in → PASS/FAIL/VOID out | 🔲 Not started |
| 3 | Untagged rule handling + AI suggestion module | 🔲 Not started |
| 4 | Hub API integration | 🔲 Not started |
| 5 | Hardening & scale (Atomic Red Team, coverage dashboard) | 🔲 Not started |

**Current blocker (Phase 1):** All corpus samples are synthetic (`signed_off: false`). The service returns VOID until real, detonation-captured samples exist with a signed-off provenance.

---

## Key design decisions

- **No Zircolite fork** — pinned as a submodule at v3.7.6 for reproducibility
- **Native SIGMA YAML only** — no conversion to Splunk/Elastic/QRadar formats; SIGMA is the universal language
- **Zero detections ≠ PASS** — every run requires positive-control checks before trusting silence
- **On-premises deployment** — logs never leave the network; parallel workers for throughput
- **Immutable corpora** — new version tag for any sample change; prior runs remain reproducible
