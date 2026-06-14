#!/usr/bin/env bash
# SVP — sample ingest script
#
# Runs on the SVP machine after copying captured files back from the Linux host.
# For bad-pool samples: verifies the reference rule fires, then adds to corpus.
# For good-pool samples: copies to corpus, updates provenance.json.
# Updates manifest.json in both cases.
#
# Usage:
#   # Bad pool (detonation capture):
#   bash scripts/ingest_sample.sh detonation_20260614_120000.log detonation_20260614_120000.meta
#
#   # Good pool (baseline capture):
#   bash scripts/ingest_sample.sh --good-pool good_pool_20260614_120000.log good_pool_20260614_120000.meta

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SVP_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# ---------- parse args ----------
GOOD_POOL=false
if [[ "${1:-}" == "--good-pool" ]]; then
  GOOD_POOL=true
  shift
fi

if [[ $# -ne 2 ]]; then
  echo "Usage: bash ingest_sample.sh [--good-pool] <sample.log> <sample.meta>" >&2
  exit 1
fi

SAMPLE_FILE=$(realpath "$1")
META_FILE=$(realpath "$2")

for f in "$SAMPLE_FILE" "$META_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: not found: $f" >&2
    exit 1
  fi
done

# ---------- helpers ----------
read_meta() {
  grep -E "^$1:" "$META_FILE" | head -1 | sed "s/^$1:[[:space:]]*//" | sed 's/[[:space:]]*#.*//' | xargs
}

require_meta() {
  local val
  val=$(read_meta "$1")
  if [[ -z "$val" || "$val" == "__FILL_IN__" ]]; then
    echo "ERROR: $META_FILE is missing required field: $1" >&2
    echo "  Fill it in and re-run." >&2
    exit 1
  fi
  echo "$val"
}

# ---------- read meta ----------
echo "[1/5] Reading provenance metadata..."

EVENTS=$(read_meta "EVENTS")
CAPTURE_DATE=$(read_meta "CAPTURE_DATE")
OS_INFO=$(read_meta "OS")
HOSTNAME_VAL=$(read_meta "HOST")
LOGGING_CONFIG=$(read_meta "LOGGING_CONFIG")
PII_SCRUB=$(read_meta "PII_SCRUB_METHOD")

if $GOOD_POOL; then
  REVIEWED_BY=$(require_meta "REVIEWED_BY")
  REVIEW_DATE=$(require_meta "REVIEW_DATE")
  CAPTURE_WINDOW=$(read_meta "CAPTURE_WINDOW")
  DOMAIN_JOINED=$(read_meta "DOMAIN_JOINED")
else
  TECHNIQUE=$(require_meta "TECHNIQUE")
  TOOLS_RUN=$(read_meta "TOOLS_RUN")
  SIGNED_OFF_BY=$(require_meta "SIGNED_OFF_BY")
  SIGN_OFF_DATE=$(require_meta "SIGN_OFF_DATE")
fi

if [[ "$PII_SCRUB" == "__FILL_IN__" || -z "$PII_SCRUB" ]]; then
  echo "ERROR: PII_SCRUB_METHOD not filled in. Review the log for PII before ingesting." >&2
  exit 1
fi

# ---------- compute sha256 ----------
echo "[2/5] Computing SHA-256..."
SHA256=$(shasum -a 256 "$SAMPLE_FILE" | awk '{print $1}')
echo "  $SHA256"

# ---------- activate venv ----------
VENV="$SVP_ROOT/venv"
if [[ ! -f "$VENV/bin/activate" ]]; then
  echo "ERROR: venv not found at $VENV. Run: python3 -m venv venv && pip install -r scanner/zircolite/requirements.txt" >&2
  exit 1
fi
source "$VENV/bin/activate"

if $GOOD_POOL; then
  # ---------- good-pool: anomaly scan ----------
  echo "[3/5] Anomaly scan (running bad-pool evaluation ruleset against good-pool capture)..."

  LINUX_RULES=$(find "$SVP_ROOT/rules/samples/linux" -name "*.yml" | tr '\n' ' ')
  if [[ -z "$LINUX_RULES" ]]; then
    echo "  WARNING: no linux evaluation rules found in rules/samples/linux/ — skipping anomaly scan"
  else
    ANOMALY_OUTPUT=$(python "$SVP_ROOT/scanner/zircolite/zircolite.py" \
      --events "$SAMPLE_FILE" \
      --ruleset $LINUX_RULES \
      --config "$SVP_ROOT/scanner/zircolite/config/config.yaml" \
      --auditd --nolog 2>&1 || true)

    HIT_COUNT=$(echo "$ANOMALY_OUTPUT" | grep -c '"count"' 2>/dev/null || echo "0")
    if echo "$ANOMALY_OUTPUT" | grep -q '"count"'; then
      echo ""
      echo "ERROR: Anomaly scan found hits in the good-pool capture:" >&2
      echo "$ANOMALY_OUTPUT" >&2
      echo "" >&2
      echo "Investigate each hit before ingesting. The capture window may not have been clean." >&2
      exit 1
    fi
    echo "  Clean — no evaluation-rule hits."
  fi

  # ---------- copy to corpus ----------
  echo "[4/5] Copying to corpus..."

  CORPUS_VERSION="v2026.06.1"
  DEST_DIR="$SVP_ROOT/corpora/$CORPUS_VERSION/good-pool/linux/server-baseline-real"
  mkdir -p "$DEST_DIR"

  DEST_FILE="$DEST_DIR/audit.log"
  cp "$SAMPLE_FILE" "$DEST_FILE"
  echo "  Copied to $DEST_FILE"

  # Write provenance.json
  cat > "$DEST_DIR/provenance.json" <<EOF
{
  "system_type": "linux-server",
  "os": "$OS_INFO",
  "domain_joined": $DOMAIN_JOINED,
  "logging_config": "$LOGGING_CONFIG",
  "capture_method": "live capture",
  "capture_date": "$CAPTURE_DATE",
  "capture_window": "$CAPTURE_WINDOW",
  "events": $EVENTS,
  "format": "auditd",
  "pii_scrubbed": true,
  "scrub_method": "$PII_SCRUB",
  "reviewed_by": "$REVIEWED_BY",
  "review_date": "$REVIEW_DATE",
  "signed_off": true,
  "notes": "Real capture replacing synthetic server-baseline. Same Neo23x0 watchpoints active as bad-pool detonation."
}
EOF
  echo "  Wrote provenance.json (signed_off: true)"

  # ---------- update manifest ----------
  echo "[5/5] Updating manifest.json..."

  MANIFEST="$SVP_ROOT/corpora/$CORPUS_VERSION/manifest.json"
  python3 - "$MANIFEST" "$CORPUS_VERSION" "$EVENTS" "good-pool/linux/server-baseline-real" <<'PYEOF'
import sys, json
manifest_path, version, events, source_dir = sys.argv[1:]
with open(manifest_path) as f:
    m = json.load(f)
new_entry = {
    "source_dir": source_dir,
    "system_type": "linux-server",
    "format": "auditd",
    "events": int(events),
    "provenance": source_dir + "/provenance.json"
}
linux_pool = m["good_pool"]["linux"]
# Replace synthetic entry if present, else append
linux_pool = [e for e in linux_pool if e.get("source_dir") != source_dir]
linux_pool.append(new_entry)
m["good_pool"]["linux"] = linux_pool
with open(manifest_path, "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
print("  manifest.json updated")
PYEOF

else
  # ---------- bad-pool: reference rule verification ----------
  echo "[3/5] Verifying reference rule fires..."

  REF_RULE="$SVP_ROOT/rules/reference/linux/T1071.004/ref_auditd_susp_activity_key.yml"
  if [[ ! -f "$REF_RULE" ]]; then
    echo "ERROR: reference rule not found: $REF_RULE" >&2
    exit 1
  fi

  ZIRCOLITE_OUTPUT=$(python "$SVP_ROOT/scanner/zircolite/zircolite.py" \
    --events "$SAMPLE_FILE" \
    --ruleset "$REF_RULE" \
    --config "$SVP_ROOT/scanner/zircolite/config/config.yaml" \
    --auditd --nolog 2>&1 || true)

  if ! echo "$ZIRCOLITE_OUTPUT" | grep -q '"count"'; then
    echo ""
    echo "ERROR: reference rule produced zero detections on this sample." >&2
    echo "The sample does not represent T1071.004 or is in the wrong format." >&2
    echo "" >&2
    echo "Zircolite output:" >&2
    echo "$ZIRCOLITE_OUTPUT" >&2
    exit 1
  fi

  DET_COUNT=$(echo "$ZIRCOLITE_OUTPUT" | python3 -c "
import sys, json, re
text = sys.stdin.read()
counts = re.findall(r'\"count\":\s*(\d+)', text)
print(sum(int(c) for c in counts))
" 2>/dev/null || echo "?")
  echo "  Reference rule fired: $DET_COUNT detection(s). Sample accepted."

  # ---------- copy to corpus ----------
  echo "[4/5] Copying to corpus..."

  CORPUS_VERSION="v2026.06.1"
  DEST_DIR="$SVP_ROOT/corpora/$CORPUS_VERSION/bad-pool/linux/T1071.004"
  mkdir -p "$DEST_DIR"

  SAMPLE_BASENAME=$(basename "$SAMPLE_FILE")
  DEST_FILE="$DEST_DIR/$SAMPLE_BASENAME"
  cp "$SAMPLE_FILE" "$DEST_FILE"
  echo "  Copied to $DEST_FILE"

  # ---------- update manifest ----------
  echo "[5/5] Updating manifest.json..."

  MANIFEST="$SVP_ROOT/corpora/$CORPUS_VERSION/manifest.json"
  REL_PATH="bad-pool/linux/T1071.004/$SAMPLE_BASENAME"

  python3 - "$MANIFEST" "$REL_PATH" "$EVENTS" "$SHA256" "$TOOLS_RUN" "$CAPTURE_DATE" <<'PYEOF'
import sys, json
manifest_path, rel_path, events, sha256, tools_run, capture_date = sys.argv[1:]
with open(manifest_path) as f:
    m = json.load(f)
new_sample = {
    "file": rel_path,
    "source": "detonation",
    "events": int(events),
    "description": "Real detonation capture: " + tools_run + " via exec watchpoints (key=susp_activity)",
    "capture_date": capture_date,
    "reference_rule_verified": True,
    "sha256": sha256
}
technique = m["bad_pool"]["linux"]["T1071.004"]
# Remove any existing entry for this file path
technique["samples"] = [s for s in technique["samples"] if s.get("file") != rel_path]
technique["samples"].append(new_sample)
technique["sample_count"] = len(technique["samples"])
with open(manifest_path, "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
print("  manifest.json updated")
PYEOF

fi

echo ""
echo "Ingest complete."
echo "  Corpus version : $CORPUS_VERSION"
echo "  SHA-256        : $SHA256"
echo ""
if $GOOD_POOL; then
  echo "Next: run the bad-pool detonation for T1071.004, then the first real verdict will be possible."
else
  echo "Next: run capture_good_pool.sh on the same host, get it signed off, then run ingest_sample.sh --good-pool."
fi
