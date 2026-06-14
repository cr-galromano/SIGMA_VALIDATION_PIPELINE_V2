#!/usr/bin/env bash
# SVP — Linux good-pool baseline capture
#
# Runs on a Linux host with auditd installed. Must be run as root.
# Captures all auditd events over a specified window and writes them to a file.
# The same auditd watchpoints used for bad-pool detonation MUST be active during
# the capture — a good-pool sample is only valid if it was collected under the
# same logging config as the bad pool.
#
# Usage:
#   sudo bash capture_good_pool.sh [duration_minutes]
#
# Default duration: 120 minutes (2 hours).
# For a quick test: sudo bash capture_good_pool.sh 5
#
# Output:
#   good_pool_YYYYMMDD_HHMMSS.log   — all auditd events in the window
#   good_pool_YYYYMMDD_HHMMSS.meta  — provenance template

set -euo pipefail

DURATION_MINUTES=${1:-120}

# ---------- guards ----------
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root (sudo bash $0)" >&2
  exit 1
fi

if ! systemctl is-active --quiet auditd 2>/dev/null; then
  if ! service auditd status >/dev/null 2>&1; then
    echo "ERROR: auditd is not running." >&2
    exit 1
  fi
fi

AUDIT_LOG=/var/log/audit/audit.log
if [[ ! -f "$AUDIT_LOG" ]]; then
  echo "ERROR: $AUDIT_LOG not found." >&2
  exit 1
fi

# ---------- verify watchpoints are active ----------
echo "[1/3] Verifying susp_activity watchpoints are loaded..."

if ! auditctl -l 2>/dev/null | grep -q 'susp_activity'; then
  echo ""
  echo "WARNING: No susp_activity watchpoints detected in the active auditd ruleset."
  echo "The good-pool capture MUST use the same logging config as the bad-pool detonation."
  echo ""
  echo "Run detonate_t1071004.sh first (it installs the watchpoints), or load them manually:"
  echo "  sudo auditctl -R /etc/audit/rules.d/svp_susp_activity.rules"
  echo ""
  read -r -p "Continue anyway? (y/N) " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    exit 1
  fi
fi

# ---------- capture ----------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_LOG="good_pool_${TIMESTAMP}.log"
OUTPUT_META="good_pool_${TIMESTAMP}.meta"

BEFORE=$(wc -l < "$AUDIT_LOG")
START_TIME=$(date -u +"%H:%M UTC")
START_DATE=$(date +%Y-%m-%d)
OS_INFO=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -rs)
HOSTNAME_VAL=$(hostname)

echo "[2/3] Capturing for ${DURATION_MINUTES} minutes (started $START_TIME)..."
echo "      This window must be incident-free. Do not run any C2 tools during capture."
echo "      Press Ctrl+C to abort."

sleep "$((DURATION_MINUTES * 60))"

END_TIME=$(date -u +"%H:%M UTC")

# ---------- extract ----------
echo "[3/3] Extracting events..."

tail -n +"$((BEFORE + 1))" "$AUDIT_LOG" > "$OUTPUT_LOG" || true

EVENT_COUNT=$(wc -l < "$OUTPUT_LOG")

if [[ "$EVENT_COUNT" -eq 0 ]]; then
  echo "WARNING: No auditd events captured in this window. The host may be very quiet or auditd may not be logging."
  echo "File is empty: $OUTPUT_LOG"
fi

echo "  Captured $EVENT_COUNT event(s)"

# Write provenance template
cat > "$OUTPUT_META" <<EOF
# SVP — good-pool provenance (fill in blanks before running ingest_sample.sh)
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

FILE:         $OUTPUT_LOG
POOL:         good
PLATFORM:     linux
FORMAT:       auditd
EVENTS:       $EVENT_COUNT

HOST:         $HOSTNAME_VAL
OS:           $OS_INFO
DOMAIN_JOINED: __FILL_IN__  (true/false)
LOGGING_CONFIG: Neo23x0 auditd watchpoints (svp_susp_activity.rules)
CAPTURE_DATE: $START_DATE
CAPTURE_WINDOW: $START_TIME–$END_TIME

# Before signing off, review the captured log:
#   1. Run the bad-pool evaluation ruleset against it — any hit must be investigated
#   2. Check for PII: hostnames, usernames, IPs that shouldn't leave this host
#   3. Confirm no incidents or red-team activity occurred in this window

# Security analyst sign-off (confirms window was clean and PII-scrubbed):
REVIEWED_BY:    __FILL_IN__
REVIEW_DATE:    __FILL_IN__
PII_SCRUB_METHOD: __FILL_IN__  (e.g. "no PII in SYSCALL records; auid= UIDs left as-is")
NOTES:          __FILL_IN__  (or "none")
EOF

echo ""
echo "Done."
echo ""
echo "  Events file : $OUTPUT_LOG"
echo "  Provenance  : $OUTPUT_META"
echo ""
echo "Before running ingest:"
echo "  1. Anomaly scan: run Zircolite against $OUTPUT_LOG with the full bad-pool ruleset"
echo "     Any hit = investigate before proceeding"
echo "  2. PII review: scan $OUTPUT_LOG for hostnames, usernames, IP addresses"
echo "  3. Fill in $OUTPUT_META (REVIEWED_BY, REVIEW_DATE, etc.)"
echo "  4. scp $OUTPUT_LOG $OUTPUT_META <svp-machine>:/path/to/SVP/scripts/"
echo "  5. On SVP machine: bash scripts/ingest_sample.sh --good-pool $OUTPUT_LOG $OUTPUT_META"
