#!/usr/bin/env bash
# SVP — T1071.004 bad-pool detonation capture
#
# Runs on a Linux host with auditd installed. Must be run as root.
# Adds Neo23x0 watchpoints for C2 tools, executes them against a non-routable
# address (RFC 5737 TEST-NET — will never connect), captures the resulting
# auditd records, and writes them to a timestamped .log file.
#
# Usage:
#   sudo bash detonate_t1071004.sh
#
# Output:
#   detonation_YYYYMMDD_HHMMSS.log   — auditd records to copy back to the SVP machine
#   detonation_YYYYMMDD_HHMMSS.meta  — pre-filled provenance fields (fill in blanks)

set -euo pipefail

# ---------- guards ----------
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root (sudo bash $0)" >&2
  exit 1
fi

if ! systemctl is-active --quiet auditd 2>/dev/null; then
  if ! service auditd status >/dev/null 2>&1; then
    echo "ERROR: auditd is not running. Install and start it first:" >&2
    echo "  apt install auditd  (Debian/Ubuntu)" >&2
    echo "  yum install audit   (RHEL/CentOS)" >&2
    echo "  systemctl start auditd" >&2
    exit 1
  fi
fi

AUDIT_LOG=/var/log/audit/audit.log
if [[ ! -f "$AUDIT_LOG" ]]; then
  echo "ERROR: $AUDIT_LOG not found. Is auditd configured to write there?" >&2
  exit 1
fi

# ---------- set up watchpoints ----------
RULES_FILE=/etc/audit/rules.d/svp_susp_activity.rules

echo "[1/4] Installing Neo23x0 C2-tool watchpoints..."

cat > "$RULES_FILE" <<'EOF'
# SVP — C2 tool watchpoints (Neo23x0 auditd best-practice subset for T1071.004)
-w /usr/bin/wget -p x -k susp_activity
-w /usr/bin/curl -p x -k susp_activity
-w /usr/bin/base64 -p x -k susp_activity
-w /bin/nc -p x -k susp_activity
-w /bin/netcat -p x -k susp_activity
-w /usr/bin/ncat -p x -k susp_activity
-w /usr/bin/ss -p x -k susp_activity
-w /usr/bin/ssh -p x -k susp_activity
-w /usr/bin/socat -p x -k susp_activity
-w /usr/bin/nmap -p x -k susp_activity
EOF

# Reload rules
if command -v augenrules &>/dev/null; then
  augenrules --load >/dev/null 2>&1
elif command -v auditctl &>/dev/null; then
  auditctl -R "$RULES_FILE" >/dev/null 2>&1
else
  echo "WARNING: cannot reload auditd rules automatically. Restart auditd manually if watchpoints were not previously active." >&2
fi

sleep 1  # let rules settle

# ---------- detonation ----------
echo "[2/4] Running detonation commands..."

# Record current line count so we can extract only the new events
BEFORE=$(wc -l < "$AUDIT_LOG")

# RFC 5737 TEST-NET addresses — will never route or connect
# Tools are expected to fail (connection refused / timeout) — that is fine.
# The auditd watchpoint fires on exec, not on successful connection.

TOOLS_RUN=()

if command -v curl &>/dev/null; then
  curl --max-time 2 --silent http://192.0.2.1/svp-test 2>/dev/null || true
  TOOLS_RUN+=("curl")
else
  echo "  SKIP: curl not found"
fi

if command -v wget &>/dev/null; then
  wget --timeout=2 --quiet -O /dev/null http://192.0.2.2/svp-test 2>/dev/null || true
  TOOLS_RUN+=("wget")
else
  echo "  SKIP: wget not found"
fi

if command -v base64 &>/dev/null; then
  echo "svp-detonation-marker" | base64 > /dev/null 2>&1 || true
  TOOLS_RUN+=("base64")
else
  echo "  SKIP: base64 not found"
fi

for NC_BIN in /bin/nc /bin/netcat /usr/bin/nc /usr/bin/netcat; do
  if [[ -x "$NC_BIN" ]]; then
    timeout 2 "$NC_BIN" -w 1 192.0.2.3 4444 < /dev/null 2>/dev/null || true
    TOOLS_RUN+=("nc")
    break
  fi
done
if [[ ! " ${TOOLS_RUN[*]} " =~ " nc " ]]; then
  echo "  SKIP: nc/netcat not found"
fi

if command -v ncat &>/dev/null; then
  ncat --send-only --idle-timeout 1 192.0.2.4 4444 < /dev/null 2>/dev/null || true
  TOOLS_RUN+=("ncat")
else
  echo "  SKIP: ncat not found"
fi

if command -v socat &>/dev/null; then
  socat - TCP:192.0.2.5:4444,connect-timeout=2 < /dev/null 2>/dev/null || true
  TOOLS_RUN+=("socat")
else
  echo "  SKIP: socat not found"
fi

sleep 1  # let auditd flush

# ---------- extract events ----------
echo "[3/4] Extracting captured events..."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_LOG="detonation_${TIMESTAMP}.log"
OUTPUT_META="detonation_${TIMESTAMP}.meta"

# Take only lines added during detonation, filter to susp_activity events
tail -n +"$((BEFORE + 1))" "$AUDIT_LOG" | grep 'key=susp_activity' > "$OUTPUT_LOG" || true

EVENT_COUNT=$(wc -l < "$OUTPUT_LOG")

if [[ "$EVENT_COUNT" -eq 0 ]]; then
  echo ""
  echo "ERROR: No susp_activity events captured. Possible causes:" >&2
  echo "  - None of the target tools were found on this system" >&2
  echo "  - Watchpoints were not loaded before detonation (try re-running)" >&2
  echo "  - auditd is not writing to $AUDIT_LOG" >&2
  echo "  - auditd buffer overflowed (check: auditctl -s)" >&2
  echo "" >&2
  echo "Tools that ran: ${TOOLS_RUN[*]:-none}" >&2
  exit 1
fi

echo "  Captured $EVENT_COUNT event(s) from: ${TOOLS_RUN[*]}"

# ---------- provenance template ----------
OS_INFO=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -rs)
HOSTNAME_VAL=$(hostname)
CAPTURE_DATE=$(date +%Y-%m-%d)

cat > "$OUTPUT_META" <<EOF
# SVP — bad-pool provenance (fill in blanks before running ingest_sample.sh)
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

FILE:        $OUTPUT_LOG
TECHNIQUE:   T1071.004
PLATFORM:    linux
FORMAT:      auditd
SOURCE:      detonation
EVENTS:      $EVENT_COUNT
TOOLS_RUN:   ${TOOLS_RUN[*]}

HOST:        $HOSTNAME_VAL
OS:          $OS_INFO
CAPTURE_DATE: $CAPTURE_DATE

# Detonation sign-off (engineer who ran this script):
SIGNED_OFF_BY:   __FILL_IN__
SIGN_OFF_DATE:   $CAPTURE_DATE

# PII scrub — review the .log file and redact before copying to SVP:
#   - Replace real IPs/hostnames in comm= and exe= fields if needed
#   - auid= values are UID numbers, acceptable to leave as-is
#   - No usernames appear in SYSCALL records, but check EXECVE records if present
PII_SCRUB_METHOD: __FILL_IN__  (e.g. "UID numbers left as-is; no hostnames in SYSCALL records")
EOF

echo ""
echo "[4/4] Done."
echo ""
echo "  Events file : $OUTPUT_LOG"
echo "  Provenance  : $OUTPUT_META"
echo ""
echo "Next steps:"
echo "  1. cat $OUTPUT_LOG        — review the captured events"
echo "  2. Edit $OUTPUT_META      — fill in SIGNED_OFF_BY and PII_SCRUB_METHOD"
echo "  3. scp $OUTPUT_LOG $OUTPUT_META  <svp-machine>:/path/to/SVP/scripts/"
echo "  4. On SVP machine: bash scripts/ingest_sample.sh $OUTPUT_LOG $OUTPUT_META"
