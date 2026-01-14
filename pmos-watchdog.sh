#!/usr/bin/env bash
# pmos_watchdog.sh
# v1.3.2d companion watchdog: capture → analyze → compare → stuck detect → early stop

set -euo pipefail

TOOL="${TOOL:-./pmos-port-assist.py}"
PROJECT="${PROJECT:-pmos_session}"
SESSION_DIR="${SESSION_DIR:-.}"

MAX_REBOOTS="${MAX_REBOOTS:-20}"
TIMEOUT_MIN="${TIMEOUT_MIN:-15}"
TIMEOUT_ABORT_N="${TIMEOUT_ABORT_N:-3}"
STABLE_N="${STABLE_N:-3}"

SAFE_FLAGS="${SAFE_FLAGS:---safe --json}"
EXTRA_TOOL_FLAGS="${EXTRA_TOOL_FLAGS:---timeline}"   # enable timeline by default
EXTRA_CAPTURE="${EXTRA_CAPTURE:-1}"

SERIAL="${SERIAL:-}"

# Optional live heartbeat monitor:
#   PULSE=1  -> start pulse in background (default uses adb dmesg -w pipe)
#   PULSE_MODE=file -> tail project latest boot log (not truly live unless something appends)
PULSE="${PULSE:-0}"
PULSE_MODE="${PULSE_MODE:-adb}"   # adb|file
PULSE_AUTOSTOP="${PULSE_AUTOSTOP:-1}"

adb_cmd() {
  if [[ -n "$SERIAL" ]]; then
    adb -s "$SERIAL" "$@"
  else
    adb "$@"
  fi
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

base_dir="$SESSION_DIR/$PROJECT"
runs_dir="$base_dir/runs"
mkdir -p "$runs_dir"

timeout_count="${timeout_count:-0}"
stable_count=0
last_hash_file="$base_dir/.last_diff_hash"

pulse_pid=""
cleanup() {
  if [[ -n "$pulse_pid" ]]; then
    kill "$pulse_pid" 2>/dev/null || true
    wait "$pulse_pid" 2>/dev/null || true
    pulse_pid=""
  fi
}
trap cleanup EXIT

wait_online() {
  if timeout "${TIMEOUT_MIN}m" adb_cmd wait-for-device >/dev/null 2>&1; then
    timeout_count=0
    return 0
  fi
  timeout_count=$((timeout_count + 1))
  echo "WARNING: device did not appear within ${TIMEOUT_MIN} minutes ($timeout_count/${TIMEOUT_ABORT_N})"
  if [[ "$timeout_count" -ge "$TIMEOUT_ABORT_N" ]]; then
    echo "ABORT: device failed to appear ${TIMEOUT_ABORT_N} times in a row"
    exit 1
  fi
  return 1
}

check_responsive() {
  local max_tries=5
  local try=0
  while [[ $try -lt $max_tries ]]; do
    if adb_cmd shell echo "ping" 2>/dev/null | grep -q "ping"; then
      return 0
    fi
    try=$((try + 1))
    sleep 2
  done
  echo "WARNING: Device not responding to shell commands"
  return 1
}

capture_state() {
  local out_dir="$1"
  local log_file="$out_dir/capture.log"
  mkdir -p "$out_dir"
  echo "Starting capture at $(date)" > "$log_file"

  if adb_cmd shell dmesg > "$out_dir/dmesg.txt" 2>&1; then
    echo "OK: dmesg ($(wc -l < "$out_dir/dmesg.txt" 2>/dev/null || echo 0) lines)" >> "$log_file"
  else
    echo "FAIL: dmesg" >> "$log_file"
  fi

  if adb_cmd shell logcat -d > "$out_dir/logcat.txt" 2>&1; then
    echo "OK: logcat ($(wc -l < "$out_dir/logcat.txt" 2>/dev/null || echo 0) lines)" >> "$log_file"
  else
    echo "FAIL: logcat" >> "$log_file"
  fi

  if [[ "$EXTRA_CAPTURE" == "1" ]]; then
    adb_cmd shell "uname -a 2>/dev/null || true" > "$out_dir/uname.txt" 2>&1 || true
    adb_cmd shell "cat /proc/version 2>/dev/null || true" > "$out_dir/proc_version.txt" 2>&1 || true
    adb_cmd shell "cat /proc/cmdline 2>/dev/null || true" > "$out_dir/cmdline.txt" 2>&1 || true
    adb_cmd shell "ls -l /dev/block/by-name 2>/dev/null || true" > "$out_dir/partitions-by-name.txt" 2>&1 || true
    adb_cmd shell "cat /proc/partitions 2>/dev/null || true" > "$out_dir/partitions.txt" 2>&1 || true
    adb_cmd shell "cat /proc/mounts 2>/dev/null || true" > "$out_dir/mounts.txt" 2>&1 || true
    adb_cmd shell "cat /proc/last_kmsg 2>/dev/null || true" > "$out_dir/last_kmsg.txt" 2>&1 || true
    adb_cmd shell "ls -R /sys/fs/pstore 2>/dev/null || true" > "$out_dir/pstore-ls.txt" 2>&1 || true

    if adb_cmd shell "cat /sys/fs/pstore/* 2>/dev/null" > "$out_dir/pstore.txt" 2>&1; then
      if [[ -s "$out_dir/pstore.txt" ]]; then
        echo "OK: pstore ($(wc -l < "$out_dir/pstore.txt" 2>/dev/null || echo 0) lines)" >> "$log_file"
      else
        echo "WARN: pstore empty" >> "$log_file"
      fi
    else
      echo "WARN: pstore capture failed/absent" >> "$log_file"
    fi
  fi

  echo "Capture complete at $(date)" >> "$log_file"
}

make_primary_log() {
  local out_dir="$1"
  local primary="$out_dir/boot.log"
  : > "$primary"

  echo "=== Boot Log Composite (generated $(date)) ===" >> "$primary"
  echo >> "$primary"

  if [[ -s "$out_dir/pstore.txt" ]]; then
    echo "### pstore (captured: $(date -r "$out_dir/pstore.txt" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown'))" >> "$primary"
    cat "$out_dir/pstore.txt" >> "$primary"
    echo >> "$primary"
  fi

  if [[ -s "$out_dir/last_kmsg.txt" ]]; then
    echo "### last_kmsg (captured: $(date -r "$out_dir/last_kmsg.txt" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown'))" >> "$primary"
    cat "$out_dir/last_kmsg.txt" >> "$primary"
    echo >> "$primary"
  fi

  if [[ -s "$out_dir/dmesg.txt" ]]; then
    echo "### dmesg (captured: $(date -r "$out_dir/dmesg.txt" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown'))" >> "$primary"
    cat "$out_dir/dmesg.txt" >> "$primary"
    echo >> "$primary"
  fi

  if [[ -s "$out_dir/logcat.txt" ]]; then
    echo "### logcat (captured: $(date -r "$out_dir/logcat.txt" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown'))" >> "$primary"
    cat "$out_dir/logcat.txt" >> "$primary"
    echo >> "$primary"
  fi

  echo "$primary"
}

start_pulse() {
  [[ "$PULSE" == "1" ]] || return 0

  echo "⚡ PULSE=1: starting live heartbeat monitor..."

  if [[ "$PULSE_MODE" == "file" ]]; then
    # Not truly live unless something appends continuously, but provided as an option.
    ( sleep 2; python3 "$TOOL" "$base_dir/latest.boot.log" --pulse $( [[ "$PULSE_AUTOSTOP" == "1" ]] && echo "--autostop" ) ) &
    pulse_pid=$!
    return 0
  fi

  # Default: real live pulse from adb dmesg stream.
  # Consumer exit is enough; adb gets SIGPIPE when pulse exits.
  (
    adb_cmd shell dmesg -w 2>/dev/null | python3 "$TOOL" - --pulse $( [[ "$PULSE_AUTOSTOP" == "1" ]] && echo "--autostop" )
  ) &
  pulse_pid=$!
}

# Launch pulse once (optional)
start_pulse

prev_primary=""

for ((i=1; i<=MAX_REBOOTS; i++)); do
  ts="$(date +%Y%m%d-%H%M%S)"
  out_dir="$runs_dir/$ts"
  mkdir -p "$out_dir"

  echo
  echo "=== Run $i/$MAX_REBOOTS @ $ts ==="

  # Your flash/reboot hook goes here if you want it:
  # fastboot flash ... ; fastboot reboot

  if ! wait_online; then
    # timed out; loop continues unless abort threshold hit
    continue
  fi

  if ! check_responsive; then
    echo "UNRESPONSIVE" > "$out_dir/device_status.txt"
  else
    echo "RESPONSIVE" > "$out_dir/device_status.txt"
  fi

  sleep 2
  capture_state "$out_dir"

  primary="$(make_primary_log "$out_dir")"
  cp "$primary" "$base_dir/latest.boot.log" 2>/dev/null || true

  # Analyzer + compare
  if [[ -n "$prev_primary" && -f "$prev_primary" ]]; then
    python3 "$TOOL" "$primary" --project "$PROJECT" --session-dir "$SESSION_DIR" $SAFE_FLAGS $EXTRA_TOOL_FLAGS --compare "$prev_primary" >/dev/null || true
  else
    python3 "$TOOL" "$primary" --project "$PROJECT" --session-dir "$SESSION_DIR" $SAFE_FLAGS $EXTRA_TOOL_FLAGS >/dev/null || true
  fi

  # Archive JSON into this run folder (if emitted)
  if [[ -f "$base_dir/latest.signals.json" ]]; then
    cp "$base_dir/latest.signals.json" "$out_dir/signals.json" || true
  fi
  if [[ -f "$base_dir/latest.analysis.md" ]]; then
    cp "$base_dir/latest.analysis.md" "$out_dir/analysis.md" || true
  fi
  if [[ -f "$base_dir/latest.diff.md" ]]; then
    cp "$base_dir/latest.diff.md" "$out_dir/diff.md" || true
  fi

  # Stability / stuck detection (diff hash + delta bucket)
  newest_diff="$(ls -1t "$base_dir"/history/*.diff.md 2>/dev/null | head -n 1 || true)"
  if [[ -n "$newest_diff" ]]; then
    cur_hash="$(hash_file "$newest_diff")"
    last_hash="$(cat "$last_hash_file" 2>/dev/null || true)"
    is_stable=0

    if [[ -n "$last_hash" && "$cur_hash" == "$last_hash" ]]; then
      is_stable=1
      echo "Stable: diff hash match"
    fi

    if [[ "$is_stable" -eq 0 ]] && grep -q "Delta:" "$newest_diff"; then
      delta_line="$(grep "Delta:" "$newest_diff" | head -n 1)"
      if echo "$delta_line" | grep -Eq '(\+0\.0|\-0\.0|\+0\.00|\-0\.00)'; then
        is_stable=1
        echo "Stable: timestamp delta ~0"
      fi
    fi

    if [[ "$is_stable" -eq 1 ]]; then
      stable_count=$((stable_count + 1))
      echo "Stability indicator ($stable_count/$STABLE_N)"
    else
      stable_count=0
      echo "$cur_hash" > "$last_hash_file"
    fi

    if [[ "$stable_count" -ge "$STABLE_N" ]]; then
      echo
      echo -e "\a\aSTUCK DETECTED — last $STABLE_N runs effectively identical"
      echo "Check: $base_dir/latest.analysis.md and $base_dir/latest.diff.md"
      break
    fi
  fi

  prev_primary="$primary"
done

echo
echo "Done. Latest outputs:"
echo "  $base_dir/latest.analysis.md"
echo "  $base_dir/latest.diff.md"
echo "  $base_dir/latest.signals.json"
