#!/usr/bin/env bash
# pmos-watchdog.sh
# v2.1 — “wow, this is actually perfect” monolithic watchdog
#
# If I had to sign one, it’s this one.
# It’s hard to kill, hard to lie to, and easy to read the morning after.
#
# What it does:
#   loop:
#     (optional) flash/reboot hook
#     wait for adb
#     capture (pstore/last_kmsg/dmesg/logcat + /proc + partitions)
#     compose a single boot.log
#     run analyzer (project+history) and compare to previous run
#     compute signature+score from analyzer JSON
#     detect “stuck at same wall” reliably (signature + diff hash + score plateau)
#     stop cleanly with a loud bell and pointers to the exact files
#
# Requirements:
#   bash, coreutils, timeout, sha256sum, awk, grep
#   adb in PATH
#   python3 in PATH
#   pmos-port-assist.py (v1.3.2e recommended; redaction default ON)
#
# Usage:
#   ./pmos-watchdog.sh
#   PROJECT=oneplus12 SESSION_DIR=./sessions MAX_REBOOTS=60 ./pmos-watchdog.sh
#   PULSE=1 ./pmos-watchdog.sh
#   FLASH_HOOK="fastboot reboot" ./pmos-watchdog.sh
#
# Safety:
#   Analyzer should be safe-by-default (redaction ON). This watchdog assumes that.
#   If you *must* disable redaction for local-only debugging:
#     SAFE_FLAGS="--json --no-redact" ./pmos-watchdog.sh

set -euo pipefail

# -------------------------
# Config (env-overridable)
# -------------------------

TOOL="${TOOL:-./pmos-port-assist.py}"
PROJECT="${PROJECT:-pmos_session}"
SESSION_DIR="${SESSION_DIR:-.}"
MAX_REBOOTS="${MAX_REBOOTS:-20}"

SERIAL="${SERIAL:-}"
ADB_WAIT_MIN="${ADB_WAIT_MIN:-15}"
ADB_WAIT_ABORT_N="${ADB_WAIT_ABORT_N:-3}"
ADB_PING_TRIES="${ADB_PING_TRIES:-6}"
ADB_PING_SLEEP_S="${ADB_PING_SLEEP_S:-2}"
ADB_BOOT_GRACE_S="${ADB_BOOT_GRACE_S:-2}"
ADB_RECONNECT="${ADB_RECONNECT:-1}"

# Capture toggles
EXTRA_CAPTURE="${EXTRA_CAPTURE:-1}"
CAPTURE_DMESG="${CAPTURE_DMESG:-1}"
CAPTURE_LOGCAT="${CAPTURE_LOGCAT:-1}"     # if you get hangs, set CAPTURE_LOGCAT=0
CAPTURE_PSTORE="${CAPTURE_PSTORE:-1}"
CAPTURE_LAST_KMSG="${CAPTURE_LAST_KMSG:-1}"

# Analyzer flags
SAFE_FLAGS="${SAFE_FLAGS:---json}"         # analyzer redaction assumed default ON
EXTRA_TOOL_FLAGS="${EXTRA_TOOL_FLAGS:---timeline}"

# Optional live pulse
PULSE="${PULSE:-0}"
PULSE_MODE="${PULSE_MODE:-adb}"           # adb|file
PULSE_AUTOSTOP="${PULSE_AUTOSTOP:-1}"

# Stop conditions / scoring
STUCK_N="${STUCK_N:-3}"

# Optional early exit gates (off by default)
EARLY_STOP_ON_PANIC="${EARLY_STOP_ON_PANIC:-0}"
EARLY_STOP_ON_INITFAIL="${EARLY_STOP_ON_INITFAIL:-0}"
EARLY_STOP_ON_VFS="${EARLY_STOP_ON_VFS:-0}"

# Weights (bigger = worse)
W_PANIC="${W_PANIC:-100}"
W_INIT="${W_INIT:-60}"
W_VFS="${W_VFS:-60}"
W_DT="${W_DT:-40}"
W_CMA="${W_CMA:-25}"
W_MOD="${W_MOD:-25}"
W_FW="${W_FW:-10}"
W_PROBE="${W_PROBE:-5}"

# Optional automation hook (flash/reboot/etc) run each iteration
FLASH_HOOK="${FLASH_HOOK:-}"

# -------------------------
# Helpers
# -------------------------

log() { printf "%s\n" "$*"; }
ts_now() { date +%Y%m%d-%H%M%S; }
die() { log "❌ $*"; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

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

ensure_deps() {
  have_cmd adb || die "adb not found in PATH"
  have_cmd python3 || die "python3 not found in PATH"
  [[ -f "$TOOL" ]] || die "Analyzer not found: TOOL=$TOOL"
}

maybe_reconnect_adb() {
  [[ "$ADB_RECONNECT" == "1" ]] || return 0
  adb_cmd reconnect >/dev/null 2>&1 || true
  adb_cmd start-server >/dev/null 2>&1 || true
}

timeout_count=0
wait_online() {
  if timeout "${ADB_WAIT_MIN}m" adb_cmd wait-for-device >/dev/null 2>&1; then
    timeout_count=0
    return 0
  fi
  timeout_count=$((timeout_count + 1))
  log "⚠️  device did not appear within ${ADB_WAIT_MIN} minutes ($timeout_count/${ADB_WAIT_ABORT_N})"
  maybe_reconnect_adb
  if [[ "$timeout_count" -ge "$ADB_WAIT_ABORT_N" ]]; then
    die "ABORT: device failed to appear ${ADB_WAIT_ABORT_N} times in a row"
  fi
  return 1
}

check_responsive() {
  local try=0
  while [[ $try -lt "$ADB_PING_TRIES" ]]; do
    if adb_cmd shell echo "ping" 2>/dev/null | grep -q "ping"; then
      return 0
    fi
    try=$((try + 1))
    sleep "$ADB_PING_SLEEP_S"
  done
  return 1
}

safe_pull_text() {
  # safe_pull_text "remote_cmd" "out_path"
  local remote="$1"
  local out="$2"
  if adb_cmd shell "$remote" >"$out" 2>&1; then
    return 0
  fi
  return 1
}

# atomic write: write temp then mv
atomic_write() {
  local src="$1"
  local dst="$2"
  local tmp="${dst}.tmp.$$"
  cp "$src" "$tmp" 2>/dev/null || cat "$src" >"$tmp"
  mv -f "$tmp" "$dst"
}

# -------------------------
# Capture
# -------------------------

capture_state() {
  local out_dir="$1"
  local caplog="$out_dir/capture.log"
  mkdir -p "$out_dir"
  : >"$caplog"
  echo "Capture start: $(date)" >>"$caplog"

  if [[ "$CAPTURE_DMESG" == "1" ]]; then
    if safe_pull_text "dmesg" "$out_dir/dmesg.txt"; then
      echo "OK: dmesg ($(wc -l <"$out_dir/dmesg.txt" 2>/dev/null || echo 0) lines)" >>"$caplog"
    else
      echo "FAIL: dmesg" >>"$caplog"
      : >"$out_dir/dmesg.txt"
    fi
  fi

  if [[ "$CAPTURE_LOGCAT" == "1" ]]; then
    # bounded; some devices hang here during partial userspace
    if timeout 45s adb_cmd shell logcat -d >"$out_dir/logcat.txt" 2>&1; then
      echo "OK: logcat ($(wc -l <"$out_dir/logcat.txt" 2>/dev/null || echo 0) lines)" >>"$caplog"
    else
      echo "WARN: logcat capture failed/timed out" >>"$caplog"
      : >"$out_dir/logcat.txt"
    fi
  else
    : >"$out_dir/logcat.txt"
  fi

  if [[ "$EXTRA_CAPTURE" == "1" ]]; then
    safe_pull_text "uname -a 2>/dev/null || true" "$out_dir/uname.txt" || true
    safe_pull_text "cat /proc/version 2>/dev/null || true" "$out_dir/proc_version.txt" || true
    safe_pull_text "cat /proc/cmdline 2>/dev/null || true" "$out_dir/cmdline.txt" || true
    safe_pull_text "ls -l /dev/block/by-name 2>/dev/null || true" "$out_dir/partitions-by-name.txt" || true
    safe_pull_text "cat /proc/partitions 2>/dev/null || true" "$out_dir/partitions.txt" || true
    safe_pull_text "cat /proc/mounts 2>/dev/null || true" "$out_dir/mounts.txt" || true

    if [[ "$CAPTURE_LAST_KMSG" == "1" ]]; then
      safe_pull_text "cat /proc/last_kmsg 2>/dev/null || true" "$out_dir/last_kmsg.txt" || true
      [[ -f "$out_dir/last_kmsg.txt" ]] || : >"$out_dir/last_kmsg.txt"
    else
      : >"$out_dir/last_kmsg.txt"
    fi

    if [[ "$CAPTURE_PSTORE" == "1" ]]; then
      safe_pull_text "ls -R /sys/fs/pstore 2>/dev/null || true" "$out_dir/pstore-ls.txt" || true
      if adb_cmd shell "cat /sys/fs/pstore/* 2>/dev/null" >"$out_dir/pstore.txt" 2>&1; then
        if [[ -s "$out_dir/pstore.txt" ]]; then
          echo "OK: pstore ($(wc -l <"$out_dir/pstore.txt" 2>/dev/null || echo 0) lines)" >>"$caplog"
        else
          echo "WARN: pstore empty" >>"$caplog"
        fi
      else
        echo "WARN: pstore capture failed/absent" >>"$caplog"
        : >"$out_dir/pstore.txt"
      fi
    else
      : >"$out_dir/pstore.txt"
    fi
  else
    : >"$out_dir/uname.txt"
    : >"$out_dir/proc_version.txt"
    : >"$out_dir/cmdline.txt"
    : >"$out_dir/partitions-by-name.txt"
    : >"$out_dir/partitions.txt"
    : >"$out_dir/mounts.txt"
    : >"$out_dir/last_kmsg.txt"
    : >"$out_dir/pstore.txt"
  fi

  echo "Capture end: $(date)" >>"$caplog"
}

make_primary_log() {
  local out_dir="$1"
  local primary="$out_dir/boot.log"
  : >"$primary"

  echo "=== Boot Log Composite (generated $(date)) ===" >>"$primary"
  echo "=== Run folder: $out_dir ===" >>"$primary"
  echo >>"$primary"

  if [[ -s "$out_dir/pstore.txt" ]]; then
    echo "### pstore" >>"$primary"
    cat "$out_dir/pstore.txt" >>"$primary"
    echo >>"$primary"
  fi

  if [[ -s "$out_dir/last_kmsg.txt" ]]; then
    echo "### last_kmsg" >>"$primary"
    cat "$out_dir/last_kmsg.txt" >>"$primary"
    echo >>"$primary"
  fi

  if [[ -s "$out_dir/dmesg.txt" ]]; then
    echo "### dmesg" >>"$primary"
    cat "$out_dir/dmesg.txt" >>"$primary"
    echo >>"$primary"
  fi

  if [[ -s "$out_dir/logcat.txt" ]]; then
    echo "### logcat" >>"$primary"
    cat "$out_dir/logcat.txt" >>"$primary"
    echo >>"$primary"
  fi

  echo "$primary"
}

# -------------------------
# Analyzer + scoring
# -------------------------

run_analyzer() {
  local primary="$1"
  local prev="${2:-}"

  if [[ -n "$prev" && -f "$prev" ]]; then
    python3 "$TOOL" "$primary" --project "$PROJECT" --session-dir "$SESSION_DIR" \
      $SAFE_FLAGS $EXTRA_TOOL_FLAGS --compare "$prev" >/dev/null 2>&1 || true
  else
    python3 "$TOOL" "$primary" --project "$PROJECT" --session-dir "$SESSION_DIR" \
      $SAFE_FLAGS $EXTRA_TOOL_FLAGS >/dev/null 2>&1 || true
  fi
}

sig_from_json() {
  local json_path="$1"
  [[ -s "$json_path" ]] || { echo "nosig"; return 0; }

  python3 - "$json_path" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], "r", encoding="utf-8"))
c = d.get("counts", {}) or {}
ts = d.get("last_timestamp", None)
def g(k): return int(c.get(k, 0) or 0)
parts = [
  f"{(ts if ts is not None else -1):.2f}",
  str(g("panic_oops")),
  str(g("init_fail")),
  str(g("vfs_root")),
  str(g("device_tree")),
  str(g("cma_fail")),
  str(g("module_fail")),
  str(g("firmware_missing")),
  str(g("probe_fail")),
]
print("|".join(parts))
PY
}

score_from_json() {
  local json_path="$1"
  [[ -s "$json_path" ]] || { echo "0"; return 0; }

  python3 - "$json_path" \
    "$W_PANIC" "$W_INIT" "$W_VFS" "$W_DT" "$W_CMA" "$W_MOD" "$W_FW" "$W_PROBE" <<'PY'
import json, sys
p = sys.argv[1]
W = list(map(int, sys.argv[2:]))
W_PANIC,W_INIT,W_VFS,W_DT,W_CMA,W_MOD,W_FW,W_PROBE = W
d = json.load(open(p, "r", encoding="utf-8"))
c = d.get("counts", {}) or {}
def g(k): return int(c.get(k, 0) or 0)
score = (
  g("panic_oops") * W_PANIC +
  g("init_fail") * W_INIT +
  g("vfs_root") * W_VFS +
  g("device_tree") * W_DT +
  g("cma_fail") * W_CMA +
  g("module_fail") * W_MOD +
  g("firmware_missing") * W_FW +
  g("probe_fail") * W_PROBE
)
print(score)
PY
}

should_early_stop() {
  local json_path="$1"
  [[ -s "$json_path" ]] || return 1

  python3 - "$json_path" "$EARLY_STOP_ON_PANIC" "$EARLY_STOP_ON_INITFAIL" "$EARLY_STOP_ON_VFS" <<'PY'
import json, sys
p = sys.argv[1]
stop_panic = sys.argv[2] == "1"
stop_init  = sys.argv[3] == "1"
stop_vfs   = sys.argv[4] == "1"
d = json.load(open(p, "r", encoding="utf-8"))
c = d.get("counts", {}) or {}
panic = int(c.get("panic_oops", 0) or 0)
initf = int(c.get("init_fail", 0) or 0)
vfs   = int(c.get("vfs_root", 0) or 0)
if (stop_panic and panic>0) or (stop_init and initf>0) or (stop_vfs and vfs>0):
  sys.exit(0)
sys.exit(1)
PY
}

archive_latest_into_run() {
  local out_dir="$1"
  [[ -f "$base_dir/latest.signals.json" ]] && cp "$base_dir/latest.signals.json" "$out_dir/signals.json" || true
  [[ -f "$base_dir/latest.analysis.md"  ]] && cp "$base_dir/latest.analysis.md"  "$out_dir/analysis.md" || true
  [[ -f "$base_dir/latest.diff.md"      ]] && cp "$base_dir/latest.diff.md"      "$out_dir/diff.md" || true
  [[ -f "$base_dir/latest.boot.log"     ]] && cp "$base_dir/latest.boot.log"     "$out_dir/boot.log.latest" || true
}

# -------------------------
# Pulse
# -------------------------

pulse_pid=""
cleanup() {
  if [[ -n "${pulse_pid}" ]]; then
    kill "$pulse_pid" 2>/dev/null || true
    wait "$pulse_pid" 2>/dev/null || true
    pulse_pid=""
  fi
}
trap cleanup EXIT

start_pulse() {
  [[ "$PULSE" == "1" ]] || return 0
  log "⚡ PULSE=1: starting live heartbeat…"

  if [[ "$PULSE_MODE" == "file" ]]; then
    ( sleep 2; python3 "$TOOL" "$base_dir/latest.boot.log" --pulse $( [[ "$PULSE_AUTOSTOP" == "1" ]] && echo "--autostop" ) ) &
    pulse_pid=$!
    return 0
  fi

  (
    adb_cmd shell dmesg -w 2>/dev/null | python3 "$TOOL" - --pulse $( [[ "$PULSE_AUTOSTOP" == "1" ]] && echo "--autostop" )
  ) &
  pulse_pid=$!
}

# -------------------------
# Flash hook
# -------------------------

apply_flash_hook() {
  [[ -n "$FLASH_HOOK" ]] || return 0
  log "🔁 FLASH_HOOK: running…"
  if [[ -x "$FLASH_HOOK" ]]; then
    "$FLASH_HOOK"
  else
    bash -lc "$FLASH_HOOK"
  fi
}

# -------------------------
# Bootstrapping
# -------------------------

ensure_deps

base_dir="$SESSION_DIR/$PROJECT"
runs_dir="$base_dir/runs"
mkdir -p "$runs_dir"

sig_file="$base_dir/.last_sig"
diff_hash_file="$base_dir/.last_diff_hash"
score_file="$base_dir/.last_score"

stable_count=0
prev_primary=""

start_pulse

# -------------------------
# Main loop
# -------------------------

for ((i=1; i<=MAX_REBOOTS; i++)); do
  run_ts="$(ts_now)"
  out_dir="$runs_dir/$run_ts"
  mkdir -p "$out_dir"

  log ""
  log "=== Run $i/$MAX_REBOOTS @ $run_ts ==="

  apply_flash_hook || true

  if ! wait_online; then
    echo "OFFLINE" >"$out_dir/device_status.txt"
    continue
  fi

  maybe_reconnect_adb
  if check_responsive; then
    echo "RESPONSIVE" >"$out_dir/device_status.txt"
  else
    echo "UNRESPONSIVE" >"$out_dir/device_status.txt"
  fi

  sleep "$ADB_BOOT_GRACE_S"
  capture_state "$out_dir"

  primary="$(make_primary_log "$out_dir")"
  atomic_write "$primary" "$base_dir/latest.boot.log"

  run_analyzer "$primary" "${prev_primary:-}"
  archive_latest_into_run "$out_dir"

  newest_json="$base_dir/latest.signals.json"
  newest_diff="$(ls -1t "$base_dir"/history/*.diff.md 2>/dev/null | head -n 1 || true)"

  sig="$(sig_from_json "$newest_json")"
  score="$(score_from_json "$newest_json")"
  echo "$sig" >"$out_dir/signature.txt" || true
  echo "$score" >"$out_dir/score.txt" || true

  last_sig="$(cat "$sig_file" 2>/dev/null || true)"
  last_score="$(cat "$score_file" 2>/dev/null || true)"

  cur_diff_hash=""
  last_diff_hash="$(cat "$diff_hash_file" 2>/dev/null || true)"
  if [[ -n "$newest_diff" && -f "$newest_diff" ]]; then
    cur_diff_hash="$(hash_file "$newest_diff")"
    echo "$cur_diff_hash" >"$out_dir/diff_hash.txt" || true
  fi

  is_stable=0
  reason=""

  # 1) Exact signature match (counts + last_timestamp baked in)
  if [[ -n "$last_sig" && "$sig" == "$last_sig" ]]; then
    is_stable=1
    reason="signature match"
  fi

  # 2) Semantic diff match (hash)
  if [[ "$is_stable" -eq 0 && -n "$cur_diff_hash" && -n "$last_diff_hash" && "$cur_diff_hash" == "$last_diff_hash" ]]; then
    is_stable=1
    reason="diff hash match"
  fi

  # 3) Score plateau (no improvement) as last resort
  if [[ "$is_stable" -eq 0 && -n "$last_score" && "$score" == "$last_score" ]]; then
    is_stable=1
    reason="score plateau"
  fi

  if [[ "$is_stable" -eq 1 ]]; then
    stable_count=$((stable_count + 1))
    log "Stable wall: $reason ($stable_count/$STUCK_N)  score=$score  sig=$sig"
  else
    stable_count=0
    echo "$sig" >"$sig_file"
    echo "$score" >"$score_file"
    [[ -n "$cur_diff_hash" ]] && echo "$cur_diff_hash" >"$diff_hash_file"
    log "Change detected. score=$score  sig=$sig"
  fi

  if should_early_stop "$newest_json"; then
    log ""
    log "🚨 EARLY STOP: configured failure gate triggered."
    log "See:"
    log "  $base_dir/latest.analysis.md"
    log "  $base_dir/latest.diff.md"
    break
  fi

  if [[ "$stable_count" -ge "$STUCK_N" ]]; then
    log ""
    log "🔔🔔 STUCK DETECTED — $STUCK_N consecutive runs effectively identical"
    log "See:"
    log "  $base_dir/latest.analysis.md"
    log "  $base_dir/latest.diff.md"
    break
  fi

  prev_primary="$primary"
done

log ""
log "Done. Latest outputs:"
log "  $base_dir/latest.boot.log"
log "  $base_dir/latest.analysis.md"
log "  $base_dir/latest.diff.md"
log "  $base_dir/latest.signals.json"
