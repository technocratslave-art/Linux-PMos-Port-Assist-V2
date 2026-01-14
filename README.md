# pmOS Port Assist (v1.3.2d)

A bring-up toolkit for postmarketOS device porting:
- Boot log forensics (signals + context + advice)
- Semantic regression diff (progress tracking across boots)
- Timeline sparkline (requires kernel timestamps)
- Live Pulse heartbeat (real-time “one-line status”)

Includes a companion watchdog script for iterative capture → analyze → compare loops.

## Quick start

Analyze a log:
```bash
python3 pmos-port-assist.py boot.log --safe --timeline

Compare two logs:

python3 pmos-port-assist.py new.log --safe --compare old.log

Live Pulse heartbeat (recommended: pipe from adb):

adb shell dmesg -w | python3 pmos-port-assist.py - --pulse --autostop

Watchdog loop (capture + history):

PROJECT=mydevice MAX_REBOOTS=10 ./pmos-watchdog.sh

Watchdog + live pulse:

PROJECT=mydevice MAX_REBOOTS=10 PULSE=1 ./pmos-watchdog.sh

What you get

The report

latest.analysis.md contains:

Lazy summary (panic/init/root mount fail flags)

Counts by signal type

Timeline sparkline (if timestamps exist)

Context blocks with numbered lines around each signal

KNOWN_ISSUES advice matches (offline hints for common pmOS pitfalls)


The diff

latest.diff.md contains:

Boot time delta (prev → current)

New vs resolved “semantic” errors (normalized signatures)

A short summary: improvement / regression / mixed / stuck


JSON (optional but useful)

With --json, you get latest.signals.json (counts, timestamps, normalized lines). The watchdog archives this into each run folder as runs/<ts>/signals.json.

Pulse mode

Pulse is a one-line heartbeat designed for long bring-up sessions.

stdin mode (best):

adb shell dmesg -w | python3 pmos-port-assist.py - --pulse --autostop

file tail mode:

python3 pmos-port-assist.py ./boot.log --pulse

Pulse output updates in place:

boot timestamp (if present)

P = panic/oops count

I = init failure count

V = VFS/root mount failure count


Exit codes:

0: normal completion

3: panic detected (pulse + autostop)

130: Ctrl+C


Watchdog environment variables

Core:

PROJECT (default: pmos_session)

SESSION_DIR (default: .)

MAX_REBOOTS (default: 20)

TIMEOUT_MIN (default: 15)

TIMEOUT_ABORT_N (default: 3)

STABLE_N (default: 3)

TOOL (default: ./pmos-port-assist.py)


Pulse integration:

PULSE=1 enables pulse in background (default off)

PULSE_MODE=adb|file (default: adb)

PULSE_AUTOSTOP=1 (default on)

PULSE_INTERVAL=1.0 (if supported by your build)


Notes:

Timeline requires kernel timestamps (CONFIG_PRINTK_TIME=y)

For truly live pulse, prefer adb pipe mode over file mode


Typical workflows

First boot sanity:

TIMEOUT_MIN=5 TIMEOUT_ABORT_N=2 MAX_REBOOTS=3 PULSE=1 ./pmos-watchdog.sh

Root mount failures:

Check lazy summary for “ROOT MOUNT FAIL”

Compare captured cmdline.txt vs partitions-by-name.txt

Confirm rootfstype and storage/fs modules are built-in or in initramfs


Iterative progress:

PROJECT=mydevice MAX_REBOOTS=10 STABLE_N=3 ./pmos-watchdog.sh

Watchdog stops when it detects you’re stuck (identical diffs or ~0 delta repeatedly).

Requirements

Python 3.8+

adb in PATH (for watchdog and live pulse)

dtc optional (for DTS lint)


License

Choose MIT or GPLv3 depending on how you want downstream use to work.

And here’s a small polish patch (safe to apply on top of your current monoliths). It adds `--pulse-interval`, adds `PULSE_INTERVAL` support in the watchdog, and makes file pulse detect rotations via inode (plus an optional message). I also included Claude’s “final tightening” for the errno fallback as a minimal change.

```diff
--- a/pmos-port-assist.py
+++ b/pmos-port-assist.py
@@ -155,6 +155,7 @@
 def decode_errno(line: str) -> str:
@@
-    if not m:
-        # Tight fallback (v1.3.2a+): require error-ish keyword near the negative number
-        m = re.search(
-            r"(?:probe|init|setup)\b.*?(?:failed|returned|error|errno|status).*?(-\d+)\b",
-            line,
-            re.I,
-        )
+    if not m:
+        # Tight fallback: require error context within reasonable proximity (reduces false positives)
+        m = re.search(
+            r"(?:probe|init|setup)(?:\s+\S+){0,10}\s+(?:fail(?:ed)?|error|errno|status|returned)(?:\s+\S+){0,3}\s+(-\d+)\b",
+            line,
+            re.I,
+        )
     if not m:
         return ""
@@ -392,7 +393,7 @@
-def run_pulse(path_str: str, interval: float = 1.0, stop_on_panic: bool = False) -> None:
+def run_pulse(path_str: str, interval: float = 1.0, stop_on_panic: bool = False) -> None:
@@
-        p = Path(path_str)
-        offset = 0
+        p = Path(path_str)
+        offset = 0
+        last_inode: Optional[int] = None
         while True:
             if p.exists():
-                try:
-                    size = p.stat().st_size
-                except OSError:
-                    size = 0
+                try:
+                    st = p.stat()
+                    size = st.st_size
+                    inode = st.st_ino
+                except OSError:
+                    size = 0
+                    inode = None
+                if inode is not None and last_inode is not None and inode != last_inode:
+                    offset = 0
+                    print("\n⚠️  File rotated (inode changed), resetting offset", file=sys.stderr)
+                if inode is not None:
+                    last_inode = inode
                 if size < offset:
                     offset = 0  # truncation/rotation
                 if size > offset:
                     with p.open("r", errors="ignore") as f:
                         f.seek(offset)
@@ -452,6 +461,10 @@
     ap.add_argument("--pulse", action="store_true", help="Live heartbeat monitor (stdin or file tail)")
     ap.add_argument("--autostop", action="store_true", help="With --pulse: stop on first panic/oops")
+    ap.add_argument(
+        "--pulse-interval", type=float, default=1.0,
+        help="Pulse heartbeat update interval in seconds (default 1.0)"
+    )
@@ -468,7 +481,7 @@
     # Pulse short-circuit
     if args.pulse:
-        run_pulse(args.logfile, interval=1.0, stop_on_panic=args.autostop)
+        run_pulse(args.logfile, interval=args.pulse_interval, stop_on_panic=args.autostop)
         return 0

--- a/pmos-watchdog.sh
+++ b/pmos-watchdog.sh
@@ -23,6 +23,7 @@
 PULSE="${PULSE:-0}"
 PULSE_MODE="${PULSE_MODE:-adb}"   # adb|file
 PULSE_AUTOSTOP="${PULSE_AUTOSTOP:-1}"
+PULSE_INTERVAL="${PULSE_INTERVAL:-1.0}"
@@ -93,12 +94,14 @@
   if [[ "$PULSE_MODE" == "file" ]]; then
     # Not truly live unless something appends continuously, but provided as an option.
-    ( sleep 2; python3 "$TOOL" "$base_dir/latest.boot.log" --pulse $( [[ "$PULSE_AUTOSTOP" == "1" ]] && echo "--autostop" ) ) &
+    ( sleep 2; python3 "$TOOL" "$base_dir/latest.boot.log" --pulse --pulse-interval "$PULSE_INTERVAL" \
+        $( [[ "$PULSE_AUTOSTOP" == "1" ]] && echo "--autostop" ) ) &
     pulse_pid=$!
     return 0
   fi
@@ -108,7 +111,9 @@
   # Default: real live pulse from adb dmesg stream.
   # Consumer exit is enough; adb gets SIGPIPE when pulse exits.
   (
-    adb_cmd shell dmesg -w 2>/dev/null | python3 "$TOOL" - --pulse $( [[ "$PULSE_AUTOSTOP" == "1" ]] && echo "--autostop" )
+    # If you see buffering delays on your host, try: stdbuf -oL ...
+    adb_cmd shell dmesg -w 2>/dev/null | python3 "$TOOL" - --pulse --pulse-interval "$PULSE_INTERVAL" \
+      $( [[ "$PULSE_AUTOSTOP" == "1" ]] && echo "--autostop" )
   ) &
   pulse_pid=$!
 }

If you want my pick for what to tag as “final production”: keep your current v1.3.2d as-is, add only the README, and tag it. Then apply the patch above as v1.3.3 (or v1.3.2e) so the release stays minimal and clean.
