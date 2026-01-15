🧠 Engine Room Architecture (v1.3.2e+)

This project uses a two-layer forensic design:

pmos-port-assist.py — the brain
Parses kernel/userland logs, normalizes failure signals, produces structured summaries (analysis.md, signals.json), and compares runs over time.
pmos-watchdog.sh — the nervous system
Handles continuous reboot/capture cycles, composes canonical boot logs, triggers analysis at the right moment, and decides when you are stuck.

Together, they form an automated kernel debugging loop suitable for unattended porting runs.

🔁 Recursive Forensics Loop

Each iteration follows the same deterministic pipeline:
1. (Optional) Flash / Reboot Hook
A user-supplied command (FLASH_HOOK) can automate reflashing or rebooting between runs.

2. Device Recovery & Validation
Waits for adb wait-for-device
Verifies shell responsiveness
Tolerates partial boots and zombie states

3. Forensic Capture
pstore and last_kmsg (crash-resilient sources)
dmesg snapshot
Bounded logcat -d (won’t hang the loop)
/proc/cmdline, mounts, partitions, kernel version

4. Canonical Boot Log
All sources are merged into a single boot.log
This file is the source of truth for analysis

5. Analysis & Comparison
pmos-port-assist.py runs with project history enabled
Automatically compares against the previous run

Emits:
latest.analysis.md
latest.diff.md
latest.signals.json

📊 Signal Scoring & Weights

To distinguish real progress from noise, each run is assigned a weighted failure score derived from signals.json.
Default weights (configurable via env vars):
panic_oops — 100
init_fail — 60
vfs_root — 60
device_tree — 40
cma_fail — 25
module_fail — 25
firmware_missing — 10
probe_fail — 5

Higher score = worse failure state.
This allows you to answer questions like:
“Did we move the crash later?”
“Did we trade a panic for an init failure?”
“Did we actually improve, or just change log text?”


🧬 Stable Signature & Stuck Detection

The watchdog no longer relies on log text alone.
Each run generates a signature:
last_timestamp | panic | init | vfs | dt | cma | module | firmware | probe
Stuck detection triggers when any combination of the following repeats for STUCK_N runs:

1. Exact signature match
Same failure class, same counts, same crash point.

2. Semantic diff hash match
diff.md unchanged even if timestamps move.

3. Score plateau
No improvement in weighted score across runs.

When triggered, the watchdog stops automatically and points you to:
latest.analysis.md
latest.diff.md
This prevents infinite “reboot but nothing changed” loops.


🚨 Early Stop Gates (Optional)

You can configure the watchdog to abort immediately on known-dead conditions:
Panic / Oops
nit failure
VFS root mount failure

Disabled by default. When enabled, this is useful for:
Known-broken configs
Fast failure validation
CI-style sanity checks

⚡ Live Pulse Mode (Optional)

With PULSE=1, the watchdog can start a live heartbeat monitor:
Streams adb shell dmesg -w into the analyzer
Uses the analyzer’s native regex (--pulse --autostop)
Stops automatically on panic/oops

Pulse is observational, not authoritative.
Crash-resilient sources (pstore / last_kmsg) remain the forensic record.

🔒 Safety by Default

Analyzer redaction is assumed ON by default (v1.3.2e)
Watchdog passes only --json unless explicitly overridden
Logs are safe to share unless --no-redact is manually enabled

🧠 Intended Workflow

1. Let the watchdog run unattended.
2. Review latest.analysis.md and latest.diff.md.
3. Apply one kernel change.
4. Re-run.
5. Trust the score + signature, not gut feeling.

This system does not guess.
It proves whether you made progress.

