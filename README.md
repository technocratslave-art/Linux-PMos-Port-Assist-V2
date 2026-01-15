# pmOS Port Assist (v1.3.2d)

A bring-up toolkit for postmarketOS device porting:
- Boot log forensics (signals + context + advice)
- Semantic regression diff (progress tracking across boots)
- Timeline sparkline (requires kernel timestamps)
- Live Pulse heartbeat (real-time “one-line status”)

​⚠️ IMPORTANT: Always use the --safe flag when sharing logs publicly to redact your IMEI, IP, and unique device IDs.
    - More details below
    
## Requirements

- Python 3.9+
- adb (Android platform tools)
- **Optional**: device-tree-compiler (`dtc`)
  - Required only if you use `--dts-file` for DTS linting
  - Install on Debian/Ubuntu: `sudo apt install device-tree-compiler`

## 🚀 Quick Start
To use these tools, run:
`chmod +x *.sh *.py`

**Live monitor:**
`adb shell dmesg -w | ./pmos-port-assist.py - --pulse 


***Safety, Privacy, and Threat Model***

This project is designed for honest device bring-up and porting workflows on a developer’s own machine. It is not hardened against malicious inputs or hostile multi-user environment
Privacy (IMPORTANT)

Boot logs frequently contain sensitive identifiers, including but not limited to:

IMEI / ICCID-like numbers

Serial numbers

MAC addresses

IP addresses

Hostnames


If you intend to share logs publicly (GitHub issues, pastebins, chat, forums), you must use safe mode.

python3 pmos_port_assist.py boot.log --safe --timeline

When using the watchdog, safe mode should also be enabled:

PROJECT=mydevice EXTRA_TOOL_FLAGS="--safe --timeline --json" ./pmos-watchdog.sh

If --safe is not used, the generated reports should be treated as private.

DTS / DTC Usage

The --dts-file and --dtc-include options invoke the local dtc (device-tree-compiler) tool.

Only run these options on trusted DTS files and include paths.
Do not point them at untrusted directories or files.

Filesystem Safety

The --project and --session-dir options control where output files are written.

Do not run this tool as root.

Do not point project/session directories at system paths.

Keep projects inside the repository or a dedicated work directory.


Threat Model Summary

This tool assumes:

You trust the device you are porting

You trust the logs you are analyzing

You are running as a normal user on your own machine


It prioritizes developer productivity and forensic clarity, not adversarial hardening.

