# pmOS Port Assist (v1.3.2d)

A bring-up toolkit for postmarketOS device porting:
- Boot log forensics (signals + context + advice)
- Semantic regression diff (progress tracking across boots)
- Timeline sparkline (requires kernel timestamps)
- Live Pulse heartbeat (real-time “one-line status”)

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
`adb shell dmesg -w | ./pmos-port-assist.py - --pulse`
