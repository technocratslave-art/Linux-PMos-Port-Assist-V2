#!/usr/bin/env python3
# pmos_port_assist.py
# v1.3.2d — forensic analyzer + semantic diff + timeline + pulse heartbeat (stdin/file tail)

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERSION = "1.3.2d"

# -------------------------
# Patterns / Knowledge Base
# -------------------------

PATTERNS: Dict[str, re.Pattern] = {
    "panic_oops": re.compile(r"\b(?:Kernel panic\b|Oops:\b|BUG:\b|Unable to handle kernel NULL pointer dereference)\b", re.I),
    "init_fail": re.compile(r"\b(?:No init found\b|Failed to execute .*?/init\b|init not found\b|run-init\b.*failed)\b", re.I),
    "vfs_root": re.compile(r"\b(?:VFS:\s*Cannot open root device|cannot mount root|mounting .* on /sysroot failed|rootfs not found)\b", re.I),
    "probe_fail": re.compile(r"\b(?:probe\b.*(?:failed|error|returned|timed out)|failed to probe)\b", re.I),
    "firmware_missing": re.compile(r"\b(?:firmware:\s*failed to load|Direct firmware load for .* failed|request_firmware.*failed|no suitable firmware)\b", re.I),
    "device_tree": re.compile(r"\b(?:OF:\s*|device tree|dtb|FDT:\s*|Unable to parse device tree|machine model.*not found|setup_machine.*dt.*not found)\b", re.I),
}

KNOWN_ISSUES: List[Dict[str, str]] = [
    {
        "pattern": r"initramfs-extra not found|ERROR:\s*initramfs-extra not found",
        "advice": "mkinitfs failed to generate initramfs-extra. Rebuild/init: run mkinitfs, verify device package hooks.",
    },
    {
        "pattern": r"Waiting for root device|waiting for .*device.*partition",
        "advice": "Rootfs not appearing in time. Add cmdline: rootwait or rootdelay=10. Compare cmdline root= vs partitions-by-name.txt.",
    },
    {
        "pattern": r"No init found|Failed to execute .*init|init not found",
        "advice": "Userspace init missing. Ensure /bin/init exists and mkinitfs includes storage + fs modules (mmc_block, ext4/f2fs).",
    },
    {
        "pattern": r"modprobe:\s*module .* not found|failed to load module",
        "advice": "Missing kernel module. Add to device package MODULES=() or mkinitfs modules list.",
    },
    {
        "pattern": r"VFS:\s*Cannot open root device|mount: mounting .* on /sysroot failed|rootfs not found",
        "advice": "Root mount failure. Verify root= partition exists, rootfstype= matches fs, and storage/fs drivers are built-in or in initramfs.",
    },
    {
        "pattern": r"mkinitfs:\s*.*hook.*not found|hook.*failed",
        "advice": "mkinitfs hook missing/failed. Inspect /etc/mkinitfs/hooks/ and deviceinfo_* variables in device package.",
    },
    {
        "pattern": r"Unknown filesystem type|rootfstype.*not configured",
        "advice": "Filesystem driver not loaded. Ensure CONFIG_EXT4_FS=y / CONFIG_F2FS_FS=y (built-in) or included in initramfs; set rootfstype=.",
    },
    {
        "pattern": r"dma_alloc_coherent failed|CMA:\s*Unable to allocate|cma:\s*allocation failed",
        "advice": "CMA exhaustion. Increase CMA: add cma=256M (or similar) to cmdline or raise CONFIG_CMA_SIZE_MBYTES.",
    },
    {
        "pattern": r"Machine model.*not found|setup_machine.*dt.*not found",
        "advice": "DT not loaded or compatible mismatch. Verify bootloader DTB handoff, kernel CONFIG_OF=y, and correct compatible string.",
    },
]

ERRNO_MAP: Dict[str, str] = {
    "-1": "EPERM",
    "-2": "ENOENT",
    "-5": "EIO",
    "-6": "ENXIO",
    "-12": "ENOMEM",
    "-13": "EACCES",
    "-16": "EBUSY",
    "-17": "EEXIST",
    "-19": "ENODEV",
    "-22": "EINVAL",
    "-28": "ENOSPC",
    "-110": "ETIMEDOUT",
    "-517": "EPROBE_DEFER",
}

# -------------------------
# Data structures
# -------------------------

@dataclasses.dataclass
class Signal:
    kind: str
    line_no: int
    line: str
    ts: Optional[float] = None
    errno: Optional[str] = None
    errno_hint: Optional[str] = None

@dataclasses.dataclass
class SignalsBundle:
    counts: Dict[str, int]
    signals: Dict[str, List[Signal]]
    last_timestamp: Optional[float]
    note: str = ""


# -------------------------
# Utilities
# -------------------------

_TS_RE = re.compile(r"^\s*(?:<\d+>)?\[\s*(\d+(?:\.\d+)?)\]\s+")
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_ADDRISH_RE = re.compile(r"\b[0-9a-fA-F]{8,}\b")
_WS_RE = re.compile(r"\s+")


def extract_boot_timestamp(line: str) -> Optional[float]:
    m = _TS_RE.match(line)
    if not m:
        return None
    try:
        return float(m.group(1))
    except Exception:
        return None


def get_last_timestamp(lines: List[str]) -> Optional[float]:
    ts = None
    for ln in lines:
        t = extract_boot_timestamp(ln)
        if t is not None:
            ts = t
    return ts


def normalize_error_line(line: str) -> str:
    # Strip leading timestamp and normalize noise.
    line = _TS_RE.sub("", line)
    line = _HEX_RE.sub("0xADDR", line)
    # Replace long address-ish tokens
    line = _ADDRISH_RE.sub("ADDR", line)
    # Collapse whitespace
    line = _WS_RE.sub(" ", line).strip()
    return line


def luhn_ok(number: str) -> bool:
    # Conservative: used only as a hint (we still redact aggressively in --safe)
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 14:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def redact_text(text: str, aggressive: bool = True) -> str:
    # Basic redactions (safe defaults)
    # Emails
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]", text)
    # IPs
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]", text)
    # UUIDs
    text = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "[REDACTED_UUID]", text)

    if aggressive:
        # Long hashes / tokens
        text = re.sub(r"\b[0-9a-fA-F]{32,}\b", "[REDACTED_HASH]", text)
        # IMEI-ish 15 digit sequences (prefer redact; luhn_ok is only a hint)
        def _redact_15(m: re.Match) -> str:
            s = m.group(0)
            if luhn_ok(s):
                return "[REDACTED_IMEI]"
            return "[REDACTED_15DIGIT]"
        text = re.sub(r"\b\d{15}\b", _redact_15, text)
        # ICCID / long decimal
        text = re.sub(r"\b\d{19,20}\b", "[REDACTED_ICCID]", text)

    return text


def decode_errno(line: str) -> str:
    """
    Extract errno from common patterns:
      error -22, err=-22, ret=-22, errno=-22, status: -110
      probe returned -22
      failed with error -22
      setup ... status -110
    """
    m = re.search(r"(?:error|err|ret|errno|status|returned)[:\s=]+(-\d+)\b", line, re.I)
    if not m:
        m = re.search(r"(?:with error\s+|=\s*)(-\d+)\b", line, re.I)
    if not m:
        # Tight fallback (v1.3.2a+): require error-ish keyword near the negative number
        m = re.search(
            r"(?:probe|init|setup)\b.*?(?:failed|returned|error|errno|status).*?(-\d+)\b",
            line,
            re.I,
        )
    if not m:
        return ""
    errno_val = m.group(1)
    return ERRNO_MAP.get(errno_val, f"errno {errno_val}")


def check_file_size(path: Path, warn_mb: int = 50, max_mb: int = 200) -> Tuple[bool, str]:
    try:
        size_mb = path.stat().st_size / (1024 * 1024)
    except OSError as e:
        return True, f"⚠️  Could not stat file size: {e}"
    if size_mb > max_mb:
        return False, f"❌ Log file too large ({size_mb:.1f}MB > {max_mb}MB). Use --last-only or split the log."
    if size_mb > warn_mb:
        return True, f"⚠️  Large log file ({size_mb:.1f}MB). Processing may take time/RAM."
    return True, ""


def lint_dts_file(dts_path: Path, include_dirs: Optional[List[str]] = None) -> str:
    if not dts_path.exists():
        return f"❌ DTS not found: {dts_path}"
    if include_dirs:
        missing = [inc for inc in include_dirs if not Path(inc).exists()]
        if missing:
            return "❌ Include dirs not found:\n  " + "\n  ".join(missing)

    cmd = ["dtc", "-I", "dts", "-O", "dtb", "-o", os.devnull]
    if include_dirs:
        for inc in include_dirs:
            cmd.extend(["-i", inc])
    cmd.append(str(dts_path))

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return "⚠️  dtc not installed. Install device-tree-compiler."
    except subprocess.TimeoutExpired:
        return "❌ dtc lint timed out (includes too complex?)"

    if res.returncode == 0:
        return f"✅ DTC Validated: {dts_path}"
    err = (res.stderr or res.stdout or "").strip()
    if "parse error" in err.lower():
        err += "\n\n💡 Hint: check missing semicolons/braces."
    if "no such file" in err.lower():
        err += "\n\n💡 Hint: verify include dirs (-i)."
    return f"❌ DTC Errors:\n{err}"


# -------------------------
# Extraction / Bundling
# -------------------------

def extract_signals(lines: List[str], tail: int = 200, no_tail: bool = False) -> SignalsBundle:
    counts: Dict[str, int] = defaultdict(int)
    signals: Dict[str, List[Signal]] = defaultdict(list)

    last_ts = get_last_timestamp(lines)

    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        ts = extract_boot_timestamp(line)

        for kind, rx in PATTERNS.items():
            if rx.search(line):
                counts[kind] += 1
                errno_hint = decode_errno(line)
                errno = None
                m = re.search(r"(-\d+)\b", line)
                if m:
                    errno = m.group(1)
                signals[kind].append(Signal(kind=kind, line_no=idx, line=line, ts=ts, errno=errno, errno_hint=errno_hint))

    # Tail blocks: keep last N lines for context unless disabled
    note = ""
    if no_tail:
        note = "Tail suppressed (--no-tail)."
    elif len(lines) > tail:
        note = f"Log truncated for display (showing last {tail} lines for context)."

    return SignalsBundle(counts=dict(counts), signals=dict(signals), last_timestamp=last_ts, note=note)


# -------------------------
# Timeline / Sparkline
# -------------------------

def build_timeline_counts(lines: List[str], bundle: SignalsBundle, kind: str, bucket_s: float = 5.0) -> List[int]:
    # Build histogram counts by timestamp buckets
    ts_values: List[float] = []
    for s in bundle.signals.get(kind, []):
        if s.ts is not None:
            ts_values.append(s.ts)
    if not ts_values:
        return []
    max_ts = max(ts_values)
    n = int(max_ts // bucket_s) + 1
    buckets = [0] * n
    for t in ts_values:
        b = int(t // bucket_s)
        if 0 <= b < n:
            buckets[b] += 1
    return buckets


_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _spark(values: List[int], width: int = 28) -> str:
    if not values:
        return ""
    if len(values) > width:
        step = len(values) / width
        sampled: List[int] = []
        i = 0.0
        while len(sampled) < width and int(i) < len(values):
            sampled.append(values[int(i)])
            i += step
        values = sampled
    mx = max(values) or 1
    out = []
    for v in values:
        idx = int((v / mx) * (len(_SPARK_CHARS) - 1))
        out.append(_SPARK_CHARS[idx])
    return "".join(out)


# -------------------------
# Markdown formatting
# -------------------------

def _context_block(lines: List[str], line_no: int, radius: int = 8) -> List[str]:
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    out = []
    for i in range(start, end + 1):
        prefix = ">> " if i == line_no else "   "
        out.append(f"{prefix}L{i:05d}: {lines[i-1].rstrip()}")
    return out


def format_signals_md(
    lines: List[str],
    bundle: SignalsBundle,
    blocks: List[Tuple[int, int, List[str]]] = [],
    dts_report: str = "",
    timeline: bool = False,
    orig_file: str = "",
) -> str:
    md: List[str] = []
    md.append(f"# pmOS Port Assist Report (v{VERSION})")
    if orig_file:
        md.append(f"- Source: `{orig_file}`")
    md.append(f"- Generated: {_dt.datetime.now().isoformat(timespec='seconds')}")
    md.append("")

    # Lazy summary (top)
    summary_parts: List[str] = []
    if bundle.counts.get("panic_oops", 0) > 0:
        summary_parts.append(f"CRITICAL: {bundle.counts['panic_oops']} panic/oops")
    if bundle.counts.get("init_fail", 0) > 0:
        summary_parts.append("INIT FAIL (no userspace init)")
    if bundle.counts.get("vfs_root", 0) > 0:
        summary_parts.append("ROOT MOUNT FAIL (check root= vs partitions)")
    if bundle.last_timestamp is not None and bundle.last_timestamp < 8:
        summary_parts.append(f"very early death @ {bundle.last_timestamp:.1f}s")

    md.append("**LAZY SUMMARY →** " + ("  ●  ".join(summary_parts) if summary_parts else "Looks relatively clean so far"))
    md.append("")

    # Counts
    md.append("## Counts")
    keys = ["panic_oops", "init_fail", "vfs_root", "probe_fail", "firmware_missing", "device_tree"]
    for k in keys:
        md.append(f"- **{k}**: {bundle.counts.get(k, 0)}")
    if bundle.last_timestamp is not None:
        md.append(f"- **last_timestamp**: {bundle.last_timestamp:.2f}s")
    md.append("")

    # Timeline
    if timeline:
        md.append("## Timeline (sparkline, 5s buckets)")
        has_any = False
        for k in keys:
            vals = build_timeline_counts(lines, bundle, k, bucket_s=5.0)
            if vals:
                sp = _spark(vals, width=28)
                md.append(f"- {k:16s} {sp}  (max {max(vals)})")
                has_any = True
        if not has_any:
            md.append("*(No kernel timestamps detected — timeline unavailable)*")
            md.append("*Tip: enable CONFIG_PRINTK_TIME=y*")
        md.append("")

    # DTS report (optional)
    if dts_report:
        md.append("## DTS Lint")
        md.append(dts_report)
        md.append("")

    # Signals with context
    md.append("## Signals (with context)")
    any_sig = False
    for k in keys:
        sigs = bundle.signals.get(k, [])
        if not sigs:
            continue
        any_sig = True
        md.append(f"### {k} ({len(sigs)})")
        for s in sigs[:30]:
            extra = f" [{s.errno_hint}]" if s.errno_hint else ""
            md.append(f"- L{s.line_no}: {s.line}{extra}")
            ctx = _context_block(lines, s.line_no, radius=6 if k in ("panic_oops", "vfs_root") else 4)
            md.append("```")
            md.extend(ctx)
            md.append("```")
        if len(sigs) > 30:
            md.append(f"*(truncated: showing 30 of {len(sigs)})*")
        md.append("")
    if not any_sig:
        md.append("*(No high-priority signals detected by current patterns.)*")
        md.append("")

    # Known issues advice
    md.append("## Offline Advice (KNOWN_ISSUES hits)")
    hits = 0
    content = "\n".join(lines)
    for ki in KNOWN_ISSUES:
        if re.search(ki["pattern"], content, re.I):
            hits += 1
            md.append(f"- **Match:** `{ki['pattern']}`")
            md.append(f"  - Advice: {ki['advice']}")
    if hits == 0:
        md.append("*(No KNOWN_ISSUES patterns matched.)*")
    md.append("")

    if bundle.note:
        md.append("## Notes")
        md.append(bundle.note)
        md.append("")

    return "\n".join(md)


# -------------------------
# Compare / Diff
# -------------------------

def bundle_signature(bundle: SignalsBundle) -> Set[str]:
    sigs: Set[str] = set()
    for kind, items in bundle.signals.items():
        for s in items:
            norm = normalize_error_line(s.line)
            if norm:
                sigs.add(f"{kind}:{norm}")
    return sigs


def format_comparison_md(prev_lines: List[str], cur_lines: List[str], prev: SignalsBundle, cur: SignalsBundle) -> str:
    md: List[str] = []
    md.append(f"# pmOS Port Assist Diff (v{VERSION})")
    md.append(f"- Generated: {_dt.datetime.now().isoformat(timespec='seconds')}")
    md.append("")

    prev_ts = prev.last_timestamp or 0.0
    cur_ts = cur.last_timestamp or 0.0
    delta = cur_ts - prev_ts
    md.append(f"**Delta:** prev={prev_ts:.2f}s → cur={cur_ts:.2f}s  (**{delta:+.2f}s**)")
    md.append("")

    prev_sig = bundle_signature(prev)
    cur_sig = bundle_signature(cur)

    new = sorted(cur_sig - prev_sig)
    gone = sorted(prev_sig - cur_sig)

    md.append("## New signals")
    if not new:
        md.append("*(none)*")
    else:
        for x in new[:100]:
            md.append(f"- {x}")
    md.append("")

    md.append("## Resolved signals")
    if not gone:
        md.append("*(none)*")
    else:
        for x in gone[:100]:
            md.append(f"- {x}")
    md.append("")

    # Quick summary
    md.append("## Summary")
    if new and not gone:
        md.append("- Regression: new failures appeared.")
    elif gone and not new:
        md.append("- Improvement: failures resolved.")
    elif gone and new:
        md.append("- Mixed: some resolved, some new.")
    else:
        md.append("- No semantic change detected (likely stuck at same wall).")
    md.append("")

    return "\n".join(md)


# -------------------------
# Project paths / output
# -------------------------

def project_paths(project: Optional[str], session_dir: Optional[str]) -> Tuple[Optional[Path], Optional[Path]]:
    if not project:
        return None, None
    base = Path(session_dir) if session_dir else Path(".")
    base_dir = base / project
    hist_dir = base_dir / "history"
    base_dir.mkdir(parents=True, exist_ok=True)
    hist_dir.mkdir(parents=True, exist_ok=True)
    return base_dir, hist_dir


def write_latest_and_history(base_dir: Path, hist_dir: Path, stem: str, content: str, ext: str = ".md") -> Path:
    latest = base_dir / f"latest.{stem}{ext}"
    latest.write_text(content, encoding="utf-8")
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    snap = hist_dir / f"{ts}.{stem}{ext}"
    snap.write_text(content, encoding="utf-8")
    return latest


def emit_json(base_dir: Path, bundle: SignalsBundle, out_name: str = "latest.signals.json") -> None:
    payload = {
        "version": VERSION,
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "counts": bundle.counts,
        "last_timestamp": bundle.last_timestamp,
        "signals": {
            k: [
                {
                    "line_no": s.line_no,
                    "ts": s.ts,
                    "errno": s.errno,
                    "errno_hint": s.errno_hint,
                    "line": normalize_error_line(s.line),
                }
                for s in v
            ]
            for k, v in bundle.signals.items()
        },
    }
    (base_dir / out_name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


# -------------------------
# Pulse mode (heartbeat)
# -------------------------

def run_pulse(path_str: str, interval: float = 1.0, stop_on_panic: bool = False) -> None:
    """
    Live heartbeat monitor.
    - path_str == '-' : read stdin line-by-line (works with adb dmesg -w pipes)
    - else file tail: reads appended bytes only (tracks offset)
    Autostop: exit on first panic/oops detection (consumer exit stops producer pipe).
    """
    print(f"⚡ Pulse Mode active on {path_str} (Ctrl+C to stop)")
    last_print = 0.0
    last_ts = 0.0
    p_count = 0
    i_count = 0
    v_count = 0
    seen_panic = False

    def consume_line(line: str) -> None:
        nonlocal last_ts, p_count, i_count, v_count, seen_panic
        t = extract_boot_timestamp(line)
        if t is not None:
            last_ts = t
        if PATTERNS["panic_oops"].search(line):
            p_count += 1
        if PATTERNS["init_fail"].search(line):
            i_count += 1
        if PATTERNS["vfs_root"].search(line):
            v_count += 1

        if stop_on_panic and (p_count > 0) and not seen_panic:
            seen_panic = True
            sys.stdout.write(f"\r\033[K💓 [{last_ts:>7.2f}s] P:{p_count} I:{i_count} V:{v_count}")
            sys.stdout.flush()
            print("\n\n🚨 PANIC DETECTED — stopping pulse.")
            raise SystemExit(3)

    def heartbeat(force: bool = False) -> None:
        nonlocal last_print
        now = time.time()
        if force or (now - last_print) >= interval:
            last_print = now
            sys.stdout.write(f"\r\033[K💓 [{last_ts:>7.2f}s] P:{p_count} I:{i_count} V:{v_count}")
            sys.stdout.flush()

    try:
        if path_str == "-":
            for line in sys.stdin:
                consume_line(line)
                heartbeat(False)
            heartbeat(True)
            print("\nPulse complete (stdin closed).")
            return

        p = Path(path_str)
        offset = 0
        while True:
            if p.exists():
                try:
                    size = p.stat().st_size
                except OSError:
                    size = 0
                if size < offset:
                    offset = 0  # truncation/rotation
                if size > offset:
                    with p.open("r", errors="ignore") as f:
                        f.seek(offset)
                        chunk = f.read()
                        offset = f.tell()
                    if chunk:
                        for ln in chunk.splitlines(True):
                            consume_line(ln)
            heartbeat(False)
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\nPulse stopped.")


# -------------------------
# Main
# -------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=f"pmOS Port Assist v{VERSION}")
    ap.add_argument("logfile", help="Path to log file, or '-' for stdin")
    ap.add_argument("--version", action="store_true", help="Print version and exit")

    ap.add_argument("--compare", default=None, help="Compare against previous log file (semantic diff)")
    ap.add_argument("--project", default=None, help="Project name (enables latest.* + history output)")
    ap.add_argument("--session-dir", default=None, help="Base directory for projects (default: cwd)")
    ap.add_argument("--safe", action="store_true", help="Enable aggressive redaction (recommended)")
    ap.add_argument("--timeline", action="store_true", help="Include timeline sparkline (requires timestamps)")
    ap.add_argument("--last-only", action="store_true", help="Only analyze last chunk of the log (faster)")
    ap.add_argument("--tail", type=int, default=200, help="Tail size for context (default 200)")
    ap.add_argument("--no-tail", action="store_true", help="Do not include tail/context blocks")
    ap.add_argument("--json", action="store_true", help="Also emit latest.signals.json")

    ap.add_argument("--dts-file", default=None, help="Run dtc lint on a .dts file")
    ap.add_argument("--dtc-include", action="append", default=None, help="Include dir for dtc (-i). Can repeat.")

    ap.add_argument("--pulse", action="store_true", help="Live heartbeat monitor (stdin or file tail)")
    ap.add_argument("--autostop", action="store_true", help="With --pulse: stop on first panic/oops")

    args = ap.parse_args()

    if args.version:
        print(VERSION)
        return 0

    # Pulse short-circuit
    if args.pulse:
        run_pulse(args.logfile, interval=1.0, stop_on_panic=args.autostop)
        return 0

    # Resolve output dirs early
    base_dir, hist_dir = project_paths(args.project, args.session_dir)

    # Read input
    if args.logfile == "-":
        raw = sys.stdin.read()
        lines = raw.splitlines(True)
        orig = "stdin"
    else:
        log_path = Path(args.logfile)
        if not log_path.exists():
            print("❌ Log file not found.", file=sys.stderr)
            return 2
        ok, msg = check_file_size(log_path)
        if msg:
            print(msg)
        if not ok:
            return 1
        raw = log_path.read_text(errors="ignore")
        lines = raw.splitlines(True)
        orig = str(log_path)

    # Safe mode redaction
    if args.safe:
        lines = [redact_text(ln, aggressive=True) for ln in lines]

    # Optional last-only speedup
    if args.last_only and len(lines) > 5000:
        lines = lines[-5000:]

    # DTS lint
    dts_report = ""
    if args.dts_file:
        dts_report = lint_dts_file(Path(args.dts_file), include_dirs=args.dtc_include)

    # Analyze
    bundle = extract_signals(lines, tail=args.tail, no_tail=args.no_tail)
    md = format_signals_md(lines, bundle, blocks=[], dts_report=dts_report, timeline=args.timeline, orig_file=orig)

    if base_dir and hist_dir:
        write_latest_and_history(base_dir, hist_dir, "analysis", md, ext=".md")
        if args.json:
            emit_json(base_dir, bundle, out_name="latest.signals.json")
    else:
        print(md)

    # Compare (optional)
    if args.compare:
        prev_path = Path(args.compare)
        if not prev_path.exists():
            print("⚠️  --compare file not found; skipping diff.", file=sys.stderr)
            return 0
        prev_raw = prev_path.read_text(errors="ignore")
        prev_lines = prev_raw.splitlines(True)
        if args.safe:
            prev_lines = [redact_text(ln, aggressive=True) for ln in prev_lines]
        if args.last_only and len(prev_lines) > 5000:
            prev_lines = prev_lines[-5000:]

        prev_bundle = extract_signals(prev_lines, tail=args.tail, no_tail=args.no_tail)
        diff_md = format_comparison_md(prev_lines, lines, prev_bundle, bundle)

        if base_dir and hist_dir:
            write_latest_and_history(base_dir, hist_dir, "diff", diff_md, ext=".md")
        else:
            print(diff_md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
