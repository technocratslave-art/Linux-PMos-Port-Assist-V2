# Contributing to pmos-port-assist

Thanks for helping improve this toolkit. The project is intentionally conservative: stable defaults, shell-safe behavior, log-true outputs. Contributions should preserve that.

## Goals

- **Forensic correctness over cleverness**
- **Backward compatibility**
- **Deterministic output** (same input → same analysis)
- **Safe sharing** (redaction prevents accidental leaks)
- **Minimal dependencies** (dtc optional)

## Repo layout

- `pmos-port-assist.py` — analyzer (“brain”)
- `pmos-watchdog.sh` — capture/loop orchestrator (“nervous system”)
- `README.md` — usage and environment variables

## Development rules

1. **No breaking CLI changes**
   - New flags must be opt-in and default-off unless they are pure additions that do not change outputs for existing invocations.

2. **Never weaken redaction defaults**
   - `--safe` must remain safe for public pastebins.
   - If you add new detectors, prefer *false positives* over *false negatives* in safe mode.

3. **No “AI loops” or self-modifying behavior**
   - Analysis must remain grounded in observed logs, pattern matches, and deterministic transforms.

4. **Keep it shell-safe**
   - Watchdog must remain POSIX-ish bash, avoid fragile subshell state and unquoted expansions.
   - Use `set -euo pipefail` only if you audit all call sites; otherwise prefer explicit error checks.

5. **Outputs must be stable**
   - If you change normalization, signature generation, or diffing, include a short rationale and before/after examples.

## How to test changes

### Python quick checks

Compile:
```bash
python3 -m py_compile pmos-port-assist.py
