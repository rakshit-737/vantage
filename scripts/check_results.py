#!/usr/bin/env python
"""Determinism check: compare freshly generated results/ with the committed ones.

    python scripts/check_results.py            # against HEAD
    python scripts/check_results.py --ref v1.1.0

Every results/*.json is compared with timing and provenance keys removed (wall times and the run
that produced a file legitimately differ between runs); results/*.csv.gz is compared after
decompression. Prints each differing value and exits 1 if anything else changed.

Floats are compared with a small tolerance. The sentence-embedding encoders run on whatever CPU
model the runner gets, and float reductions differ in the last bits between CPU models; that can
swap two near-tied techniques deep in a ranking and move a single control's AP@200 by about
1e-4 (seen between two runs on ubuntu-24.04). Reported means are rounded to 3 decimals, so JSON
floats may differ by at most --tol (default 0.002) and per-control scores by --tol-control
(default 0.01). Strings, integers and the set of rows must match exactly.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import subprocess  # nosec B404 - fixed git command, no shell
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VOLATILE = {"generated", "python", "platform", "provenance", "seconds", "greedy_ms", "ilp_ms", "coverage_ms",
            "spof_fast_s", "spof_bruteforce_s", "speedup"}


def strip(x):
    if isinstance(x, dict):
        return {k: strip(v) for k, v in x.items() if k not in VOLATILE}
    if isinstance(x, list):
        return [strip(v) for v in x]
    return x


def close(a, b, tol: float) -> bool:
    """Equal, or both non-integer numbers within ``tol``."""
    if a == b:
        return True
    nums = all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (a, b))
    return nums and (isinstance(a, float) or isinstance(b, float)) and abs(a - b) <= tol


def diff(a, b, tol: float, path: str = "", out: list[str] | None = None) -> list[str]:
    out = [] if out is None else out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: {'missing in new' if k not in b else 'not in committed'}")
            else:
                diff(a[k], b[k], tol, f"{path}/{k}", out)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            diff(x, y, tol, f"{path}[{i}]", out)
    elif not close(a, b, tol):
        out.append(f"{path}: committed {json.dumps(a)[:120]} != new {json.dumps(b)[:120]}")
    return out


def num(x: str) -> float | None:
    try:
        return float(x)
    except ValueError:
        return None


def diff_csv(old: bytes, new: bytes, tol: float) -> tuple[list[str], float]:
    """Row-by-row comparison of two gzip CSVs; numeric cells within ``tol``. Also the max |diff|."""
    a = list(csv.reader(io.StringIO(gzip.decompress(old).decode("utf-8"))))
    b = list(csv.reader(io.StringIO(gzip.decompress(new).decode("utf-8"))))
    if len(a) != len(b) or (a and a[0] != b[0]):
        return [f"shape/header differs: {len(a)} vs {len(b)} rows"], 0.0
    out, worst = [], 0.0
    for i, (r, s) in enumerate(zip(a, b, strict=True)):
        for j, (x, y) in enumerate(zip(r, s, strict=True)):
            if x == y:
                continue
            u, v = num(x), num(y)
            if u is None or v is None or abs(u - v) > tol:
                out.append(f"row {i} {r[:3]} {a[0][j]}: committed {x} != new {y}")
            else:
                worst = max(worst, abs(u - v))
    return out, worst


def committed(ref: str, rel: str) -> bytes | None:
    r = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=ROOT, capture_output=True, check=False)  # nosec B603 B607
    return r.stdout if r.returncode == 0 else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ref", default="HEAD", help="git ref holding the committed results (default HEAD)")
    ap.add_argument("--tol", type=float, default=0.002, help="tolerance for floats in results/*.json")
    ap.add_argument("--tol-control", type=float, default=0.01, help="tolerance for per-control scores (csv.gz)")
    a = ap.parse_args()
    bad = 0
    files = sorted((ROOT / "results").glob("*.json")) + sorted((ROOT / "results").glob("*.csv.gz"))
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        old = committed(a.ref, rel)
        if old is None:
            print(f"NEW      {rel} (not in {a.ref})")
            continue
        note = ""
        if f.suffix == ".json":
            problems = diff(strip(json.loads(old)), strip(json.loads(f.read_text(encoding="utf-8"))), a.tol)
        else:
            problems, worst = diff_csv(old, f.read_bytes(), a.tol_control)
            note = f" (max |diff| within tolerance: {worst:.2g})" if worst else ""
        status = "ok" if not problems else "DIFFERS"
        print(f"{status:<8} {rel}{note}")
        for p in problems[:25]:
            print(f"         {p}")
        bad += bool(problems)
    print(f"{bad} file(s) differ from {a.ref} (timing and provenance ignored)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
