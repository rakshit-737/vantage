#!/usr/bin/env python
"""Determinism check: compare freshly generated results/ with the committed ones.

    python scripts/check_results.py            # against HEAD
    python scripts/check_results.py --ref v1.1.0

Every results/*.json is compared with timing and provenance keys removed (wall times and the run
that produced a file legitimately differ between runs); results/*.csv.gz is compared after
decompression. Prints each differing value and exits 1 if anything else changed.
"""
from __future__ import annotations

import argparse
import gzip
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


def diff(a, b, path: str = "", out: list[str] | None = None) -> list[str]:
    out = [] if out is None else out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: {'missing in new' if k not in b else 'not in committed'}")
            else:
                diff(a[k], b[k], f"{path}/{k}", out)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            diff(x, y, f"{path}[{i}]", out)
    elif a != b:
        out.append(f"{path}: committed {json.dumps(a)[:120]} != new {json.dumps(b)[:120]}")
    return out


def committed(ref: str, rel: str) -> bytes | None:
    r = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=ROOT, capture_output=True, check=False)  # nosec B603 B607
    return r.stdout if r.returncode == 0 else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ref", default="HEAD", help="git ref holding the committed results (default HEAD)")
    a = ap.parse_args()
    bad = 0
    files = sorted((ROOT / "results").glob("*.json")) + sorted((ROOT / "results").glob("*.csv.gz"))
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        old = committed(a.ref, rel)
        if old is None:
            print(f"NEW      {rel} (not in {a.ref})")
            continue
        if f.suffix == ".json":
            problems = diff(strip(json.loads(old)), strip(json.loads(f.read_text(encoding="utf-8"))))
        else:
            same = gzip.decompress(old) == gzip.decompress(f.read_bytes())
            problems = [] if same else ["decompressed content differs"]
        status = "ok" if not problems else "DIFFERS"
        print(f"{status:<8} {rel}")
        for p in problems[:25]:
            print(f"         {p}")
        bad += bool(problems)
    print(f"{bad} file(s) differ from {a.ref} (timing and provenance ignored)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
