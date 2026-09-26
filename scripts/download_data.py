#!/usr/bin/env python
"""Download the real public datasets VANTAGE uses (resumable, sha256-verified).

    python scripts/download_data.py                 # into $VANTAGE_DATA_DIR or ./data
    python scripts/download_data.py --dest D:/datasets/vantage
    python scripts/download_data.py --skip-verify   # accept upstream changes (prints new hashes)

Datasets (none are committed to git):
  * MITRE ATT&CK Enterprise STIX 2.1, v19.2 (current) and v8.2 (the release the CIS mapping
    targets) - github.com/mitre-attack/attack-stix-data - ATT&CK Terms of Use (royalty-free,
    attribution required).
  * CIS Controls v8 -> MITRE Enterprise ATT&CK v8.2 master mapping (xlsx) - Center for Internet
    Security - CC BY-NC-ND 4.0.
  * SigmaHQ rule release r2026-07-01 (sigma_all_rules.zip) - Detection Rule License (DRL) 1.1.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vantage import paths  # noqa: E402

ATTACK = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
FILES = {
    paths.ATTACK_FILE: (f"{ATTACK}/{paths.ATTACK_FILE}", None),
    paths.ATTACK_CIS_FILE: (f"{ATTACK}/{paths.ATTACK_CIS_FILE}", None),
    paths.SIGMA_FILE: (
        f"https://github.com/SigmaHQ/sigma/releases/download/{paths.SIGMA_RELEASE}/sigma_all_rules.zip",
        None),
    paths.CIS_FILE: ("https://learn.cisecurity.org/CIS-Controls-v8-Master-Mapping-to-MITRE-Enterprise-Attck-v8.2",
                     None),
}
# sha256 of the exact files the published results were produced from
SHA256 = {
}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, retries: int = 30) -> None:
    part = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, retries + 1):
        have = part.stat().st_size if part.exists() else 0
        req = urllib.request.Request(url, headers={"User-Agent": "vantage-downloader/1.0"})
        if have:
            req.add_header("Range", f"bytes={have}-")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (fixed https URLs)
                mode = "ab" if have and r.status == 206 else "wb"
                with open(part, mode) as fh:
                    while chunk := r.read(1 << 16):
                        fh.write(chunk)
            part.replace(dest)
            return
        except Exception as e:  # network resets are common on large raw.githubusercontent files
            print(f"  retry {attempt}/{retries} after {type(e).__name__}: {e}", file=sys.stderr)
            time.sleep(min(2 * attempt, 20))
    raise SystemExit(f"failed to download {url}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default=os.environ.get("VANTAGE_DATA_DIR") or str(paths.data_dir()))
    ap.add_argument("--skip-verify", action="store_true")
    a = ap.parse_args()
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, (url, _) in FILES.items():
        p = dest / name
        if not p.exists():
            print(f"downloading {name} ...")
            fetch(url, p)
        digest = sha256(p)
        want = SHA256.get(name)
        status = "ok" if want == digest else ("UNPINNED" if not want else "MISMATCH")
        if status == "MISMATCH" and not a.skip_verify:
            bad += 1
        print(f"{status:8} {p.stat().st_size / 1e6:7.1f} MB  {digest}  {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
