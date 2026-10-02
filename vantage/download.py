#!/usr/bin/env python
"""Download the real public datasets VANTAGE uses (resumable, sha256-verified).

    python -m vantage.download                 # into $VANTAGE_DATA_DIR or ./data
    python -m vantage.download --dest D:/datasets/vantage
    python -m vantage.download --skip-verify   # accept upstream changes (prints new hashes)

Datasets (none are committed to git):
  * MITRE ATT&CK Enterprise STIX 2.1, v19.2 (current) and v8.2 (the release the CIS mapping
    targets) - github.com/mitre-attack/attack-stix-data - ATT&CK Terms of Use (royalty-free,
    attribution required).
  * CIS Controls v8 -> MITRE Enterprise ATT&CK v8.2 master mapping (xlsx) - Center for Internet
    Security - CC BY-NC-ND 4.0.
  * CTID Mappings Explorer: NIST SP 800-53 rev5 -> ATT&CK v16.1 (JSON) - Apache-2.0.
  * SigmaHQ rule release r2026-07-01 (sigma_all_rules.zip) - Detection Rule License (DRL) 1.1.
  * ATT&CK Enterprise v16.1 and v17.1 STIX (the releases the CTID mappings target) - used only to
    restrict each framework's auto-mapping candidates to techniques that existed when it was mapped.
  * (into ctid/) CTID Mappings Explorer: AWS, Azure, GCP, M365 security-stack mappings, CRI
    Profile v2.1 and CSA CCM 4.1 -> ATT&CK (Apache-2.0); NIST SP 800-53 rev5 OSCAL catalog and
    SP 800-53B LOW/MODERATE/HIGH/PRIVACY baseline profiles (usnistgov/oscal-content, public domain).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import urllib.request
from pathlib import Path

from vantage import paths

# Upstream git commits the raw URLs are pinned to (the files at these commits match SHA256 below).
ATTACK_SHA = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"   # mitre-attack/attack-stix-data
ME_SHA = "705ca1b87954f9ff8d9eda62fb70b89939331407"       # center-for-threat-informed-defense/mappings-explorer
OSCAL_SHA = "78650f02ad9321bb7b817846f8fbd4f2bcd620de"    # usnistgov/oscal-content
RAW = "https://raw.githubusercontent.com"
ATTACK = f"{RAW}/mitre-attack/attack-stix-data/{ATTACK_SHA}/enterprise-attack"
ME = f"{RAW}/center-for-threat-informed-defense/mappings-explorer/{ME_SHA}/mappings"
OSCAL = f"{RAW}/usnistgov/oscal-content/{OSCAL_SHA}/nist.gov/SP800-53/rev5/json"
FILES = {
    paths.ATTACK_FILE: (f"{ATTACK}/{paths.ATTACK_FILE}", None),
    paths.ATTACK_CIS_FILE: (f"{ATTACK}/{paths.ATTACK_CIS_FILE}", None),
    paths.SIGMA_FILE: (
        f"https://github.com/SigmaHQ/sigma/releases/download/{paths.SIGMA_RELEASE}/sigma_all_rules.zip",
        None),
    paths.NIST_FILE: (f"{ME}/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/{paths.NIST_FILE}", None),
    paths.CIS_FILE: ("https://learn.cisecurity.org/CIS-Controls-v8-Master-Mapping-to-MITRE-Enterprise-Attck-v8.2",
                     None),
}
_ME_PATH = {"AWS": "aws/attack-16.1/aws-12.12.2024", "Azure": "azure/attack-16.1/azure-04.26.2025",
            "GCP": "gcp/attack-16.1/gcp-03.06.2025", "M365": "m365/attack-16.1/m365-07.18.2025",
            "CRI-2.1": "cri_profile/attack-16.1/cri_profile-v2.1",
            "CSA-CCM-4.1": "csa_ccm/attack-17.1/csa_ccm-4.1"}
for _f in paths.ATTACK_RELEASE_FILES.values():
    FILES[_f] = (f"{ATTACK}/{_f}", None)
for _k, (_f, _v) in paths.CTID_FRAMEWORKS.items():
    FILES[f"{paths.CTID_DIR}/{_f}"] = (f"{ME}/{_ME_PATH[_k]}/enterprise/{_f}", None)
for _f in [paths.OSCAL_CATALOG, *paths.OSCAL_BASELINES.values()]:
    FILES[f"{paths.CTID_DIR}/{_f}"] = (f"{OSCAL}/{_f}", None)
# sha256 of the exact files the published results were produced from
SHA256 = {
    paths.ATTACK_FILE: "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
    paths.ATTACK_CIS_FILE: "8af8ba82d52c2735b1ae6804ab4f2cb8812121d8cdc37e5523ffba671d9ea69b",
    paths.SIGMA_FILE: "5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085",
    paths.NIST_FILE: "355ae97d309c00eb2428e5af07754ff4ca16cfe63928194081d0e883aed929c8",
    paths.CIS_FILE: "f1d3343dc72158ed935b383a10df640f873fec56e00d3e5fd72c64093c74af91",
}

SHA256.update({
    paths.ATTACK_RELEASE_FILES["16.1"]: "8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813",
    paths.ATTACK_RELEASE_FILES["17.1"]: "0d1c347a4d584cf7e11ef46556c33b7689341443bf86299188d46c307274323b",
})
_CTID_SHA = {  # files under <data>/ctid/
    "NIST_SP-800-53_rev5_HIGH-baseline_profile.json":
        "60576970caef91b2cba56d46e5948b72e3b879434fc2a4840bc4179e5e75cfd7",
    "NIST_SP-800-53_rev5_LOW-baseline_profile.json":
        "8fd206017c8d718b44bdef612c2ff321a9fd84d97a515c8ec33c4619accbef6e",
    "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json":
        "9030dbf1f13169947eb97eb101b4bd2f00d3c151b100455a923ac75803f00ea1",
    "NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json":
        "7e650c4397ad633eadeaf510baa523372849b1fa3e18207b6c6b70ed456224f9",
    "NIST_SP-800-53_rev5_catalog.json":
        "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062",
    "aws-12.12.2024_attack-16.1-enterprise.json":
        "21d88ec6db69269e6bd59e6626d6461242bb5e621472d6b992c788142e068004",
    "azure-04.26.2025_attack-16.1-enterprise.json":
        "e13e691d5c19e64d0a7df309f670641ffb8718175e33d34f49375f65ab04cbc2",
    "cri_profile-v2.1_attack-16.1-enterprise.json":
        "9b6ac255cc178733c4b40ed5a52ef14c2062305d33949268658fecaaaa2b265f",
    "csa_ccm-4.1_attack-17.1-enterprise.json":
        "468f64848a458a0291347f3e75136024a7e0bfc9dc6ed37580824d03a9b69c73",
    "gcp-03.06.2025_attack-16.1-enterprise.json":
        "26cd24171f82386f46ec9480b861ae7fc8d4208c5b165a55a8932e06f0f1c96b",
    "m365-07.18.2025_attack-16.1-enterprise.json":
        "6b74d3928acc154e5f93f278f1d88c448feb5af7c9d400bc7911d841956839f7",
}
SHA256.update({f"{paths.CTID_DIR}/{f}": h for f, h in _CTID_SHA.items()})


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, retries: int = 30) -> None:
    part = dest.with_suffix(dest.suffix + ".part")
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url}")
    for attempt in range(1, retries + 1):
        have = part.stat().st_size if part.exists() else 0
        req = urllib.request.Request(url, headers={"User-Agent": "vantage-downloader/1.0"})
        if have:
            req.add_header("Range", f"bytes={have}-")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:  # nosec B310 - https enforced above
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
    ap = argparse.ArgumentParser(description="Download and sha256-verify the pinned public datasets.")
    ap.add_argument("--dest", default=os.environ.get("VANTAGE_DATA_DIR") or str(paths.data_dir()),
                    help="data folder (default: $VANTAGE_DATA_DIR or the default data dir)")
    ap.add_argument("--skip-verify", action="store_true", help="do not fail on a sha256 mismatch")
    a = ap.parse_args()
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, (url, _) in FILES.items():
        p = dest / name
        p.parent.mkdir(parents=True, exist_ok=True)
        fresh = not p.exists()
        if fresh:
            print(f"downloading {name} ...")
            fetch(url, p)
        digest = sha256(p)
        want = SHA256.get(name)
        status = "ok" if want == digest else ("UNPINNED" if not want else "MISMATCH")
        if status == "MISMATCH" and not a.skip_verify:
            bad += 1
            if fresh:  # never leave an unverified download under its final name
                p.replace(p.with_name(p.name + ".mismatch"))
        print(f"{status:8} {p.stat().st_size / 1e6:7.1f} MB  {digest}  {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
