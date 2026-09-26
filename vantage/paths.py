"""Where real datasets live. Datasets are never committed; see scripts/download_data.py."""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

ATTACK_VERSION = "19.2"          # pinned ATT&CK Enterprise release used for the live catalog
ATTACK_CIS_VERSION = "8.2"       # ATT&CK release the official CIS v8 mapping was authored against
SIGMA_RELEASE = "r2026-07-01"    # pinned SigmaHQ release

ATTACK_FILE = f"enterprise-attack-{ATTACK_VERSION}.json"
ATTACK_CIS_FILE = f"enterprise-attack-{ATTACK_CIS_VERSION}.json"
SIGMA_FILE = f"sigma_all_rules-{SIGMA_RELEASE}.zip"
CIS_FILE = "cis_v8_attack_v82_master_mapping.xlsx"
NIST_ATTACK_VERSION = "16.1"     # ATT&CK release the CTID NIST 800-53 rev5 mapping targets
NIST_FILE = f"nist_800_53-rev5_attack-{NIST_ATTACK_VERSION}-enterprise.json"


def data_dir() -> Path:
    """Raw downloads. Override with VANTAGE_DATA_DIR (e.g. a folder outside the repo)."""
    return Path(os.environ.get("VANTAGE_DATA_DIR") or REPO_ROOT / "data")


def processed_dir() -> Path:
    return data_dir() / "processed"


def catalog_path() -> Path:
    return processed_dir() / "catalog.json"


def nist_catalog_path() -> Path:
    """Same techniques/rules as catalog.json, but NIST SP 800-53 rev5 controls instead of CIS v8."""
    return processed_dir() / "catalog-nist.json"


def have_real_data() -> bool:
    return catalog_path().exists()
