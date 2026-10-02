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

# Round 3: extra CTID Mappings Explorer frameworks + NIST OSCAL catalog/baselines (in <data>/ctid/)
CTID_DIR = "ctid"
CTID_FRAMEWORKS = {  # short name -> (file, ATT&CK version the mapping targets)
    "AWS": ("aws-12.12.2024_attack-16.1-enterprise.json", "16.1"),
    "Azure": ("azure-04.26.2025_attack-16.1-enterprise.json", "16.1"),
    "GCP": ("gcp-03.06.2025_attack-16.1-enterprise.json", "16.1"),
    "M365": ("m365-07.18.2025_attack-16.1-enterprise.json", "16.1"),
    "CRI-2.1": ("cri_profile-v2.1_attack-16.1-enterprise.json", "16.1"),
    "CSA-CCM-4.1": ("csa_ccm-4.1_attack-17.1-enterprise.json", "17.1"),
}
# ATT&CK releases the CTID mappings were authored against (for the per-framework technique universe)
ATTACK_RELEASE_FILES = {v: f"enterprise-attack-{v}.json" for v in ("16.1", "17.1")}
OSCAL_CATALOG = "NIST_SP-800-53_rev5_catalog.json"
OSCAL_BASELINES = {b: f"NIST_SP-800-53_rev5_{b}-baseline_profile.json"
                   for b in ("LOW", "MODERATE", "HIGH", "PRIVACY")}


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
