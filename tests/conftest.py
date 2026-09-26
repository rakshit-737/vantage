from pathlib import Path

import pytest

from vantage import paths
from vantage.catalog import catalog_from_dict
from vantage.ingest.attack import load_attack
from vantage.ingest.build import build_catalog
from vantage.ingest.cis import parse_rows
from vantage.ingest.sigma import load_rules

FIX = Path(__file__).parent / "fixtures"

HEADER = ["CIS Control", "CIS Safeguard", "Asset Type", "Security Function", "Title", "Description",
          "IG1", "IG2", "IG3", "V7.1 > V8 Change Log", "ATT&CK Technique ID", "ATT&CK Sub-Technique ID",
          "Combined ATT&CK (Sub-)Technique ID", "ATT&CK (Sub-)Technique Name",
          "ATT&CK (Sub-)Technique Description", "Safeguard Mitigates (Sub-)Technique?"]


def _row(sg, title, desc, igs, tid, ok="Y", fn="Protect"):
    ig = ["x" if n >= igs else None for n in (1, 2, 3)]
    return [sg.split(".")[0], sg, "Devices", fn, title, desc, *ig, "", tid, None, tid, "", "", ok]


# Synthetic rows in the official workbook's layout (the real workbook is CC BY-NC-ND and not committed).
CIS_ROWS = [
    HEADER,
    ["2", "2", None, None, "Inventory of Software", "header row", None, None, None, None, None, None, None,
     None, None, None],
    _row("2.7", "Allowlist Authorized Scripts", "Use technical controls such as digital signatures to "
         "ensure only authorized scripts like PowerShell are allowed to execute.", 3, "T1086"),
    _row("2.7", "Allowlist Authorized Scripts", "same", 3, "T1059"),
    _row("5.2", "Use Unique Passwords", "Use unique passwords for all enterprise assets and protect "
         "credentials in LSASS.", 1, "T1003.001"),
    _row("12.2", "Establish and Maintain a Secure Network Architecture", "Segment the network to limit "
         "SMB lateral movement between zones.", 2, "T1021.002"),
    _row("12.2", "Establish and Maintain a Secure Network Architecture", "same", 2, "T1064"),
    _row("8.2", "Collect Audit Logs", "Collect audit logs.", 1, "T1053.005", ok="N", fn="Detect"),
]


@pytest.fixture(scope="session")
def mini_attack():
    return load_attack(FIX / "mini-attack.json")


@pytest.fixture(scope="session")
def mini_dict(mini_attack):
    return build_catalog(mini_attack, parse_rows(CIS_ROWS), load_rules(FIX / "sigma"))


@pytest.fixture
def mini_cat(mini_dict):
    return catalog_from_dict(mini_dict)


@pytest.fixture(scope="session")
def real_cat():
    if not paths.have_real_data():
        pytest.skip("real catalog not built (scripts/download_data.py + python -m vantage.ingest.build)")
    from vantage.catalog import load_catalog
    return load_catalog("real")
