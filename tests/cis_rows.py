"""Synthetic CIS workbook rows (importable without pytest, e.g. by scripts/fixture_catalog.py)."""

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
