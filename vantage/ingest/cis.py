"""Parser for the official CIS Controls v8 -> MITRE Enterprise ATT&CK v8.2 master mapping (xlsx).

Source: https://www.cisecurity.org/insights/white-papers/cis-controls-v8-master-mapping-to-mitre-enterprise-attck-v82
The workbook is licensed by CIS (CC BY-NC-ND 4.0); it is downloaded by the user and never
committed. We read the "V8-ATT&CK Low (Sub-)Techniques" sheet: one row per
(safeguard, technique) with a "Safeguard Mitigates (Sub-)Technique?" flag.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

SHEET = "V8-ATT&CK Low (Sub-)Techniques"


@dataclass
class Safeguard:
    """One CIS v8 safeguard with its mapped ATT&CK (sub-)techniques."""
    id: str                 # e.g. "CIS-4.1"
    control: int
    title: str
    description: str
    asset_type: str
    function: str
    ig: int                 # lowest Implementation Group that includes it (1..3)
    techniques: set[str] = field(default_factory=set)  # ATT&CK v8.2 ids


def _norm(v: object) -> str:
    return "" if v is None else str(v).strip()


def parse_rows(rows: Iterable[Sequence[object]]) -> dict[str, Safeguard]:
    """Safeguards from the rows of the CIS master-mapping sheet (first row = header)."""
    rows = iter(rows)
    header = [_norm(c) for c in next(rows)]
    col = {h: i for i, h in enumerate(header) if h}

    def g(r: Sequence[object], name: str) -> str:
        i = col.get(name)
        return _norm(r[i]) if i is not None and i < len(r) else ""

    out: dict[str, Safeguard] = {}
    for r in rows:
        sg = g(r, "CIS Safeguard")
        if "." not in sg:
            continue  # control header row
        # Excel can render "4.10" as 4.1 -> keep the raw string when it is already text
        sid = f"CIS-{sg}"
        if sid not in out:
            igs = [n for n in (1, 2, 3) if g(r, f"IG{n}").lower() == "x"]
            out[sid] = Safeguard(sid, int(sg.split(".")[0]), g(r, "Title"), g(r, "Description"),
                                 g(r, "Asset Type"), g(r, "Security Function"), min(igs) if igs else 3)
        tid = g(r, "Combined ATT&CK (Sub-)Technique ID")
        if tid and g(r, "Safeguard Mitigates (Sub-)Technique?").upper().startswith("Y"):
            out[sid].techniques.add(tid.upper())
    return out


def load_cis(path: str | Path) -> dict[str, Safeguard]:
    """Read the CIS v8 -> ATT&CK workbook (``data`` extra: openpyxl)."""
    import openpyxl  # optional dependency ([data] extra)

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        return parse_rows(wb[SHEET].iter_rows(values_only=True))
    finally:
        wb.close()
