"""NIST SP 800-53 rev5 OSCAL catalog + SP 800-53B baseline profiles.

Source: https://github.com/usnistgov/oscal-content (nist.gov/SP800-53/rev5/json) - public domain
(US Government work). Gives the full control *statement* prose (which the CTID mapping file does
not carry) and the LOW / MODERATE / HIGH / PRIVACY baseline memberships.

Control ids are normalised to the CTID zero-padded form: ``ac-2`` -> ``AC-02``,
``ac-2.1`` -> ``AC-02(01)``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_PARAM = re.compile(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}")


def norm_id(oscal_id: str) -> str:
    """OSCAL control id (``ac-2.1``) in CTID form (``AC-02(01)``)."""
    base, _, enh = oscal_id.strip().lower().partition(".")
    fam, _, num = base.partition("-")
    out = f"{fam.upper()}-{int(num):02d}"
    return f"{out}({int(enh):02d})" if enh else out


@dataclass
class OscalControl:
    """One OSCAL rev5 control: title, statement text and SP 800-53B baselines."""
    id: str                  # AC-02 / AC-02(01)
    title: str
    family: str              # AC
    family_name: str
    statement: str
    guidance: str = ""
    withdrawn: bool = False
    baselines: set[str] = field(default_factory=set)


def _prose(part: dict, params: dict[str, str]) -> str:
    txt = [part.get("prose", "")]
    txt += [_prose(p, params) for p in part.get("parts", []) if p.get("name") == "item"]
    s = " ".join(t for t in txt if t)
    return _PARAM.sub(lambda m: f"[{params.get(m.group(1), 'organization-defined value')}]", s)


def _walk(ctrl: dict, fam: str, fam_name: str, out: dict[str, OscalControl]) -> None:
    params = {p["id"]: (p.get("label") or next((g.get("prose", "") for g in p.get("guidelines", [])), ""))
              for p in ctrl.get("params", [])}
    parts = {p["name"]: p for p in ctrl.get("parts", [])}
    withdrawn = any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in ctrl.get("props", []))
    cid = norm_id(ctrl["id"])
    out[cid] = OscalControl(cid, ctrl.get("title", ""), fam, fam_name,
                            _prose(parts["statement"], params) if "statement" in parts else "",
                            _prose(parts["guidance"], params) if "guidance" in parts else "", withdrawn)
    for sub in ctrl.get("controls", []):
        _walk(sub, fam, fam_name, out)


def parse_catalog(doc: dict) -> dict[str, OscalControl]:
    """Controls and enhancements from the OSCAL rev5 catalog, parameters substituted."""
    out: dict[str, OscalControl] = {}
    for g in doc["catalog"]["groups"]:
        for c in g.get("controls", []):
            _walk(c, g["id"].upper(), g.get("title", ""), out)
    return out


def parse_profile(doc: dict) -> set[str]:
    """Control ids included by an OSCAL baseline profile."""
    ids: set[str] = set()
    for imp in doc["profile"].get("imports", []):
        for inc in imp.get("include-controls", []):
            ids.update(norm_id(i) for i in inc.get("with-ids", []))
    return ids


def load_catalog_with_baselines(catalog: str | Path, profiles: dict[str, str | Path]) -> dict[str, OscalControl]:
    """OSCAL catalog with each control's SP 800-53B baseline membership."""
    with open(catalog, encoding="utf-8") as fh:
        ctrls = parse_catalog(json.load(fh))
    for name, p in profiles.items():
        with open(p, encoding="utf-8") as fh:
            for cid in parse_profile(json.load(fh)):
                if cid in ctrls:
                    ctrls[cid].baselines.add(name)
    return ctrls
