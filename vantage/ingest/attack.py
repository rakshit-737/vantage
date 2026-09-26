"""MITRE ATT&CK Enterprise STIX 2.1 bundle parser.

Extracts techniques (with all tactics), mitigations (course-of-action + `mitigates`
relationships), the tactic order of the Enterprise matrix, and the revoked-by chain so
that technique ids from older releases (e.g. the v8.2 ids used by the CIS mapping) can be
carried forward to the current release.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MDLINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_HTML = re.compile(r"</?code>")


def clean_text(s: str) -> str:
    s = _CITATION.sub("", s or "")
    s = _MDLINK.sub(r"\1", s)
    s = _HTML.sub("", s)
    return re.sub(r"\s+", " ", s).strip()


def _ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


@dataclass
class AttackData:
    version: str
    techniques: dict[str, dict] = field(default_factory=dict)        # active only
    mitigations: dict[str, dict] = field(default_factory=dict)       # active only
    tactic_order: list[str] = field(default_factory=list)            # shortnames, matrix order
    tactic_names: dict[str, str] = field(default_factory=dict)
    revoked_to: dict[str, str] = field(default_factory=dict)         # old id -> new id
    deprecated: set[str] = field(default_factory=set)

    def resolve(self, tid: str) -> str | None:
        """Follow revoked-by links; None if deprecated or unknown."""
        seen = set()
        tid = tid.strip().upper()
        while tid in self.revoked_to and tid not in seen:
            seen.add(tid)
            tid = self.revoked_to[tid]
        return tid if tid in self.techniques else None


def parse_bundle(bundle: dict, version: str = "") -> AttackData:
    objs = bundle["objects"]
    by_stix = {o["id"]: o for o in objs}
    data = AttackData(version=version)

    for o in objs:
        if o["type"] == "x-mitre-collection" and not version:
            data.version = o.get("x_mitre_version", "")
    tactics_by_ref = {o["id"]: o for o in objs if o["type"] == "x-mitre-tactic"}
    for m in (o for o in objs if o["type"] == "x-mitre-matrix"):
        for ref in m.get("tactic_refs", []):
            t = tactics_by_ref.get(ref)
            if t and t["x_mitre_shortname"] not in data.tactic_order:
                data.tactic_order.append(t["x_mitre_shortname"])
                data.tactic_names[t["x_mitre_shortname"]] = t["name"]
    order = {s: i for i, s in enumerate(data.tactic_order)}

    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        tid = _ext_id(o)
        if not tid or not tid.startswith("T"):
            continue
        if o.get("x_mitre_deprecated"):
            data.deprecated.add(tid)
            continue
        if o.get("revoked"):
            continue
        phases = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                  if p.get("kill_chain_name") == "mitre-attack"]
        phases.sort(key=lambda p: order.get(p, 99))
        data.techniques[tid] = {
            "id": tid, "name": o["name"], "tactics": phases,
            "description": clean_text(o.get("description", "")),
            "platforms": o.get("x_mitre_platforms", []),
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
        }
    # Parent names for sub-techniques ("PowerShell" -> "Command and Scripting Interpreter: PowerShell")
    for tid, t in data.techniques.items():
        if "." in tid and tid.split(".")[0] in data.techniques:
            t["full_name"] = f"{data.techniques[tid.split('.')[0]]['name']}: {t['name']}"
        else:
            t["full_name"] = t["name"]

    for o in objs:
        if o["type"] == "course-of-action" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            mid = _ext_id(o)
            if mid and mid.startswith("M"):
                data.mitigations[mid] = {"id": mid, "name": o["name"],
                                         "description": clean_text(o.get("description", "")),
                                         "techniques": set()}
    for r in (o for o in objs if o["type"] == "relationship"):
        src, dst = by_stix.get(r["source_ref"]), by_stix.get(r["target_ref"])
        if not src or not dst:
            continue
        if r["relationship_type"] == "revoked-by" and src["type"] == dst["type"] == "attack-pattern":
            a, b = _ext_id(src), _ext_id(dst)
            if a and b:
                data.revoked_to[a] = b
        elif (r["relationship_type"] == "mitigates" and src["type"] == "course-of-action"
              and dst["type"] == "attack-pattern" and not r.get("revoked")
              and not r.get("x_mitre_deprecated")):
            mid, tid = _ext_id(src), _ext_id(dst)
            if mid in data.mitigations and tid in data.techniques:
                data.mitigations[mid]["techniques"].add(tid)
    return data


def load_attack(path: str | Path, version: str = "") -> AttackData:
    with open(path, encoding="utf-8") as fh:
        return parse_bundle(json.load(fh), version)
