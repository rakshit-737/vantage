"""Parser for the CTID Mappings Explorer NIST SP 800-53 rev5 -> ATT&CK Enterprise mapping (JSON).

Source: https://github.com/center-for-threat-informed-defense/mappings-explorer
(mappings/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/...) - Apache-2.0.
Each mapping object is one (control, technique) pair with mapping_type "mitigates"; objects with
status "non_mappable" (technique has no mitigation in ATT&CK) carry no control and are skipped.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NistControl:
    id: str                 # e.g. "NIST-AC-2"
    control: str            # e.g. "AC-2"
    family: str             # e.g. "AC"
    family_name: str        # e.g. "Access Control"
    title: str
    techniques: set[str] = field(default_factory=set)  # ATT&CK ids as published (v16.1)


def parse_mapping(doc: dict) -> tuple[dict[str, NistControl], dict]:
    families = doc.get("metadata", {}).get("capability_groups", {}) or {}
    out: dict[str, NistControl] = {}
    skipped = 0
    for m in doc.get("mapping_objects", []):
        cid, tid = m.get("capability_id"), m.get("attack_object_id")
        if not cid or not tid or m.get("mapping_type") != "mitigates":
            skipped += 1
            continue
        cid = cid.strip().upper()
        fam = cid.split("-", 1)[0]
        c = out.get(f"NIST-{cid}")
        if c is None:
            c = out[f"NIST-{cid}"] = NistControl(f"NIST-{cid}", cid, fam, families.get(fam, fam),
                                                 (m.get("capability_description") or cid).strip())
        c.techniques.add(tid.strip().upper())
    meta = {k: doc.get("metadata", {}).get(k) for k in
            ("attack_version", "mapping_framework", "mapping_framework_version", "last_update")}
    meta["skipped_objects"] = skipped
    return out, meta


def load_nist(path: str | Path) -> tuple[dict[str, NistControl], dict]:
    with open(path, encoding="utf-8") as fh:
        return parse_mapping(json.load(fh))
