"""Generic parser for CTID Mappings Explorer files (any framework -> ATT&CK Enterprise).

Source: https://github.com/center-for-threat-informed-defense/mappings-explorer (Apache-2.0).
Handles both "mitigates" mappings (NIST 800-53, CRI Profile, CSA CCM) and the "technique_scores"
security-stack mappings (AWS, Azure, GCP, M365), where every capability->technique pair carries a
protect/detect/respond category and a minimal/partial/significant score.

Only the capability id, description (its name) and group are kept as control text. The per-pair
``comments`` field is deliberately dropped: it is written *about the technique* and would leak the
label into any auto-mapper that reads it.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

POSITIVE = {"mitigates", "technique_scores", "technique_score"}


@dataclass
class CtidCapability:
    id: str
    name: str
    group: str
    group_name: str
    techniques: set[str] = field(default_factory=set)
    scores: dict[str, str] = field(default_factory=dict)      # technique -> minimal/partial/significant
    categories: set[str] = field(default_factory=set)         # protect / detect / respond


def parse_ctid(doc: dict) -> tuple[dict[str, CtidCapability], dict]:
    md = doc.get("metadata", {}) or {}
    groups = md.get("capability_groups", {}) or {}
    out: dict[str, CtidCapability] = {}
    skipped = Counter()
    for m in doc.get("mapping_objects", []):
        cid, tid = (m.get("capability_id") or "").strip(), (m.get("attack_object_id") or "").strip().upper()
        if not cid or not tid:
            skipped["no_capability_or_technique"] += 1
            continue
        if m.get("mapping_type") not in POSITIVE or m.get("status") == "non_mappable":
            skipped[f"type_{m.get('mapping_type')}"] += 1
            continue
        grp = (m.get("capability_group") or "").strip()
        c = out.get(cid)
        if c is None:
            c = out[cid] = CtidCapability(cid, (m.get("capability_description") or cid).strip().rstrip("_"),
                                          grp, str(groups.get(grp, grp)))
        c.techniques.add(tid)
        if m.get("score_value"):
            c.scores[tid] = m["score_value"]
        if m.get("score_category"):
            c.categories.add(m["score_category"])
    meta = {k: md.get(k) for k in ("attack_version", "mapping_framework", "mapping_framework_version",
                                   "last_update")}
    meta["skipped_objects"] = dict(skipped)
    return out, meta


def load_ctid(path: str | Path) -> tuple[dict[str, CtidCapability], dict]:
    with open(path, encoding="utf-8") as fh:
        return parse_ctid(json.load(fh))
