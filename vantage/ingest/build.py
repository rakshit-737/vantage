"""Build the real-data catalog (ATT&CK v19.2 + official CIS v8 mapping + SigmaHQ) as JSON.

    python -m vantage.ingest.build            # reads $VANTAGE_DATA_DIR, writes processed/catalog.json

Provenance and every drop decision (deprecated techniques, rules without ATT&CK tags,
revoked ids carried forward) is recorded in catalog["meta"] so results are auditable.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from .. import paths
from .attack import AttackData, load_attack
from .cis import Safeguard, load_cis
from .sigma import SigmaRule, load_rules, logsource_cost


def forward_cis(safeguards: dict[str, Safeguard], attack: AttackData) -> tuple[dict, dict]:
    """Carry v8.2 technique ids to the current release. Returns (safeguard -> ids, stats)."""
    stats = Counter()
    out = {}
    for sid, sg in safeguards.items():
        ids = set()
        for t in sg.techniques:
            new = attack.resolve(t)
            if new is None:
                stats["dropped_deprecated_or_unknown"] += 1
            else:
                stats["carried_forward_revoked" if new != t else "unchanged"] += 1
                ids.add(new)
        out[sid] = sorted(ids)
    return out, dict(stats)


def build_catalog(attack: AttackData, safeguards: dict[str, Safeguard], rules: list[SigmaRule],
                  sources: dict | None = None) -> dict:
    cis_map, cis_stats = forward_cis(safeguards, attack)
    rstats = Counter()
    detections, ls_counts = {}, Counter()
    for r in rules:
        techs = sorted({t2 for t in r.techniques if (t2 := attack.resolve(t))})
        if not techs:
            rstats["skipped_no_attack_tag" if not r.techniques else "skipped_only_deprecated_tags"] += 1
            continue
        if r.id in detections:
            rstats["skipped_duplicate_id"] += 1
            continue
        rstats["kept"] += 1
        ls_counts[r.logsource] += 1
        detections[r.id] = {"id": r.id, "title": r.title, "techniques": techs,
                            "requires": [r.logsource], "cost": 1.0, "level": r.level,
                            "status": r.status, "path": r.path}
    techniques = {}
    for tid, t in attack.techniques.items():
        tactics = t["tactics"] or ["unknown"]
        techniques[tid] = {"id": tid, "name": t["full_name"], "tactic": tactics[0], "tactics": tactics,
                           "description": t["description"], "platforms": t["platforms"]}
    return {
        "meta": {
            "attack_version": attack.version,
            "tactic_order": attack.tactic_order,
            "tactic_names": attack.tactic_names,
            "sources": sources or {},
            "cis": {"safeguards": len(safeguards),
                    "mapped_safeguards": sum(1 for v in cis_map.values() if v),
                    "pairs_v82": sum(len(s.techniques) for s in safeguards.values()),
                    "pairs_current": sum(len(v) for v in cis_map.values()), **cis_stats},
            "sigma": {"rules_read": len(rules), **dict(rstats),
                      "log_sources": len(ls_counts)},
        },
        "techniques": techniques,
        "controls": {sid: {"id": sid, "framework": "CIS v8", "title": sg.title, "text": sg.description,
                           "mitigates": cis_map[sid], "ig": sg.ig, "function": sg.function}
                     for sid, sg in safeguards.items()},
        "log_sources": {ls: {"id": ls, "name": ls, "cost": logsource_cost(ls), "rules": n}
                        for ls, n in sorted(ls_counts.items())},
        "detections": detections,
        "mitigations": {mid: {"id": mid, "name": m["name"], "description": m["description"],
                              "techniques": sorted(m["techniques"])}
                        for mid, m in attack.mitigations.items()},
    }


def main(argv: list[str] | None = None) -> int:
    d = paths.data_dir()
    need = [paths.ATTACK_FILE, paths.CIS_FILE, paths.SIGMA_FILE]
    missing = [n for n in need if not (d / n).exists()]
    if missing:
        print(f"missing in {d}: {missing}; run scripts/download_data.py first", file=sys.stderr)
        return 1
    attack = load_attack(d / paths.ATTACK_FILE, paths.ATTACK_VERSION)
    cat = build_catalog(attack, load_cis(d / paths.CIS_FILE), load_rules(d / paths.SIGMA_FILE),
                        sources={"attack": paths.ATTACK_FILE, "cis": paths.CIS_FILE,
                                 "sigma": paths.SIGMA_FILE})
    out = paths.catalog_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cat), encoding="utf-8")
    print(json.dumps(cat["meta"]["cis"] | {"sigma": cat["meta"]["sigma"],
                                           "techniques": len(cat["techniques"])}, indent=2))
    print(f"wrote {out} ({Path(out).stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
