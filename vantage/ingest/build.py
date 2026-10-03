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
from .nist import NistControl, load_nist
from .sigma import SigmaRule, load_rules, logsource_cost

# Deploying/tuning one Sigma rule is assumed to cost 1/20 of onboarding a standard log source
# (see docs/adr/0004-cost-model.md). Keeps "onboard + deploy what it unlocks" comparable.
RULE_COST = 0.05


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
    """Join ATT&CK, the CIS mapping and Sigma rules into the catalog JSON dict."""
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
                            "requires": [r.logsource], "cost": RULE_COST, "level": r.level,
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


def nist_controls(controls: dict[str, NistControl], attack: AttackData,
                  baselines: dict[str, set[str]] | None = None) -> tuple[dict, dict]:
    """NIST 800-53 rev5 controls as catalog controls, ids carried from ATT&CK v16.1 to current.
    ``baselines``: control id (``AC-02``) -> SP 800-53B baselines it belongs to (from OSCAL)."""
    stats = Counter()
    out = {}
    for cid, c in sorted(controls.items()):
        ids = set()
        for t in c.techniques:
            new = attack.resolve(t)
            if new is None:
                stats["dropped_deprecated_or_unknown"] += 1
            else:
                stats["carried_forward_revoked" if new != t else "unchanged"] += 1
                ids.add(new)
        out[cid] = {"id": cid, "framework": "NIST SP 800-53 rev5", "title": f"{c.control} {c.title}",
                    "text": f"{c.family_name}: {c.title}", "mitigates": sorted(ids), "ig": None,
                    "function": c.family, "baselines": sorted((baselines or {}).get(c.control, ()))}
    return out, dict(stats)


def with_nist(cat: dict, controls: dict[str, NistControl], meta: dict, attack: AttackData,
              baselines: dict[str, set[str]] | None = None) -> dict:
    """The same catalog with NIST SP 800-53 controls (and SP 800-53B baselines) as controls."""
    ctrls, stats = nist_controls(controls, attack, baselines)
    out = dict(cat)
    out["meta"] = dict(cat["meta"]) | {"nist": {**meta, "controls": len(ctrls),
                                                "mapped_controls": sum(1 for c in ctrls.values() if c["mitigates"]),
                                                "pairs_current": sum(len(c["mitigates"]) for c in ctrls.values()),
                                                **stats}}
    out["controls"] = ctrls
    return out


def main(argv: list[str] | None = None) -> int:
    """Build catalog.json and catalog-nist.json from the downloaded datasets."""
    d = paths.data_dir()
    need = [paths.ATTACK_FILE, paths.CIS_FILE, paths.SIGMA_FILE]
    missing = [n for n in need if not (d / n).exists()]
    if missing:
        print(f"missing in {d}: {missing}; run python -m vantage.download first", file=sys.stderr)
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
    if (d / paths.NIST_FILE).exists():
        nist, meta = load_nist(d / paths.NIST_FILE)
        oscal_cat = d / paths.CTID_DIR / paths.OSCAL_CATALOG
        base = None
        if oscal_cat.exists():  # SP 800-53B baseline membership (optional download)
            from .oscal import load_catalog_with_baselines
            oc = load_catalog_with_baselines(oscal_cat, {b: d / paths.CTID_DIR / f
                                                         for b, f in paths.OSCAL_BASELINES.items()})
            base = {cid: o.baselines for cid, o in oc.items()}
        ncat = with_nist(cat, nist, meta, attack, base)
        ncat["meta"]["sources"] = dict(ncat["meta"]["sources"]) | {"nist": paths.NIST_FILE}
        paths.nist_catalog_path().write_text(json.dumps(ncat), encoding="utf-8")
        print(json.dumps(ncat["meta"]["nist"], indent=2))
        print(f"wrote {paths.nist_catalog_path()}")
    else:
        print(f"({paths.NIST_FILE} not found: skipping the NIST 800-53 catalog)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
