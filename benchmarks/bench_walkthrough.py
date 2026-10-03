"""The numbers quoted on the docs "How it works" page, computed from the real catalog.

    python benchmarks/bench_walkthrough.py

Posture: the synthetic Acme org (vantage/postures/acme-real.yaml): claims CIS IG2, deploys every
stable and test SigmaHQ rule, ingests Windows event, cloud, proxy and web logs only. For two
techniques it reports the claiming safeguards, live and dead rules and the most common missing log
source; then the matrix totals, the top single point of failure, and what the recommender's first
pick changes (newly detectable vs defended techniques).
"""
from __future__ import annotations

from collections import Counter

from common import md_table, write_md, write_result

from vantage.catalog import load_catalog
from vantage.cli import REAL_DEMO_ORG
from vantage.coverage import compute_coverage
from vantage.failure import rank_spofs
from vantage.io import load_org
from vantage.models import CoverageStatus
from vantage.recommend import recommend
from vantage.selectors import expand_org

TECHNIQUES = ["T1003.001", "T1055"]
D = CoverageStatus.DEFENDED


def technique_row(cat, org, cov, tid: str) -> dict:
    dead = sorted(d for d in cov.dead_detections if tid in cat.detections[d].techniques)
    missing = Counter(ls for d in dead for ls in cat.detections[d].requires - org.ingested_log_sources)
    top, top_n = missing.most_common(1)[0] if missing else ("-", 0)
    return {"technique": f"{tid} {cat.techniques[tid].name}", "claimed by (IG2 safeguards)": len(cov.claimed[tid]),
            "live rules": len(cov.detected_by[tid]), "dead rules (deployed, log source missing)": len(dead),
            "most common missing source": f"`{top}` ({top_n})", "status": cov.status[tid].value}


def main() -> None:
    cat = load_catalog("real")
    org = expand_org(cat, load_org(REAL_DEMO_ORG))
    cov = compute_coverage(cat, org)
    n = len(cat.techniques)
    rows = [technique_row(cat, org, cov, t) for t in TECHNIQUES]
    s = cov.summary()
    spof = rank_spofs(cat, org, top=1)[0]
    first = recommend(cat, org, max_steps=1, actions=("onboard_log_source",))[0]
    defended0 = len(cov.by_status(D))
    ing1 = org.ingested_log_sources | {first.target}
    with_unlocked = compute_coverage(cat, org, ingested=ing1, deployed=org.deployed_detections | set(first.enables))
    own_rules = compute_coverage(cat, org, ingested=ing1)
    rec = {"target": first.target, "cost": first.cost, "rules_unlocked": len(first.enables),
           "newly_detectable": len(first.new_techniques),
           "defended_before": defended0, "defended_before_pct": round(100 * defended0 / n, 1),
           "defended_after_with_unlocked_rules": len(with_unlocked.by_status(D)),
           "defended_after_own_rules_only": len(own_rules.by_status(D))}
    rec["defended_after_pct"] = round(100 * rec["defended_after_with_unlocked_rules"] / n, 1)
    rec["defended_gain"] = rec["defended_after_with_unlocked_rules"] - defended0
    totals = {"claimed_pct": s["claimed_pct"], "defended_pct": s["true_pct"], "paper_only": s["paper_only"],
              "dead_rules": len(cov.dead_detections), "spof": spof.node, "spof_kind": spof.kind,
              "spof_dark": len(spof.techniques_gone_dark), "spof_pct": spof.pct_of_matrix}
    md = ["### How-it-works walkthrough (synthetic Acme posture, real catalog)", "",
          md_table(rows, list(rows[0])), "",
          f"Matrix: claimed {totals['claimed_pct']}% vs defended {totals['defended_pct']}% of {n} techniques, "
          f"{totals['paper_only']} paper-only, {totals['dead_rules']} dead rules. Top single point of failure: "
          f"{totals['spof_kind']} `{totals['spof']}` ({totals['spof_dark']} techniques go dark).", "",
          f"Recommender's first pick: onboard `{rec['target']}` (cost {rec['cost']:g}), which unlocks "
          f"{rec['rules_unlocked']} rules and makes {rec['newly_detectable']} techniques newly detectable. "
          f"Defended coverage goes from {rec['defended_before']} ({rec['defended_before_pct']}%) to "
          f"{rec['defended_after_with_unlocked_rules']} ({rec['defended_after_pct']}%) techniques, "
          f"+{rec['defended_gain']} "
          f"({rec['defended_after_own_rules_only']} if only the posture's already-deployed rules come alive). The "
          "recommender maximises newly *detectable* techniques, not defended ones."]
    write_md("walkthrough", md)
    write_result("walkthrough", {"org": org.name, "techniques": rows, "totals": totals, "first_recommendation": rec})
    print("\n".join(md))


if __name__ == "__main__":
    main()
