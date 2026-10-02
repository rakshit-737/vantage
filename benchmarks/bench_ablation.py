"""Benchmark: ablation that isolates the core claim (paper coverage overstates defensibility).

    python benchmarks/bench_ablation.py

For every control framework with a public ATT&CK mapping (CIS v8 IG1-3, NIST SP 800-53B
LOW/MODERATE/HIGH, CRI Profile v2.1, CSA CCM 4.1, AWS, Azure, GCP, M365) and every telemetry tier
(benchmarks/bench_coverage.py TIERS), it adds the evidence requirements one at a time:

  L0 claimed      - a claimed control maps to the technique (what a compliance audit reports)
  L1 + rule tag   - ... and some deployed SigmaHQ rule (stable+test) is tagged with it
                    (log sources ignored: the usual "coverage by ATT&CK tag" view)
  L2 + telemetry  - ... and at least one such rule has *all* its log sources ingested (= defended)

L0 - L2 is the overstatement that VANTAGE measures. Intervals: sensitivity to the particular SigmaHQ
release - the 2.5-97.5 percentile range when a random 10% of the deployed rules is removed (500
draws). (A with-replacement bootstrap is not used: coverage is a set function of *distinct* rules, so
resampling with replacement silently drops about a third of them and biases every level down.)
Each framework claims every mapped control (CIS: up to its IG; NIST: its baseline).
"""
from __future__ import annotations

import random
import time

from bench_coverage import TIERS, tier_sources
from common import FIGS, RESULTS, md_table, need, write_result

from vantage import paths
from vantage.catalog import load_catalog
from vantage.coverage import compute_coverage
from vantage.frameworks import all_frameworks, load_oscal
from vantage.ingest.attack import load_attack
from vantage.models import OrgPosture
from vantage.selectors import expand_org

B = 500


def claim_sets(cat, attack) -> dict[str, set[str]]:
    """framework label -> claimed technique set (v19.2 ids)."""
    out = {}
    for ig in (1, 2, 3):
        out[f"CIS v8 IG{ig}"] = {t for c in cat.controls.values() if c.ig and c.ig <= ig for t in c.mitigates}
    fws = all_frameworks(attack, cat.controls)
    oscal = load_oscal()
    nist = fws["NIST 800-53"]
    for b in ("LOW", "MODERATE", "HIGH"):
        ids = {cid for cid, o in oscal.items() if b in o.baselines}
        out[f"NIST 800-53B {b}"] = {t for k, c in nist.controls.items() if k.split(":", 1)[1] in ids
                                    for t in c.mitigates}
    for name in ("CRI-2.1", "CSA-CCM-4.1", "AWS", "Azure", "GCP", "M365"):
        out[name] = set(fws[name].techniques)
    return out


def levels(cat, claimed: set[str], ingested: set[str], rules: list[str]) -> dict:
    n = len(cat.techniques)
    tagged = {t for d in rules for t in cat.detections[d].techniques}
    org = OrgPosture("x", set(), set(ingested), set(rules))
    cov = compute_coverage(cat, org, controls=set())
    live = cov.detected_set()
    return {"L0": 100 * len(claimed) / n, "L1": 100 * len(claimed & tagged) / n,
            "L2": 100 * len(claimed & live) / n}


def main() -> None:
    t0 = time.perf_counter()
    need(paths.ATTACK_FILE, f"{paths.CTID_DIR}/{paths.OSCAL_CATALOG}")
    cat = load_catalog("real")
    attack = load_attack(paths.data_dir() / paths.ATTACK_FILE, paths.ATTACK_VERSION)
    claims = claim_sets(cat, attack)
    rules = sorted(expand_org(cat, OrgPosture("r", set(), set(), {"@status:stable|test"})).deployed_detections)
    rng = random.Random(0)  # nosec B311 - statistics
    boots = [rng.sample(rules, int(0.9 * len(rules))) for _ in range(B)]  # 10% rule dropout
    rows = []
    for i, (tier, _) in enumerate(TIERS):
        ing = tier_sources(cat, i)
        for fw, cl in claims.items():
            pt = levels(cat, cl, ing, rules)
            bs = [levels(cat, cl, ing, b) for b in boots]

            def ci(key, bs=bs):
                v = sorted(x[key] for x in bs)
                return f"[{v[int(0.025 * B)]:.1f}, {v[int(0.975 * B) - 1]:.1f}]"
            rows.append({"tier": tier.split(" ", 1)[0], "framework": fw,
                         "L0 claimed": round(pt["L0"], 1),
                         "L1 + rule tag": f"{pt['L1']:.1f} {ci('L1')}",
                         "L2 + telemetry (defended)": f"{pt['L2']:.1f} {ci('L2')}",
                         "overstatement L0-L2 (pp)": f"{pt['L0'] - pt['L2']:.1f}",
                         "tag-only overstatement L1-L2 (pp)": f"{pt['L1'] - pt['L2']:.1f}",
                         "_l0": pt["L0"], "_l1": pt["L1"], "_l2": pt["L2"]})
        print(f"{tier}: done ({time.perf_counter() - t0:.0f}s)", flush=True)
    cols = ["tier", "framework", "L0 claimed", "L1 + rule tag", "L2 + telemetry (defended)",
            "overstatement L0-L2 (pp)", "tag-only overstatement L1-L2 (pp)"]
    t0_rows = [r for r in rows if r["tier"] == "T0"]
    t5_rows = [r for r in rows if r["tier"] == "T5"]
    rng_over = lambda rs: (min(r["_l0"] - r["_l2"] for r in rs), max(r["_l0"] - r["_l2"] for r in rs))  # noqa: E731
    lo0, hi0 = rng_over(t0_rows)
    lo5, hi5 = rng_over(t5_rows)
    md = ["### Ablation: what each evidence requirement removes from paper coverage", "",
          f"Percent of the 697 ATT&CK v19.2 techniques; {len(rules)} stable+test SigmaHQ rules deployed. Brackets: "
          "range (2.5-97.5 percentile) when a random 10% of those rules is removed, 500 draws. Telemetry tiers "
          "as in section A of the coverage results.", "",
          f"Across 12 framework profiles the paper-vs-defended overstatement is {lo0:.1f}-{hi0:.1f} pp with "
          f"classic Windows logs only (T0) and still {lo5:.1f}-{hi5:.1f} pp with every Sigma log source (T5).", "",
          md_table(rows, cols), "",
          f"Wall time: {time.perf_counter() - t0:.0f} s."]
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "ablation.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    write_result("ablation", {"rows": [{k: v for k, v in r.items() if not k.startswith("_")} | {
        "L0": round(r["_l0"], 2), "L1": round(r["_l1"], 2), "L2": round(r["_l2"], 2)} for r in rows],
        "rule_dropout_draws": B, "rules": len(rules), "seconds": round(time.perf_counter() - t0, 1),
        "overstatement_pp_T0": [round(lo0, 1), round(hi0, 1)], "overstatement_pp_T5": [round(lo5, 1), round(hi5, 1)]})
    figure(rows, FIGS / "ablation.png")
    print("\n".join(md))


def figure(rows, path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fws = list(dict.fromkeys(r["framework"] for r in rows))
    tiers = list(dict.fromkeys(r["tier"] for r in rows))
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), sharey=True)
    for ax, tier in zip(axes, (tiers[0], tiers[-1]), strict=True):
        rs = [next(r for r in rows if r["tier"] == tier and r["framework"] == f) for f in fws]
        y = range(len(fws))
        ax.barh(list(y), [r["_l0"] for r in rs], color="#e0782a", label="L0 claimed on paper")
        ax.barh(list(y), [r["_l1"] for r in rs], color="#9bb8d9", label="L1 + a Sigma rule is tagged")
        ax.barh(list(y), [r["_l2"] for r in rs], color="#2f9e5b", label="L2 + its log sources ingested")
        ax.set_yticks(list(y), fws, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlim(0, 75)
        ax.set_xlabel("% of ATT&CK v19.2 techniques")
        ax.set_title({"T0": "T0: classic Windows event logs", "T5": "T5: every Sigma log source"}.get(tier, tier),
                     fontsize=9)
    axes[0].legend(fontsize=7, loc="lower right")
    fig.suptitle("Paper coverage vs defended coverage, 12 framework profiles", fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=100)


if __name__ == "__main__":
    main()
