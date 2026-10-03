"""Benchmark: ablation that isolates the core claim (paper coverage overstates defensibility).

    python benchmarks/bench_ablation.py

For every control framework with a public ATT&CK mapping (CIS v8 IG1-3, NIST SP 800-53B
LOW/MODERATE/HIGH, CRI Profile v2.1, CSA CCM 4.1, AWS, Azure, GCP, M365) and every telemetry tier
(benchmarks/bench_coverage.py TIERS), it adds the evidence requirements one at a time:

  L0 claimed      - a claimed control maps to the technique (what a compliance audit reports)
  L1 + rule tag   - ... and some deployed SigmaHQ rule (stable+test) is tagged with it
                    (log sources ignored: the usual "coverage by ATT&CK tag" view)
  L2 + telemetry  - ... and at least one such rule has *all* its log sources ingested (= defended)

L0 - L2 is the overstatement that VANTAGE measures. It splits into a rule-tag share (L0 - L1: claimed
techniques no deployed rule is tagged with) and a telemetry share (L1 - L2: tagged, but no such rule
has its log sources ingested).

Two further arms separate what the control layer adds (CIS only, where each safeguard carries its
CIS Security Function): a detection-only view (DeTT&CT-style: techniques with a live rule, whatever
is claimed) next to defended, and the paper-only techniques split into those claimed by at least one
*Detect* safeguard and those claimed only by Protect/Identify/Respond/Recover safeguards. A
technique in the second group may be blocked by a preventive control without any detection, so it
is not necessarily undefended: it is coverage without detection evidence.

Intervals: sensitivity to the particular SigmaHQ
release - the 2.5-97.5 percentile range when a random 10% of the deployed rules is removed (500
draws). (A with-replacement bootstrap is not used: coverage is a set function of *distinct* rules, so
resampling with replacement silently drops about a third of them and biases every level down.)
Each framework claims every mapped control (CIS: up to its IG; NIST: its baseline).
"""
from __future__ import annotations

import random
import time

from bench_coverage import TIERS, tier_sources
from common import FIGS, md_table, need, write_md, write_result

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


def control_layer(cat, ingested: set[str], rules: list[str]) -> dict:
    """CIS IG1-3: detection-only (DeTT&CT-style) vs defended, and paper-only split by CIS function."""
    n = len(cat.techniques)
    org = OrgPosture("x", set(), set(ingested), set(rules))
    live = compute_coverage(cat, org, controls=set()).detected_set()
    out = {"detectable_pct": round(100 * len(live) / n, 4)}
    for ig in (1, 2, 3):
        ctrls = [c for c in cat.controls.values() if c.ig and c.ig <= ig]
        claimed = {t for c in ctrls for t in c.mitigates}
        by_detect = {t for c in ctrls if c.function == "Detect" for t in c.mitigates}
        paper = claimed - live
        out[f"IG{ig}"] = {"claimed": len(claimed), "defended": len(claimed & live),
                          "defended_pct": round(100 * len(claimed & live) / n, 4),
                          "detectable_unclaimed": len(live - claimed), "paper_only": len(paper),
                          "paper_only_with_detect_safeguard": len(paper & by_detect),
                          "paper_only_non_detect_only": len(paper - by_detect),
                          "claimed_by_detect_safeguard": len(by_detect)}
    return out


def main() -> None:
    t0 = time.perf_counter()
    need(paths.ATTACK_FILE, f"{paths.CTID_DIR}/{paths.OSCAL_CATALOG}")
    cat = load_catalog("real")
    attack = load_attack(paths.data_dir() / paths.ATTACK_FILE, paths.ATTACK_VERSION)
    claims = claim_sets(cat, attack)
    rules = sorted(expand_org(cat, OrgPosture("r", set(), set(), {"@status:stable|test"})).deployed_detections)
    rng = random.Random(0)  # nosec B311 - statistics
    boots = [rng.sample(rules, int(0.9 * len(rules))) for _ in range(B)]  # 10% rule dropout
    rows, layer = [], {}
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
                         "rule-tag share L0-L1 (pp)": f"{pt['L0'] - pt['L1']:.1f}",
                         "telemetry share L1-L2 (pp)": f"{pt['L1'] - pt['L2']:.1f}",
                         "_l0": pt["L0"], "_l1": pt["L1"], "_l2": pt["L2"]})
        layer[tier.split(" ", 1)[0]] = control_layer(cat, ing, rules)
        print(f"{tier}: done ({time.perf_counter() - t0:.0f}s)", flush=True)
    cols = ["tier", "framework", "L0 claimed", "L1 + rule tag", "L2 + telemetry (defended)",
            "overstatement L0-L2 (pp)", "rule-tag share L0-L1 (pp)", "telemetry share L1-L2 (pp)"]
    tiers = list(dict.fromkeys(r["tier"] for r in rows))
    t0_rows = [r for r in rows if r["tier"] == "T0"]
    t5_rows = [r for r in rows if r["tier"] == "T5"]
    rng_over = lambda rs: (min(r["_l0"] - r["_l2"] for r in rs), max(r["_l0"] - r["_l2"] for r in rs))  # noqa: E731
    lo0, hi0 = rng_over(t0_rows)
    lo5, hi5 = rng_over(t5_rows)
    # which share dominates, per tier (unrounded)
    dominance = {t: {"profiles": len(rs), "telemetry_larger": sum((r["_l1"] - r["_l2"]) > (r["_l0"] - r["_l1"])
                                                                  for r in rs)}
                 for t in tiers for rs in [[r for r in rows if r["tier"] == t]]}
    dom_txt = ", ".join(f"{d['telemetry_larger']}/{d['profiles']} at {t}" for t, d in dominance.items())
    lay = [{"tier": t, "detectable, no control layer (DeTT&CT-style) %": f"{v['detectable_pct']:.1f}",
            "defended (CIS IG2 claimed AND detectable) %": f"{v['IG2']['defended_pct']:.1f}",
            "detectable but not claimed": v["IG2"]["detectable_unclaimed"],
            "paper-only": v["IG2"]["paper_only"],
            "paper-only, claimed by a Detect safeguard": v["IG2"]["paper_only_with_detect_safeguard"],
            "paper-only, claimed only by non-Detect safeguards": v["IG2"]["paper_only_non_detect_only"]}
           for t, v in layer.items()]
    md = ["### Ablation: what each evidence requirement removes from paper coverage", "",
          f"Percent of the 697 ATT&CK v19.2 techniques; {len(rules)} stable+test SigmaHQ rules deployed. Brackets: "
          "one-sided sensitivity range (2.5-97.5 percentile) when a random 10% of those rules is removed, 500 draws; "
          "removing rules can only lower coverage, so the range sits at or below the point estimate. "
          "It is not a confidence interval. Telemetry tiers "
          "as in section A of the coverage results.", "",
          f"Across 12 framework profiles the paper-vs-defended overstatement is {lo0:.1f}-{hi0:.1f} pp with "
          f"classic Windows logs only (T0) and still {lo5:.1f}-{hi5:.1f} pp with every Sigma log source (T5).", "",
          "Where the gap comes from: the telemetry share (L1-L2) is larger than the rule-tag share (L0-L1) in "
          f"{dom_txt} profiles. With classic Windows logs most of the gap is missing telemetry; once "
          "Sysmon-class endpoint logs are ingested (T2+), most of what remains is claimed techniques that no "
          "deployed SigmaHQ rule is tagged with.", "",
          "<!-- --8<-- [start:summary] -->",
          "T0 and T5 rows (the full table is below):", "",
          md_table([r for r in rows if r["tier"] in ("T0", "T5")], cols),
          "<!-- --8<-- [end:summary] -->", "",
          "<!-- --8<-- [start:control-layer] -->",
          "#### What the control layer adds over a detection-only view (CIS v8 IG2)", "",
          "Detectable = a live rule exists, whatever is claimed (what a DeTT&CT-style data-source and detection "
          "view reports). Paper-only techniques are split by the CIS Security Function of the safeguards that "
          "claim them; those claimed only by Protect/Identify/Respond/Recover safeguards may be prevented "
          "rather than detected, so they are coverage without detection evidence, not proof of exposure.", "",
          md_table(lay, list(lay[0])),
          "<!-- --8<-- [end:control-layer] -->", "",
          "<!-- --8<-- [start:full] -->",
          md_table(rows, cols),
          "<!-- --8<-- [end:full] -->", "",
          f"Wall time: {time.perf_counter() - t0:.0f} s."]
    write_md("ablation", md)
    write_result("ablation", {"rows": [{k: v for k, v in r.items() if not k.startswith("_")} | {
        "L0": round(r["_l0"], 2), "L1": round(r["_l1"], 2), "L2": round(r["_l2"], 2)} for r in rows],
        "rule_dropout_draws": B, "rules": len(rules), "seconds": round(time.perf_counter() - t0, 1),
        "overstatement_pp_T0": [round(lo0, 1), round(hi0, 1)], "overstatement_pp_T5": [round(lo5, 1), round(hi5, 1)],
        "telemetry_share_dominates": dominance, "control_layer_cis": layer})
    figure(rows, FIGS / "ablation.png")
    shares_figure(rows, FIGS / "ablation_shares.png")
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
        ax.set_xlim(0, 75)
        ax.set_xlabel("% of ATT&CK v19.2 techniques")
        ax.set_title({"T0": "T0: classic Windows event logs", "T5": "T5: every Sigma log source"}.get(tier, tier),
                     fontsize=9)
    axes[0].invert_yaxis()  # shared y axis: invert once
    fig.legend(*axes[0].get_legend_handles_labels(), loc="lower center", ncol=3, fontsize=8, frameon=False)
    fig.suptitle("Paper coverage vs defended coverage, 12 framework profiles", fontsize=10)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=100)


def shares_figure(rows, path) -> None:
    """Rule-tag share vs telemetry share of the gap per tier: median over the 12 profiles, min-max bars."""
    import statistics

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    tiers = list(dict.fromkeys(r["tier"] for r in rows))
    fig, ax = plt.subplots(figsize=(7.6, 3.6))
    series = [(lambda r: r["_l0"] - r["_l1"], "rule-tag share (L0-L1): no tagged rule", "#9bb8d9"),
              (lambda r: r["_l1"] - r["_l2"], "telemetry share (L1-L2): log source missing", "#e0782a")]
    for k, (key, label, col) in enumerate(series):
        med, lo, hi = [], [], []
        for t in tiers:
            v = [key(r) for r in rows if r["tier"] == t]
            med.append(statistics.median(v))
            lo.append(statistics.median(v) - min(v))
            hi.append(max(v) - statistics.median(v))
        x = [i + (k - 0.5) * 0.38 for i in range(len(tiers))]
        ax.bar(x, med, 0.38, yerr=[lo, hi], capsize=3, color=col, label=label)
    ax.set_xticks(range(len(tiers)), tiers)
    ax.set_xlabel("telemetry tier (cumulative)")
    ax.set_ylabel("pp of ATT&CK v19.2")
    ax.set_title("Where the paper-vs-defended gap comes from (median of 12 profiles, bars = min-max)", fontsize=9)
    ax.legend(fontsize=8, frameon=False)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=100)
    plt.close(fig)


if __name__ == "__main__":
    main()
