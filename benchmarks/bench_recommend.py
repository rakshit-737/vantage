"""Benchmark: budgeted log-source onboarding on the real catalog.

    python benchmarks/bench_recommend.py

Start state: the synthetic Acme posture (vantage/postures/acme-real.yaml). Action set: onboard one
Sigma log source (and deploy every rule it unlocks). Objective: number of ATT&CK techniques that
gain a live detection, under a cost budget.

Compared strategies
  * greedy     - vantage.recommend (new techniques / cost), the shipped recommender
  * optimal    - exact integer program (scipy.optimize.milp / HiGHS): budgeted maximum coverage
  * most-rules - onboard the log sources with the most Sigma rules first (a common heuristic)
  * cheapest   - cheapest log sources first
  * random     - 50 random orders (seed 0): mean and 2.5-97.5 percentile range
"""
from __future__ import annotations

import random
import statistics
import time

import numpy as np
from common import FIGS, md_table, write_md, write_result
from scipy.optimize import Bounds, LinearConstraint, milp

from vantage.catalog import load_catalog
from vantage.cli import REAL_DEMO_ORG
from vantage.coverage import live_detections
from vantage.io import load_org
from vantage.recommend import recommend
from vantage.selectors import expand_org

BUDGETS = [1, 2, 3, 5, 8, 12, 20]


def setup():
    cat = load_catalog("real")
    org = expand_org(cat, load_org(REAL_DEMO_ORG))
    covered = set()
    for d in live_detections(cat, org.deployed_detections, org.ingested_log_sources):
        covered |= cat.detections[d].techniques
    cands = {}
    for ls in cat.log_sources:
        if ls in org.ingested_log_sources:
            continue
        unlock = {d for d, det in cat.detections.items() if det.requires <= {ls} | org.ingested_log_sources
                  and ls in det.requires}
        gain = set().union(*(cat.detections[d].techniques for d in unlock)) - covered if unlock else set()
        cost = cat.log_sources[ls].cost + sum(cat.detections[d].cost for d in unlock
                                               if d not in org.deployed_detections)
        cands[ls] = {"gain": gain, "cost": round(cost, 4), "rules": len(unlock)}
    return cat, org, covered, cands


def run_order(order, cands, budget):
    got, spent = set(), 0.0
    for ls in order:
        c = cands[ls]
        if spent + c["cost"] <= budget + 1e-9:
            spent += c["cost"]
            got |= c["gain"]
    return len(got)


def optimal(cands, budget):
    ls_ids = [k for k, v in cands.items() if v["gain"]]
    techs = sorted(set().union(*(cands[k]["gain"] for k in ls_ids)))
    ti = {t: i for i, t in enumerate(techs)}
    n, m = len(ls_ids), len(techs)
    c = np.concatenate([np.zeros(n), -np.ones(m)])      # maximise covered techniques
    rows = []
    # y_t - sum_{ls covers t} x_ls <= 0
    A = np.zeros((m + 1, n + m))
    for j, ls in enumerate(ls_ids):
        for t in cands[ls]["gain"]:
            A[ti[t], j] = -1
    for i in range(m):
        A[i, n + i] = 1
    A[m, :n] = [cands[k]["cost"] for k in ls_ids]
    ub = np.concatenate([np.zeros(m), [budget]])
    rows.append(LinearConstraint(A, -np.inf, ub))
    res = milp(c, constraints=rows, integrality=np.ones(n + m), bounds=Bounds(0, 1),
               options={"time_limit": 120})
    return int(round(-res.fun)) if res.success else None


def main() -> None:
    cat, org, covered, cands = setup()
    rng = random.Random(0)
    rows = []
    for b in BUDGETS:
        t0 = time.perf_counter()
        plan = recommend(cat, org, budget=b, max_steps=200, actions=("onboard_log_source",))
        g_s = time.perf_counter() - t0
        greedy = sum(len(r.new_techniques) for r in plan)
        t0 = time.perf_counter()
        opt = optimal(cands, b)
        o_s = time.perf_counter() - t0
        most = run_order(sorted(cands, key=lambda k: (-cands[k]["rules"], k)), cands, b)
        cheap = run_order(sorted(cands, key=lambda k: (cands[k]["cost"], k)), cands, b)
        rnd = [run_order(rng.sample(sorted(cands), len(cands)), cands, b) for _ in range(50)]
        r_lo, r_hi = (float(x) for x in np.percentile(rnd, [2.5, 97.5]))
        rows.append({"budget": b, "greedy": greedy, "optimal": opt,
                     "greedy/optimal": round(greedy / opt, 3) if opt else "",
                     "most-rules": most, "cheapest": cheap,
                     "random(mean)": round(statistics.mean(rnd), 1),
                     "random 2.5-97.5%": f"{r_lo:.1f}-{r_hi:.1f}",
                     "greedy/random(mean)": round(greedy / statistics.mean(rnd), 1) if statistics.mean(rnd) else "",
                     "greedy_ms": round(g_s * 1000), "ilp_ms": round(o_s * 1000),
                     "_r_lo": r_lo, "_r_hi": r_hi})
        print(rows[-1])
    first = recommend(cat, org, max_steps=5, actions=("onboard_log_source",))
    plan_rows = [{"step": i + 1, "onboard": r.target, "cost": r.cost, "new_techniques": len(r.new_techniques),
                  "rules_unlocked": len(r.enables)} for i, r in enumerate(first)]
    cols = [k for k in rows[0] if not k.startswith("_")]
    ratio_mean = [r["greedy"] / r["random(mean)"] for r in rows if r["random(mean)"]]
    ratio_hi = [r["greedy"] / r["_r_hi"] for r in rows if r["_r_hi"]]
    gain_most = [r["greedy"] - r["most-rules"] for r in rows]
    md = ["### Techniques newly detectable vs onboarding budget (start: Acme real posture, "
          f"{len(covered)} techniques already detectable, {len(cands)} candidate log sources)", "",
          md_table(rows, cols), "",
          f"Greedy finds {min(ratio_mean):.1f}-{max(ratio_mean):.1f}x the mean of 50 random orders and "
          f"{min(ratio_hi):.1f}-{max(ratio_hi):.1f}x their 97.5th percentile; it beats most-rules-first by "
          f"{min(gain_most)}-{max(gain_most)} techniques. Greedy equals the exact ILP at "
          f"{sum(r['greedy'] == r['optimal'] for r in rows)} of {len(rows)} budgets (an empirical result on this "
          "instance, not a guarantee).", "",
          "### Greedy plan (first 5 steps)", "",
          md_table(plan_rows, list(plan_rows[0]))]
    write_md("recommend", md)
    write_result("recommend", {"start_detectable": len(covered), "candidates": len(cands),
                               "budgets": [{k: v for k, v in r.items() if not k.startswith("_")}
                                           | {"random_p2.5": round(r["_r_lo"], 2), "random_p97.5": round(r["_r_hi"], 2)}
                                           for r in rows],
                               "greedy_over_random_mean": [round(min(ratio_mean), 2), round(max(ratio_mean), 2)],
                               "greedy_over_random_p97.5": [round(min(ratio_hi), 2), round(max(ratio_hi), 2)],
                               "greedy_minus_most_rules": [min(gain_most), max(gain_most)],
                               "greedy_plan": plan_rows})
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 3.4))
    ax.fill_between(BUDGETS, [r["_r_lo"] for r in rows], [r["_r_hi"] for r in rows], color="#999", alpha=0.25,
                    label="random orders, 2.5-97.5%")
    for key, col in [("optimal", "#222"), ("greedy", "#2f9e5b"), ("most-rules", "#e0782a"),
                     ("cheapest", "#8a63d2"), ("random(mean)", "#999")]:
        ax.plot(BUDGETS, [r[key] for r in rows], marker="o", label=key, color=col,
                linestyle="--" if key == "optimal" else "-")
    ax.set_xlabel("onboarding budget (relative cost units)")
    ax.set_ylabel("new techniques detectable")
    ax.set_title("Budgeted log-source onboarding on SigmaHQ + ATT&CK v19.2", fontsize=10)
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    FIGS.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGS / "recommend.png", dpi=110)
    print("\n".join(md))


if __name__ == "__main__":
    main()
