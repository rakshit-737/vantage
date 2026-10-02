"""Benchmark: cross-framework comparison and train-on-one / test-on-another auto-mapping.

    python benchmarks/bench_crossframework.py              # TF-IDF + MiniLM (CPU; run in the realdata workflow)
    python benchmarks/bench_crossframework.py --no-embed   # TF-IDF only

Measured wall time is written to results/crossframework.json ("seconds").

Part 1 - frameworks side by side in one ATT&CK release (v19.2): CIS v8, NIST SP 800-53 rev5
(+ SP 800-53B LOW/MODERATE/HIGH/PRIVACY baselines), CRI Profile v2.1, CSA CCM 4.1, and the
AWS / Azure / GCP / M365 security-stack mappings. Size, technique coverage, pairwise overlap.

Part 2 - auto-mapping transfer. For every ordered pair (train framework A, test framework B != A)
a TransferMapper is fitted on A's labels only (hyper-parameters by leave-one-out on A) and scored
on B's official mapping; a pooled source (all frameworks except B) is the pre-specified headline.
The in-framework estimate is nested leave-one-control-out. Zero-shot
(mitigation bridge, no labels) and a labels-only prior baseline are reported per test framework.
Cells: macro MAP@200 over B's mapped controls; 95% bootstrap intervals in the JSON.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import time

from common import FIGS, RESULTS, md_table, need, write_result

from vantage import automap, paths
from vantage.catalog import load_catalog
from vantage.frameworks import TEXT_RICH, all_frameworks, baseline_techniques, load_oscal, source_universe
from vantage.ingest.attack import load_attack
from vantage.transfer import PriorTransferBaseline, TransferMapper

KS = (10, 20, 50)
MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class Restrict:
    """Score a mapper over a restricted technique universe (the test framework's source release)."""

    def __init__(self, mapper, universe: frozenset[str]):
        self.m, self.u = mapper, universe
        self.name = getattr(mapper, "name", type(mapper).__name__)

    def _filter(self, ranked, k):
        return [(t, s) for t, s in ranked if t in self.u][:k]

    def rank_for(self, c, k):
        if hasattr(self.m, "rank_for"):
            return self._filter(self.m.rank_for(c, 10_000), k)
        return self._filter(self.m.rank(automap.control_text(c), 10_000), k)


def evaluate(mapper, cat, controls, universe=None) -> tuple[dict, list[float]]:
    """(summary metrics with CIs, per-control AP@200 aligned with `controls` that have labels)."""
    c = copy.copy(cat)
    c.controls = {x.id: x for x in controls}
    m = Restrict(mapper, universe) if universe is not None else mapper
    per = automap.per_control_scores(m, c, KS)
    out = {"mapper": m.name, "controls": len(per["MAP@200"])}
    for key, vals in per.items():
        out[key] = round(sum(vals) / (len(vals) or 1), 3)
        lo, hi = automap.bootstrap_ci(vals)
        out[f"{key}_ci"] = [round(lo, 3), round(hi, 3)]
    return out, per["MAP@200"]


def _restricted_controls(controls, universe):
    """Gold sets restricted to the universe (a label outside it cannot be ranked by anyone)."""
    out = []
    for c in controls:
        g = c.mitigates & universe
        if g:
            out.append(dataclasses.replace(c, mitigates=frozenset(g)))
    return out


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a | b else 0.0


def part1(fws, cat, oscal) -> tuple[list[dict], list[dict], list[dict], dict]:
    n_tech = len(cat.techniques)
    rows = []
    for f in fws.values():
        m = f.mapped
        rows.append({"framework": f.name, "source ATT&CK": f.source_attack, "controls (mapped)": len(m),
                     "pairs": sum(len(c.mitigates) for c in m),
                     "pairs/control": round(sum(len(c.mitigates) for c in m) / max(len(m), 1), 1),
                     "techniques": len(f.techniques),
                     "% of ATT&CK v19.2": round(100 * len(f.techniques) / n_tech, 1),
                     "carried fwd / dropped": f"{f.stats.get('carried_forward_revoked', 0)} / "
                                              f"{f.stats.get('dropped_deprecated_or_unknown', 0)}"})
    names = list(fws)
    overlap = [{"": a, **{b: round(jaccard(fws[a].techniques, fws[b].techniques), 2) for b in names}}
               for a in names]
    nist = fws["NIST 800-53"]
    base = baseline_techniques(nist, oscal)
    bl = []
    mapped_ids = {k.split(":", 1)[1] for k in nist.controls}
    for b, techs in base.items():
        in_b = {cid for cid, o in oscal.items() if b in o.baselines}
        depth = [sum(1 for k, c in nist.controls.items() if k.split(":", 1)[1] in in_b and t in c.mitigates)
                 for t in techs]
        bl.append({"baseline": b, "controls in baseline (incl. enhancements)": len(in_b),
                   "of which base controls with a CTID mapping": len(in_b & mapped_ids),
                   "techniques mitigated": len(techs), "% of ATT&CK v19.2": round(100 * len(techs) / n_tech, 1),
                   "median controls per technique": sorted(depth)[len(depth) // 2] if depth else 0})
    extra = {"MODERATE minus LOW": sorted(base["MODERATE"] - base["LOW"]),
             "HIGH minus MODERATE": sorted(base["HIGH"] - base["MODERATE"]),
             "all frameworks union": len(set().union(*(f.techniques for f in fws.values()))),
             "in every framework": len(set.intersection(*(f.techniques for f in fws.values())))}
    return rows, overlap, bl, extra


def part2(fws, cat, encoder: str, universes: dict) -> dict:
    """Zero-shot, direct, single-source transfer, pooled transfer, prior, nested in-framework LOO."""
    names = list(fws)
    bridge = automap.MitigationBridgeMapper(cat, encoder, model=MODEL)
    direct = bridge.direct
    tests = {b: _restricted_controls(fws[b].mapped, universes[b]) for b in names}
    out = {"zero_shot": {}, "direct": {}, "prior": {}, "transfer": {}, "pooled": {}, "loo_nested": {},
           "fitted": {}, "per_control": {}}
    pc = out["per_control"]
    for b in names:
        out["zero_shot"][b], pc[f"zero_shot|{b}"] = evaluate(bridge, cat, tests[b], universes[b])
        out["direct"][b], pc[f"direct|{b}"] = evaluate(direct, cat, tests[b], universes[b])
    for a in names:
        t0 = time.perf_counter()
        tm = TransferMapper(cat, tests[a], encoder, model=MODEL, train_name=a, bridge=bridge,
                            universe=universes[a])
        out["fitted"][a] = {"beta": tm.beta, "gamma": tm.gamma, "train_loo_map_tuned": tm.fit_map}
        nested = tm.nested_loo_aps()
        vals = [nested[c.id] for c in tests[a] if c.id in nested]
        lo, hi = automap.bootstrap_ci(vals)
        out["loo_nested"][a] = {"MAP@200": round(sum(vals) / len(vals), 3), "MAP@200_ci": [round(lo, 3), round(hi, 3)],
                                "controls": len(vals)}
        pc[f"loo_nested|{a}"] = vals
        pb = PriorTransferBaseline(tests[a], a)
        for b in names:
            out["transfer"][f"{a} -> {b}"], pc[f"transfer|{a} -> {b}"] = evaluate(tm, cat, tests[b], universes[b])
            out["prior"][f"{a} -> {b}"], _ = evaluate(pb, cat, tests[b], universes[b])
        print(f"[{encoder}] train={a}: beta={tm.beta} gamma={tm.gamma} ({time.perf_counter() - t0:.0f}s)",
              flush=True)
    for b in names:  # pre-specified source: pool every *other* framework's labels
        t0 = time.perf_counter()
        pool = [c for a in names if a != b for c in tests[a]]
        tm = TransferMapper(cat, pool, encoder, model=MODEL, train_name=f"all but {b}", bridge=bridge,
                            universe=universes[b])
        out["pooled"][b], pc[f"pooled|{b}"] = evaluate(tm, cat, tests[b], universes[b])
        out["fitted"][f"pooled -> {b}"] = {"beta": tm.beta, "gamma": tm.gamma}
        print(f"[{encoder}] pooled -> {b} ({time.perf_counter() - t0:.0f}s)", flush=True)
    return out


def matrix(res: dict, names: list[str], key: str, metric: str = "MAP@200") -> list[dict]:
    rows = []
    for a in names:
        rows.append({"train / test": a, **{b: f"{res[key][f'{a} -> {b}'][metric]:.3f}" for b in names}})
    return rows


def _ci(r) -> str:
    lo, hi = r["MAP@200_ci"]
    return f"{r['MAP@200']:.3f} [{lo:.3f}, {hi:.3f}]"


def _delta(res, x: str, y: str) -> str:
    m, lo, hi = automap.paired_bootstrap_ci(res["per_control"][x], res["per_control"][y])
    flag = "" if lo <= 0 <= hi else " *"
    return f"{m:+.3f} [{lo:+.3f}, {hi:+.3f}]{flag}"


def summary(res: dict, names: list[str]) -> list[dict]:
    rows = []
    for b in names:
        z = res["zero_shot"][b]
        single = [res["transfer"][f"{a} -> {b}"]["MAP@200"] for a in names if a != b]
        neg = sum(v < z["MAP@200"] for v in single)
        rows.append({"test framework": b, "n": z["controls"],
                     "direct (no bridge)": f"{res['direct'][b]['MAP@200']:.3f}",
                     "zero-shot bridge": _ci(z),
                     "bridge - direct (paired)": _delta(res, f"zero_shot|{b}", f"direct|{b}"),
                     "pooled transfer (all other fw)": _ci(res["pooled"][b]),
                     "pooled - zero-shot (paired)": _delta(res, f"pooled|{b}", f"zero_shot|{b}"),
                     "single-source transfer mean (min-max)":
                         f"{sum(single) / len(single):.3f} ({min(single):.3f}-{max(single):.3f})",
                     "sources below zero-shot": f"{neg}/{len(single)}",
                     "in-framework nested LOO": _ci(res["loo_nested"][b])})
    return rows


def figure(res: dict, names: list[str], path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    m = [[res["transfer"][f"{a} -> {b}"]["MAP@200"] for b in names] for a in names]
    z = [res["zero_shot"][b]["MAP@200"] for b in names]
    fig, ax = plt.subplots(figsize=(8.2, 6.2))
    im = ax.imshow([z, *m], cmap="viridis", vmin=0, vmax=max(max(r) for r in [z, *m]))
    ax.set_xticks(range(len(names)), names, rotation=35, ha="right", fontsize=8)
    ax.set_yticks(range(len(names) + 1), ["zero-shot (no labels)", *[f"train: {a}" for a in names]], fontsize=8)
    ax.axhline(0.5, color="white", lw=2)
    for i, row in enumerate([z, *m]):
        for j, v in enumerate(row):
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=7,
                    color="white" if v < 0.6 * max(max(r) for r in m) else "black")
    ax.set_xlabel("test framework (official mapping)")
    ax.set_title("Control -> ATT&CK auto-mapping, MAP@200: train on one framework, test on another\n"
                 "(diagonal = leave-one-out, weights tuned on the same folds: optimistic)", fontsize=9)
    fig.colorbar(im, ax=ax, fraction=0.035)
    fig.tight_layout()
    fig.savefig(path, dpi=105)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split(chr(10))[0])
    ap.add_argument("--no-embed", action="store_true", help="TF-IDF encoder only (no sentence-transformers)")
    a = ap.parse_args()
    t_start = time.perf_counter()
    need(paths.ATTACK_FILE, paths.ATTACK_CIS_FILE, paths.NIST_FILE, f"{paths.CTID_DIR}/{paths.OSCAL_CATALOG}",
         *paths.ATTACK_RELEASE_FILES.values())
    attack = load_attack(paths.data_dir() / paths.ATTACK_FILE, paths.ATTACK_VERSION)
    cat = load_catalog("real")
    oscal = load_oscal()
    fws = all_frameworks(attack, cat.controls, cis_stats=cat.meta.get("cis"))
    names = list(fws)
    rel = {paths.ATTACK_CIS_VERSION: paths.ATTACK_CIS_FILE, **paths.ATTACK_RELEASE_FILES}
    uni_by_release = {v: source_universe(f, attack) for v, f in rel.items()}
    universes = {n: uni_by_release[fws[n].source_attack] for n in names}
    rows, overlap, bl, extra = part1(fws, cat, oscal)
    for r in rows:
        r["candidate techniques"] = len(universes[r["framework"]])
    encoders = ["tfidf"]
    if not a.no_embed:
        try:
            import sentence_transformers  # noqa: F401
            encoders.append("embed")
        except ImportError:
            print("sentence-transformers not installed: TF-IDF only")
    res = {e: part2(fws, cat, e, universes) for e in encoders}
    from vantage.frameworks import nist_framework
    title_only = nist_framework(attack, oscal, text="title").mapped
    nu = universes["NIST 800-53"]
    abl = {e: {"statement": res[e]["zero_shot"]["NIST 800-53"]["MAP@200"],
               "title only": evaluate(automap.MitigationBridgeMapper(cat, e, model=MODEL), cat,
                                      _restricted_controls(title_only, nu), nu)[0]["MAP@200"]} for e in encoders}
    main_e = encoders[-1]
    enc_name = {"tfidf": "TF-IDF", "embed": "MiniLM-L6-v2"}
    md = ["### Frameworks in one ATT&CK release (v19.2)", "",
          md_table(rows, list(rows[0])), "",
          "`candidate techniques` = v19.2 techniques that existed (directly or via revoked-by) in the ATT&CK "
          "release the framework was mapped against; auto-mappers are scored over that set only.", "",
          f"Union over all frameworks: {extra['all frameworks union']} techniques; mapped by every framework: "
          f"{extra['in every framework']}.", "",
          "Technique-set overlap (Jaccard):", "", md_table(overlap, list(overlap[0])), "",
          "### NIST SP 800-53B baselines (CTID mapping, base controls only)", "",
          md_table(bl, list(bl[0])), "",
          f"MODERATE adds {len(extra['MODERATE minus LOW'])} techniques over LOW "
          f"({', '.join(extra['MODERATE minus LOW']) or '-'}); HIGH adds {len(extra['HIGH minus MODERATE'])} "
          "over MODERATE.", ""]
    for e in encoders:
        md += [f"### Auto-mapping transfer summary ({enc_name[e]} encoder)", "",
               "MAP@200 with 95% bootstrap intervals over the test framework's controls; differences are paired "
               "bootstraps over the same controls (`*` = interval excludes 0). The pooled source (every *other* "
               "framework's labels) is fixed in advance, so no test labels pick it. Nested LOO re-chooses the "
               "transfer weights without the held-out control. Text-rich frameworks: "
               f"{', '.join(TEXT_RICH)}; the cloud security-stack mappings only give a product name.", "",
               md_table(summary(res[e], names), list(summary(res[e], names)[0])), "",
               f"#### Single-source transfer matrix, MAP@200 ({e}); first row = zero-shot bridge", "",
               "Diagonal = leave-one-out with weights tuned on the same folds (optimistic; see nested LOO above).",
               "",
               md_table([{"train / test": "zero-shot",
                          **{b: f"{res[e]['zero_shot'][b]['MAP@200']:.3f}" for b in names}},
                         *matrix(res[e], names, "transfer")], ["train / test", *names]), "",
               f"Labels-only prior (train framework's technique frequencies), MAP@200 ({e}):", "",
               md_table(matrix(res[e], names, "prior"), ["train / test", *names]), "",
               "Fitted weights (beta = kNN label transfer, gamma = prior): " +
               "; ".join(f"{k}: {v['beta']}/{v['gamma']}" for k, v in res[e]["fitted"].items()), ""]
    md += ["NIST 800-53 zero-shot MAP@200, full OSCAL statement vs CTID title only: " +
           "; ".join(f"{e}: {v['statement']:.3f} vs {v['title only']:.3f}" for e, v in abl.items()), "",
           f"Wall time: {time.perf_counter() - t_start:.0f} s ({', '.join(encoders)})."]
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "crossframework.md").write_text(chr(10).join(md) + chr(10), encoding="utf-8")
    slim = {e: {k: v for k, v in r.items() if k != "per_control"} for e, r in res.items()}
    write_result("crossframework", {"attack_version": paths.ATTACK_VERSION, "frameworks": rows,
                                    "overlap_jaccard": overlap, "nist_baselines": bl, "extra": extra,
                                    "automap": slim, "nist_text_ablation": abl, "embed_model": MODEL,
                                    "encoders": encoders, "seconds": round(time.perf_counter() - t_start, 1)})
    FIGS.mkdir(parents=True, exist_ok=True)
    figure(res[main_e], names, FIGS / "crossframework.png")
    print(chr(10).join(md))


if __name__ == "__main__":
    main()
