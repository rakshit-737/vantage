"""Benchmark: auto-mapping CIS v8 safeguard text -> ATT&CK techniques, scored against the
official CIS v8 -> ATT&CK v8.2 master mapping.

    python benchmarks/bench_automap.py            # add --no-embed to skip sentence-transformers

Ground truth: 105 of 153 safeguards carry >= 1 mapped (sub-)technique (2,962 pairs).
Mappers only see the safeguard title + description and public ATT&CK text; no CIS labels are
used for fitting (the popularity baseline uses the *other* safeguards' labels, leave-one-out,
as an upper-bound-ish "prior only" reference).

Paired differences between mappers (same safeguards) get a paired bootstrap 95% interval and a
two-sided sign-flip permutation p-value. Per-safeguard AP@200 and P@10 for every mapper are written
to results/automap_per_control.csv.gz.
"""
from __future__ import annotations

import argparse
import statistics
import time

from common import FIGS, eval_catalog_v82, fmt_p, md_table, sign_flip_p, write_csv_gz, write_md, write_result

from vantage import automap
from vantage.catalog import load_catalog

KS = (5, 10, 20, 50)
EMBED_MODELS = ["sentence-transformers/all-MiniLM-L6-v2", "BAAI/bge-small-en-v1.5"]


def mappers(cat, embed: bool):
    yield automap.RandomBaseline(cat)
    yield automap.PopularityBaseline(cat)
    yield automap.TfidfMapper(cat)
    yield automap.MitigationBridgeMapper(cat, "tfidf")
    if embed:
        for m in EMBED_MODELS:
            yield automap.EmbeddingMapper(cat, m)
            yield automap.MitigationBridgeMapper(cat, "embed", model=m)


def random_seeds(cat, seeds: int = 10) -> dict:
    """The random baseline over several seeds: mean and sd of each metric."""
    runs = [automap.evaluate_mapper(automap.RandomBaseline(cat, s), cat, KS) for s in range(seeds)]
    keys = [k for k in runs[0] if k not in ("mapper", "controls")]
    return {"mapper": f"baseline-random ({seeds} seeds)", "controls": runs[0]["controls"],
            **{k: round(statistics.mean(r[k] for r in runs), 3) for k in keys},
            **{f"{k}_sd": round(statistics.stdev(r[k] for r in runs), 3) for k in keys}}


def run(cat, embed: bool) -> tuple[list[dict], dict[str, dict[str, list[float]]]]:
    """Summary rows (mean + bootstrap CI per metric) and the per-control scores of every mapper."""
    rows, per = [], {}
    for m in mappers(cat, embed):
        t0 = time.perf_counter()
        sc = automap.per_control_scores(m, cat, KS)
        n = len(sc["MAP@200"])
        r = {"mapper": getattr(m, "name", type(m).__name__), "controls": n}
        for key, vals in sc.items():
            r[key] = round(sum(vals) / (n or 1), 3)
            lo, hi = automap.bootstrap_ci(vals)
            r[f"{key}_ci"] = [round(lo, 3), round(hi, 3)]
        r["seconds"] = round(time.perf_counter() - t0, 2)
        print(r)
        rows.append(r)
        per[r["mapper"]] = sc
    return rows, per


# (a, b) mapper-name prefixes for the paired comparisons reported on ATT&CK v8.2
PAIRS = [("mitigation-bridge[all-MiniLM-L6-v2]", "mitigation-bridge[bge-small-en-v1.5]"),
         ("mitigation-bridge[all-MiniLM-L6-v2]", "baseline-popularity"),
         ("mitigation-bridge[tfidf]", "baseline-popularity"),
         ("mitigation-bridge[all-MiniLM-L6-v2]", "mitigation-bridge[tfidf]"),
         ("mitigation-bridge[all-MiniLM-L6-v2]", "embed-direct[all-MiniLM-L6-v2]"),
         ("mitigation-bridge[tfidf]", "tfidf-direct"),
         ("tfidf-direct", "baseline-popularity")]


def paired(per: dict[str, dict[str, list[float]]], metric: str = "MAP@200") -> list[dict]:
    out = []
    for a, b in PAIRS:
        if a not in per or b not in per:
            continue
        x, y = per[a][metric], per[b][metric]
        m, lo, hi = automap.paired_bootstrap_ci(x, y)
        p = sign_flip_p([u - v for u, v in zip(x, y, strict=True)])
        out.append({"comparison": f"{a} - {b}", "metric": metric, "mean diff": round(m, 4),
                    "95% CI": [round(lo, 4), round(hi, 4)], "p (sign-flip)": round(p, 6)})
    return out


def ceilings(cat) -> dict:
    """Oracle P@10 (a perfect ranker can score at most min(|gold|, 10) / 10 per safeguard)."""
    gold = [len(c.mitigates) for c in cat.controls.values() if c.mitigates]
    return {"oracle_P@10": round(sum(min(g, 10) / 10 for g in gold) / len(gold), 4),
            "safeguards_lt10_gold": sum(g < 10 for g in gold), "mapped_safeguards": len(gold),
            "gold_pairs": sum(gold)}


def fmt(rows: list[dict]) -> list[dict]:
    """Table rows with the 95% bootstrap interval next to each headline metric."""
    out = []
    for r in rows:
        o = dict(r)
        for k in ("P@10", "R@20", "R@50", "MAP@200"):
            if f"{k}_ci" in r:
                lo, hi = r[f"{k}_ci"]
                o[k] = f"{r[k]:.3f} [{lo:.3f}, {hi:.3f}]"
        out.append(o)
    return out


def figure(rows: list[dict], path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    names = [r["mapper"] for r in rows]
    fig, ax = plt.subplots(figsize=(8, 3.6))
    y = range(len(rows))
    ax.barh([i + 0.2 for i in y], [r["R@20"] for r in rows], height=0.4, label="Recall@20", color="#3b82c4")
    ax.barh([i - 0.2 for i in y], [r["MAP@200"] for r in rows], height=0.4, label="MAP@200", color="#e0782a")
    ax.set_yticks(list(y), names, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("score (macro-averaged over 105 mapped CIS v8 safeguards)")
    ax.set_title("Control -> ATT&CK auto-mapping vs official CIS v8 mapping (ATT&CK v8.2)", fontsize=10)
    ax.set_xlim(0, max(r["MAP@200"] for r in rows) * 1.35)
    ax.legend(fontsize=8, loc="lower right")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=110)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-embed", action="store_true")
    a = ap.parse_args()
    embed = not a.no_embed
    if embed:
        try:
            import sentence_transformers  # noqa: F401
        except ImportError:
            print("sentence-transformers not installed: skipping embedding mappers")
            embed = False
    v82 = eval_catalog_v82()
    print(f"== ATT&CK v8.2 universe: {len(v82.techniques)} techniques, {len(v82.mitigations)} mitigations")
    rows82, per82 = run(v82, embed)
    real = load_catalog("real")
    print(f"== ATT&CK v19.2 universe (labels carried forward): {len(real.techniques)} techniques")
    real.controls = {k: c for k, c in real.controls.items() if c.framework.startswith("CIS")}
    rows19, per19 = run(real, embed)
    rnd = random_seeds(v82)
    ceil = ceilings(v82)
    pairs = paired(per82)
    cols = ["mapper", "P@10", "R@20", "R@50", "MAP@200", "seconds"]
    ptab = [{"comparison (ATT&CK v8.2)": r["comparison"], "MAP@200 diff": f"{r['mean diff']:+.3f}",
             "95% CI (paired bootstrap)": f"[{r['95% CI'][0]:+.3f}, {r['95% CI'][1]:+.3f}]",
             "p (sign-flip)": fmt_p(r["p (sign-flip)"])} for r in pairs]
    md = ["### ATT&CK v8.2 (labels exactly as published)", "",
          "Cells are the macro mean over mapped safeguards with a 95% percentile bootstrap interval "
          "(1,000 resamples of safeguards, seed 0).", "", md_table(fmt(rows82), cols), "",
          f"Random baseline over 10 seeds: P@10 {rnd['P@10']} +/- {rnd['P@10_sd']}, "
          f"R@20 {rnd['R@20']} +/- {rnd['R@20_sd']}, MAP@200 {rnd['MAP@200']} +/- {rnd['MAP@200_sd']}.", "",
          f"Oracle ceiling: a perfect ranker scores P@10 = {ceil['oracle_P@10']:.3f}, because "
          f"{ceil['safeguards_lt10_gold']} of {ceil['mapped_safeguards']} safeguards have fewer than 10 gold "
          "techniques.", ""]
    if ptab:
        md += ["Paired differences over the same safeguards (paired bootstrap, 2,000 resamples; two-sided "
               "sign-flip permutation test, 20,000 draws, p never 0; not multiplicity-adjusted):", "",
               md_table(ptab, list(ptab[0])), ""]
    md += ["### ATT&CK v19.2 (labels carried forward via revoked-by)", "", md_table(fmt(rows19), cols), "",
           "Per-safeguard scores for every mapper: `results/automap_per_control.csv.gz`."]
    write_md("automap", md)
    ids82 = [c.id for c in v82.controls.values() if c.mitigates]
    ids19 = [c.id for c in real.controls.values() if c.mitigates]
    pc_rows = [[u, m, cid, f"{sc['MAP@200'][i]:.6f}", f"{sc['P@10'][i]:.4f}"]
               for u, per, ids in (("v8.2", per82, ids82), ("v19.2", per19, ids19))
               for m, sc in per.items() for i, cid in enumerate(ids)]
    write_csv_gz("automap_per_control", ["attack", "mapper", "safeguard", "AP@200", "P@10"], pc_rows)
    write_result("automap", {"ground_truth": "CIS Controls v8 -> MITRE Enterprise ATT&CK v8.2 master mapping",
                             "mapped_safeguards": rows82[0]["controls"], "v8.2": rows82, "v19.2": rows19,
                             "random_10_seeds": rnd, "ceilings_v8.2": ceil, "paired_v8.2": pairs})
    FIGS.mkdir(parents=True, exist_ok=True)
    figure(rows82, FIGS / "automap.png")
    print("\n".join(md))


if __name__ == "__main__":
    main()
