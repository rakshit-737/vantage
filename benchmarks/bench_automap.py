"""Benchmark: auto-mapping CIS v8 safeguard text -> ATT&CK techniques, scored against the
official CIS v8 -> ATT&CK v8.2 master mapping.

    python benchmarks/bench_automap.py            # add --no-embed to skip sentence-transformers

Ground truth: 105 of 153 safeguards carry >= 1 mapped (sub-)technique (2,962 pairs).
Mappers only see the safeguard title + description and public ATT&CK text; no CIS labels are
used for fitting (the popularity baseline uses the *other* safeguards' labels, leave-one-out,
as an upper-bound-ish "prior only" reference).
"""
from __future__ import annotations

import argparse
import time

from common import FIGS, RESULTS, eval_catalog_v82, md_table, write_result

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


def run(cat, embed: bool) -> list[dict]:
    rows = []
    for m in mappers(cat, embed):
        t0 = time.perf_counter()
        r = automap.evaluate_mapper(m, cat, KS)
        r["seconds"] = round(time.perf_counter() - t0, 2)
        print(r)
        rows.append(r)
    return rows


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
    rows82 = run(v82, embed)
    real = load_catalog("real")
    print(f"== ATT&CK v19.2 universe (labels carried forward): {len(real.techniques)} techniques")
    rows19 = run(real, embed)
    cols = ["mapper", "P@5", "P@10", "R@10", "R@20", "R@50", "MAP@200", "seconds"]
    md = ["### ATT&CK v8.2 (labels exactly as published)", "", md_table(rows82, cols), "",
          "### ATT&CK v19.2 (labels carried forward via revoked-by)", "", md_table(rows19, cols)]
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "automap.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    write_result("automap", {"ground_truth": "CIS Controls v8 -> MITRE Enterprise ATT&CK v8.2 master mapping",
                             "mapped_safeguards": rows82[0]["controls"], "v8.2": rows82, "v19.2": rows19})
    FIGS.mkdir(parents=True, exist_ok=True)
    figure(rows82, FIGS / "automap.png")
    print("\n".join(md))


if __name__ == "__main__":
    main()
