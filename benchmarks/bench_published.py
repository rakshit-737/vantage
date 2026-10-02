"""Comparison with published control -> ATT&CK auto-mapping results (task C).

    python benchmarks/bench_published.py      # reads results/crossframework.json, writes results/published.md

No published benchmark can be reproduced like-for-like, so this script only lays VANTAGE's numbers
next to the closest published setups and lists every difference. It computes nothing new.
"""
from __future__ import annotations

import json

from common import RESULTS, md_table


def main() -> None:
    cf = json.loads((RESULTS / "crossframework.json").read_text(encoding="utf-8"))
    n = "NIST 800-53"
    rows = [{"system": "Lee et al. 2026, SBERT + ATT&CK mitigations ensemble (published)",
             "ground truth": "CTID NIST 800-53 mapping as 'silver standard', K-RMF control text",
             "metric": "Recall@restricted (paper's own calibrated metric)", "value": "0.74 (as reported)"}]
    names = {"tfidf": "TF-IDF", "embed": "MiniLM-L6-v2"}
    for enc, a in cf["automap"].items():
        for block, label in (("direct", "direct text match"), ("zero_shot", "mitigation bridge, zero-shot"),
                             ("pooled", "TransferMapper, trained on the 7 other frameworks")):
            r = a[block][n]
            rows.append({"system": f"VANTAGE {label} ({names.get(enc, enc)})",
                         "ground truth": "CTID NIST 800-53 rev5, 109 controls",
                         "metric": "R@10 / R@50 / MAP@200",
                         "value": f"{r['R@10']:.3f} / {r['R@50']:.3f} / {r['MAP@200']:.3f}"})
    rows.append({"system": "TRAM (CTID), CTI sentence classifier (published)",
                 "ground truth": "TRAM-labelled CTI report sentences, about 50 techniques",
                 "metric": "micro-F1 on sentences", "value": "different task: not comparable"})
    diffs = [
        "Lee et al. 2026 (Electronics 15(6):1248, doi:10.3390/electronics15061248) is the closest published "
        "setup and the prior art for routing through ATT&CK mitigations. Its headline metric, Recall@restricted, "
        "is defined in the full text, which we could not retrieve (HTTP 403 from both MDPI and preprints.org); "
        "the abstract says only that it is 'calibrated' for the coverage limits of the CTID silver standard. "
        "Without its exact definition (restriction set, cut-off k) no number here should be read as better or "
        "worse than 0.74.",
        "Control text: they use Korean RMF (K-RMF) control text; we use the NIST OSCAL rev5 control statements.",
        "ATT&CK release: CTID labels target v16.1; we carry them to v19.2 and rank only techniques that existed "
        "in v16.1 (653 candidates).",
        "Model: they use an SBERT ensemble; the numbers above use the encoder named in the row.",
        "TRAM classifies CTI report sentences into about 50 techniques; its published scores come from a "
        "private 2023 dataset with unseeded splits, so there is no matching setup for control text.",
    ]
    md = ["### Comparison with published auto-mapping work", "",
          "**There is no directly comparable published benchmark** for control text -> ATT&CK ranking "
          "under our setup. The table puts VANTAGE's numbers next to the closest published work and lists "
          "every difference. It is context, not a head-to-head result.", "",
          md_table(rows, ["system", "ground truth", "metric", "value"]), "",
          "Setup differences:", "", *[f"- {d}" for d in diffs], ""]
    (RESULTS / "published.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
