"""Markdown reports: ATT&CK text heatmap + 'compliant-but-undetectable' audit report."""
from __future__ import annotations

from collections import defaultdict

from .coverage import CoverageResult, compute_coverage
from .failure import rank_spofs
from .models import Catalog, CoverageStatus, OrgPosture
from .recommend import recommend
from .zerotrust import score_zero_trust

GLYPH = {CoverageStatus.DEFENDED: "[D]", CoverageStatus.PAPER_ONLY: "[P]",
         CoverageStatus.DETECTED_ONLY: "[d]", CoverageStatus.BLIND: "[ ]"}


def heatmap(cat: Catalog, cov: CoverageResult) -> str:
    by_tactic: dict[str, list[str]] = defaultdict(list)
    for t in cat.techniques.values():
        by_tactic[t.tactic].append(t.id)
    lines = ["Legend: [D] defended  [P] paper-only (claimed, not detectable)  "
             "[d] detected, no control  [ ] blind", ""]
    for tactic in sorted(by_tactic):
        cells = " ".join(f"{GLYPH[cov.status[t]]}{t}" for t in sorted(by_tactic[tactic]))
        lines.append(f"{tactic:<20} {cells}")
    return "\n".join(lines)


def audit_report(cat: Catalog, org: OrgPosture) -> str:
    cov = compute_coverage(cat, org)
    s = cov.summary()
    zt = score_zero_trust(org.zero_trust, cat)
    out = [
        f"# VANTAGE audit report: {org.name}",
        "",
        "> Generated from a declared posture file. Treat as SENSITIVE: this document is a map "
        "of blind spots.",
        "",
        "## Summary",
        "",
        f"- Techniques in scope: {s['techniques']}",
        f"- Claimed (paper) coverage: **{s['claimed_pct']}%**",
        f"- True (defended) coverage: **{s['true_pct']}%**",
        f"- Paper-only techniques: {s['paper_only']}  |  Blind: {s['blind']}  |  "
        f"Detected without control: {s['detected_only']}",
        f"- Deployed-but-dead detections (log source not ingested): {len(cov.dead_detections)}",
        f"- Zero-Trust posture score: **{zt.score}/100**",
        "",
        "## Compliant but undetectable",
        "",
        "| Technique | Name | Claimed by | Why undetectable |",
        "| --- | --- | --- | --- |",
    ]
    for t in cov.by_status(CoverageStatus.PAPER_ONLY):
        dead = sorted(d for d in cov.dead_detections if t in cat.detections[d].techniques)
        why = ("rules deployed but missing log source: " + ", ".join(
            f"{d} (needs {', '.join(sorted(cat.detections[d].requires - org.ingested_log_sources))})"
            for d in dead)) if dead else "no detection deployed"
        out.append(f"| {t} | {cat.techniques[t].name} | {', '.join(sorted(cov.claimed[t]))} | {why} |")
    out += ["", "## Heatmap", "", "```", heatmap(cat, cov), "```", "", "## Single points of failure", ""]
    for i in rank_spofs(cat, org, top=5):
        out.append(f"- {i.kind} `{i.node}` -> {len(i.techniques_gone_dark)} techniques dark "
                   f"({i.pct_of_matrix}% of matrix)")
    out += ["", "## Recommended next actions (greedy set cover)", ""]
    for n, r in enumerate(recommend(cat, org, max_steps=5), 1):
        out.append(f"{n}. {r.action} `{r.target}` (cost {r.cost:g}) -> +{len(r.new_techniques)} "
                   f"techniques: {', '.join(r.new_techniques)}")
    out += ["", "## Zero-Trust components", ""]
    out += [f"- {k}: {v}" for k, v in zt.components.items()]
    if zt.exposed_lateral_techniques:
        out.append(f"- Lateral/discovery techniques exposed by open flows into critical segments: "
                   f"{', '.join(zt.exposed_lateral_techniques)}")
    return "\n".join(out) + "\n"
