"""Benchmark: the "paper vs real" coverage gap on the real catalog
(ATT&CK v19.2 + official CIS v8 mapping + SigmaHQ r2026-07-01).

    python benchmarks/bench_coverage.py

Part A - telemetry tiers x CIS Implementation Group claims (deterministic profiles).
Part B - 100 random synthetic orgs (vantage.synth.random_org) across four maturity levels.
Part C - engine performance (fast one-pass SPOF ranking vs brute-force recomputation).
Part D - the same telemetry tiers with NIST SP 800-53 rev5 claims (CTID mapping), if built.
"""
from __future__ import annotations

import statistics
import time
from fnmatch import fnmatchcase

from common import FIGS, RESULTS, md_table, write_result

from vantage.catalog import load_catalog
from vantage.coverage import compute_coverage
from vantage.failure import rank_spofs, simulate_failure
from vantage.models import OrgPosture
from vantage.selectors import expand_org
from vantage.synth import random_org

SYSMON_CATS = ["process_creation", "registry_*", "file_*", "image_load", "network_connection", "dns_query",
               "process_access", "create_remote_thread", "pipe_created", "driver_load", "wmi_event",
               "create_stream_hash", "raw_access_thread", "process_tampering", "sysmon_*"]
TIERS = [
    ("T0 classic Windows event logs", ["windows/security", "windows/system", "windows/application"]),
    ("T1 + PowerShell logging", ["windows/ps_script", "windows/ps_module", "windows/powershell-classic",
                                 "windows/ps_classic_*"]),
    ("T2 + Sysmon/EDR-class endpoint", [f"windows/{c}" for c in SYSMON_CATS]),
    ("T3 + cloud & identity audit", ["aws/*", "azure/*", "gcp/*", "m365/*", "okta/*", "github/*",
                                     "google_workspace/*", "onelogin/*"]),
    ("T4 + network, web, Linux, macOS", ["proxy", "dns", "firewall", "webserver", "zeek/*", "linux*",
                                         "macos/*", "antivirus"]),
    ("T5 every Sigma log source", ["*"]),
]


def tier_sources(cat, upto: int) -> set[str]:
    pats = [p for _, ps in TIERS[: upto + 1] for p in ps]
    return {ls for ls in cat.log_sources if any(fnmatchcase(ls, p) for p in pats)}


def part_a(cat) -> list[dict]:
    rows = []
    for i, (tier, _) in enumerate(TIERS):
        ingested = tier_sources(cat, i)
        for ig in (1, 2, 3):
            org = expand_org(cat, OrgPosture(f"{tier}/IG{ig}", {f"@ig{ig}"}, set(ingested),
                                             {"@status:stable|test"}))
            cov = compute_coverage(cat, org)
            s = cov.summary()
            detected = len(cov.detected_set())
            rows.append({"tier": tier, "claims": f"IG{ig}", "log_sources": len(ingested),
                         "claimed_pct": s["claimed_pct"], "true_pct": s["true_pct"],
                         "weighted_true_pct": s["weighted_true_pct"],
                         "gap_pp": round(s["claimed_pct"] - s["true_pct"], 1),
                         "detectable_pct": round(100 * detected / s["techniques"], 1),
                         "paper_only": s["paper_only"], "detected_only": s["detected_only"],
                         "dead_rules": len(cov.dead_detections)})
    return rows


def part_b(cat, seeds: int = 25) -> list[dict]:
    rows = []
    for m in (0.2, 0.4, 0.6, 0.8):
        cl, tr, gap = [], [], []
        for s in range(seeds):
            cov = compute_coverage(cat, random_org(cat, s, m))
            cl.append(cov.claimed_pct)
            tr.append(cov.true_pct)
            gap.append(cov.claimed_pct - cov.true_pct)
        f = lambda xs: f"{statistics.mean(xs):.1f} +/- {statistics.stdev(xs):.1f}"  # noqa: E731
        half = 2.064 * statistics.stdev(gap) / seeds ** 0.5  # t(0.975, df=24) for 25 orgs
        mg = statistics.mean(gap)
        rows.append({"maturity": m, "orgs": seeds, "claimed_pct": f(cl), "true_pct": f(tr), "gap_pp": f(gap),
                     "gap_mean": round(mg, 1), "gap_95ci": f"[{mg - half:.1f}, {mg + half:.1f}]"})
    return rows


def part_c(cat) -> dict:
    org = expand_org(cat, OrgPosture("perf", {"@ig2"}, set(tier_sources(cat, 3)), {"@all"}))
    t = time.perf_counter()
    compute_coverage(cat, org)
    cov_ms = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    fast = rank_spofs(cat, org)
    fast_s = time.perf_counter() - t
    t = time.perf_counter()
    brute = []
    for ls in org.ingested_log_sources:
        i = simulate_failure(cat, org, "log_source", ls)
        if i.techniques_gone_dark:
            brute.append(i)
    for d in org.deployed_detections:
        i = simulate_failure(cat, org, "detection", d)
        if i.techniques_gone_dark:
            brute.append(i)
    brute_s = time.perf_counter() - t
    same = {(i.kind, i.node, i.techniques_gone_dark) for i in fast} == \
           {(i.kind, i.node, i.techniques_gone_dark) for i in brute}
    return {"deployed_rules": len(org.deployed_detections), "ingested_log_sources": len(org.ingested_log_sources),
            "coverage_ms": round(cov_ms, 1), "spof_fast_s": round(fast_s, 3), "spof_bruteforce_s": round(brute_s, 2),
            "speedup": round(brute_s / fast_s, 1), "identical_results": same}


def part_d() -> list[dict]:
    from vantage import paths
    if not paths.nist_catalog_path().exists():
        return []
    cat = load_catalog("nist")
    rows = []
    for i, (tier, _) in enumerate(TIERS):
        org = expand_org(cat, OrgPosture(f"{tier}/NIST", {"@all"}, tier_sources(cat, i), {"@status:stable|test"}))
        cov = compute_coverage(cat, org)
        s = cov.summary()
        rows.append({"tier": tier, "claims": "NIST 800-53 rev5 (all mapped)", "claimed_pct": s["claimed_pct"],
                     "detectable_pct": round(100 * len(cov.detected_set()) / s["techniques"], 1),
                     "true_pct": s["true_pct"], "weighted_true_pct": s["weighted_true_pct"],
                     "gap_pp": round(s["claimed_pct"] - s["true_pct"], 1), "paper_only": s["paper_only"]})
    return rows


def figure(rows, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ig2 = [r for r in rows if r["claims"] == "IG2"]
    labels = [r["tier"].split(" ", 1)[0] for r in ig2]
    x = range(len(ig2))
    fig, ax = plt.subplots(figsize=(8, 4.0))
    ax.bar([i - 0.27 for i in x], [r["claimed_pct"] for r in ig2], 0.27, label="claimed (CIS IG2 on paper)",
           color="#e0782a")
    ax.bar(list(x), [r["detectable_pct"] for r in ig2], 0.27, label="detectable (live Sigma rule)", color="#3b82c4")
    ax.bar([i + 0.27 for i in x], [r["true_pct"] for r in ig2], 0.27, label="defended (claimed AND detectable)",
           color="#2f9e5b")
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("% of 697 ATT&CK v19.2 techniques")
    ax.set_title("Paper vs real coverage by telemetry tier (CIS IG2 claimed, stable+test Sigma rules)",
                 fontsize=10)
    ax.legend(fontsize=8, loc='upper center', bbox_to_anchor=(0.5, -0.16), ncol=3, frameon=False)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=110)


def main() -> None:
    cat = load_catalog("real")
    a = part_a(cat)
    b = part_b(cat)
    c = part_c(cat)
    d = part_d()
    md = ["### A. Telemetry tier x claimed CIS Implementation Group", "",
          md_table(a, ["tier", "claims", "log_sources", "claimed_pct", "detectable_pct", "true_pct",
                       "weighted_true_pct", "gap_pp", "paper_only", "dead_rules"]),
          "", "`weighted_true_pct` scores each defended technique by rule quality (ADR 0007) instead of 0/1.",
          "", "### B. Random synthetic orgs (25 per maturity level)", "",
          md_table(b, ["maturity", "orgs", "claimed_pct", "true_pct", "gap_pp", "gap_95ci"]),
          "", "Values are mean +/- sd over 25 orgs (seeds 0-24); gap_95ci is a t-interval of the mean gap.",
          "", "### C. Engine performance", "", md_table([c], list(c))]
    if d:
        md += ["", "### D. NIST SP 800-53 rev5 claims (CTID mapping, ATT&CK v16.1 carried to v19.2)", "",
               md_table(d, ["tier", "claimed_pct", "detectable_pct", "true_pct", "weighted_true_pct", "gap_pp",
                            "paper_only"])]
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "coverage.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    write_result("coverage", {"catalog": cat.meta, "tiers": a, "random_orgs": b, "performance": c,
                             "nist_tiers": d})
    FIGS.mkdir(parents=True, exist_ok=True)
    figure(a, FIGS / "coverage_gap.png")
    print("\n".join(md))


if __name__ == "__main__":
    main()
