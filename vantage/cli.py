"""VANTAGE command-line interface (read-only analysis of a declared posture file)."""
from __future__ import annotations

import argparse
import json
import sys

from . import automap
from .coverage import compute_coverage
from .failure import rank_spofs, simulate_failure
from .graph import build_graph, to_cypher, to_json
from .io import load_org, save_org
from .models import CoverageStatus
from .recommend import recommend
from .report import audit_report, heatmap
from .seed import load_seed_catalog
from .synth import demo_org, random_org
from .zerotrust import score_zero_trust


def _org(args):
    cat = load_seed_catalog()
    org = load_org(args.org) if getattr(args, "org", None) else demo_org()
    cat.validate_org(org)
    return cat, org


def cmd_coverage(a):
    cat, org = _org(a)
    cov = compute_coverage(cat, org)
    print(json.dumps(cov.summary(), indent=2))
    print(heatmap(cat, cov))


def cmd_failure(a):
    cat, org = _org(a)
    impacts = [simulate_failure(cat, org, a.kind, a.node)] if a.node else rank_spofs(cat, org, a.top)
    for i in impacts:
        print(f"{i.kind:<11} {i.node:<18} dark={len(i.techniques_gone_dark):>2} "
              f"({i.pct_of_matrix}%)  {', '.join(i.techniques_gone_dark)}")


def cmd_recommend(a):
    cat, org = _org(a)
    for n, r in enumerate(recommend(cat, org, budget=a.budget, max_steps=a.steps), 1):
        print(f"{n}. {r.action:<19} {r.target:<18} cost={r.cost:<4g} +{len(r.new_techniques)} "
              f"{', '.join(r.new_techniques)}")


def cmd_zt(a):
    cat, org = _org(a)
    s = score_zero_trust(org.zero_trust, cat)
    print(json.dumps({"score": s.score, "components": s.components,
                      "exposed_lateral_techniques": list(s.exposed_lateral_techniques)}, indent=2))


def cmd_report(a):
    cat, org = _org(a)
    text = audit_report(cat, org)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {a.out}")
    else:
        print(text)


def cmd_automap(a):
    cat = load_seed_catalog()
    if a.eval:
        print(json.dumps(automap.evaluate(cat, a.k), indent=2))
        return
    for tid, score in automap.TfidfMapper(cat).rank(a.text, a.k):
        print(f"{tid:<10} {score:.3f}  {cat.techniques[tid].name}")


def cmd_graph(a):
    cat, org = _org(a)
    g = build_graph(cat, org)
    print(to_cypher(g) if a.format == "cypher" else to_json(g))


def cmd_synth(a):
    cat = load_seed_catalog()
    org = demo_org() if a.demo else random_org(cat, a.seed, a.maturity)
    save_org(org, a.out)
    print(f"wrote {a.out}")


def cmd_demo(a):
    cat, org = _org(a)
    cov = compute_coverage(cat, org)
    s = cov.summary()
    print(f"== {org.name} ==")
    print(f"[1] Compliant but blind: claimed {s['claimed_pct']}% vs true {s['true_pct']}% "
          f"({s['paper_only']} paper-only techniques, {len(cov.dead_detections)} dead rules)")
    edr = simulate_failure(cat, org, "log_source", "edr")
    print(f"[2] SPOF: losing EDR telemetry blinds {len(edr.techniques_gone_dark)} techniques "
          f"({edr.pct_of_matrix}% of matrix)")
    top = recommend(cat, org, max_steps=1)
    if top:
        r = top[0]
        print(f"[3] Cheapest win: {r.action} '{r.target}' (cost {r.cost:g}) -> "
              f"+{len(r.new_techniques)} techniques")
    before = score_zero_trust(org.zero_trust, cat)
    org.zero_trust.open_flows.discard(frozenset({"finance", "general"}))
    org.zero_trust.open_flows.discard(frozenset({"servers", "general"}))
    after = score_zero_trust(org.zero_trust, cat)
    print(f"[4] ZT delta: microsegment finance/servers from general -> score {before.score} -> "
          f"{after.score}, exposed lateral techniques {len(before.exposed_lateral_techniques)} -> "
          f"{len(after.exposed_lateral_techniques)}")
    print("[5] Audit report: run `python -m vantage report --out report.md`")
    ev = automap.evaluate(cat)
    print(f"[+] Auto-map (TF-IDF) vs seed labels @k={ev['k']}: P={ev['precision']} R={ev['recall']}")
    blind = cov.by_status(CoverageStatus.BLIND)
    print(f"[+] Blind techniques: {', '.join(blind) or 'none'}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vantage", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("--org", help="org posture YAML (default: built-in synthetic demo org)")
        sp.set_defaults(fn=fn)
        return sp

    add("coverage", cmd_coverage, "coverage summary + heatmap")
    f = add("failure", cmd_failure, "failure propagation / SPOF ranking")
    f.add_argument("--kind", choices=["log_source", "detection"], default="log_source")
    f.add_argument("--node")
    f.add_argument("--top", type=int, default=10)
    r = add("recommend", cmd_recommend, "greedy set-cover recommendations")
    r.add_argument("--budget", type=float)
    r.add_argument("--steps", type=int, default=5)
    add("zt", cmd_zt, "Zero-Trust posture score")
    rp = add("report", cmd_report, "compliant-but-undetectable audit report (markdown)")
    rp.add_argument("--out")
    g = add("graph", cmd_graph, "export graph (json or cypher for optional Neo4j)")
    g.add_argument("--format", choices=["json", "cypher"], default="json")
    add("demo", cmd_demo, "run the five demo scenarios")
    am = sub.add_parser("automap", help="map free-text control to ATT&CK")
    am.add_argument("text", nargs="?", default="")
    am.add_argument("-k", type=int, default=5)
    am.add_argument("--eval", action="store_true")
    am.set_defaults(fn=cmd_automap)
    sy = sub.add_parser("synth", help="write a synthetic org YAML")
    sy.add_argument("--out", required=True)
    sy.add_argument("--seed", type=int, default=0)
    sy.add_argument("--maturity", type=float, default=0.5)
    sy.add_argument("--demo", action="store_true")
    sy.set_defaults(fn=cmd_synth)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.fn(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
