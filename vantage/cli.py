"""VANTAGE command-line interface (read-only analysis of a declared posture file)."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

from . import __version__, automap
from .catalog import load_catalog
from .coverage import compute_coverage
from .failure import rank_control_spofs, rank_spofs, simulate_failure
from .graph import build_graph, to_cypher, to_json
from .io import load_org, save_org
from .models import CoverageStatus, ValidationError
from .recommend import recommend
from .report import audit_report, heatmap
from .selectors import expand_org
from .synth import demo_org, random_org
from .zerotrust import score_zero_trust

REAL_DEMO_ORG = Path(__file__).resolve().parent / "postures" / "acme-real.yaml"  # shipped in the wheel
NIST_DEMO_ORG = REAL_DEMO_ORG.with_name("acme-nist.yaml")


def _catalog(args):
    return load_catalog(getattr(args, "catalog", None))


def is_real(args) -> bool:
    return getattr(args, "catalog", None) not in (None, "", "seed")


def _org(args):
    cat = _catalog(args)
    if getattr(args, "org", None):
        org = load_org(args.org)
    elif is_real(args):
        org = load_org(NIST_DEMO_ORG if args.catalog == "nist" else REAL_DEMO_ORG)
    else:
        org = demo_org()
    expand_org(cat, org)
    cat.validate_org(org)
    return cat, org


def cmd_coverage(a):
    cat, org = _org(a)
    cov = compute_coverage(cat, org)
    s = cov.summary()
    if len(s["dead_detections"]) > 20:
        s["dead_detections"] = len(s["dead_detections"])
    print(json.dumps(s, indent=2))
    print(heatmap(cat, cov))


def cmd_failure(a):
    cat, org = _org(a)
    if a.node:
        impacts = [simulate_failure(cat, org, a.kind, a.node)]
    elif a.kind == "control":
        impacts = rank_control_spofs(cat, org, a.top)
    else:
        impacts = rank_spofs(cat, org, a.top)
    for i in impacts:
        shown = ", ".join(i.techniques_gone_dark[:12]) + (" ..." if len(i.techniques_gone_dark) > 12 else "")
        print(f"{i.kind:<11} {i.node:<28} dark={len(i.techniques_gone_dark):>3} "
              f"({i.pct_of_matrix}%)  {shown}")


def cmd_recommend(a):
    cat, org = _org(a)
    actions = ("onboard_log_source",) if a.log_sources_only else ("deploy_detection", "onboard_log_source")
    for n, r in enumerate(recommend(cat, org, budget=a.budget, max_steps=a.steps, actions=actions), 1):
        shown = ", ".join(r.new_techniques[:12]) + (" ..." if len(r.new_techniques) > 12 else "")
        print(f"{n}. {r.action:<19} {r.target:<28} cost={r.cost:<5g} +{len(r.new_techniques)} {shown}")


def cmd_zt(a):
    cat, org = _org(a)
    s = score_zero_trust(org.zero_trust, cat)
    print(json.dumps({"score": s.score, "components": s.components,
                      "exposed_lateral_techniques": len(s.exposed_lateral_techniques)
                      if len(s.exposed_lateral_techniques) > 30 else list(s.exposed_lateral_techniques)},
                     indent=2))


def cmd_report(a):
    cat, org = _org(a)
    text = audit_report(cat, org)
    if a.pdf:
        from .pdf import markdown_to_pdf
        markdown_to_pdf(text, a.pdf)
        print(f"wrote {a.pdf}")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {a.out}")
    elif not a.pdf:
        print(text)


def make_mapper(cat, method: str):
    if method == "embed":
        return automap.EmbeddingMapper(cat)
    if method in ("bridge", "bridge-embed"):
        return automap.MitigationBridgeMapper(cat, "embed" if method == "bridge-embed" else "tfidf")
    return automap.TfidfMapper(cat)


def cmd_automap(a):
    cat = _catalog(a)
    if a.eval:
        print(json.dumps(automap.evaluate(cat, a.k), indent=2))
        return
    for tid, score in make_mapper(cat, a.method).rank(a.text, a.k):
        print(f"{tid:<10} {score:.3f}  {cat.techniques[tid].name}")


def cmd_graph(a):
    cat, org = _org(a)
    g = build_graph(cat, org)
    print(to_cypher(g) if a.format == "cypher" else to_json(g))


def cmd_navigator(a):
    from .navigator import to_layer_json
    cat, org = _org(a)
    text = to_layer_json(cat, compute_coverage(cat, org), f"VANTAGE: {org.name}")
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"wrote {a.out}")
    else:
        print(text)


def cmd_serve(a):  # pragma: no cover - interactive
    import os

    import uvicorn

    from .api import create_app, resolve_token
    if a.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding beyond localhost exposes a map of your blind spots; add the name you "
              "browse to in VANTAGE_ALLOWED_HOSTS and keep the token secret.", file=sys.stderr)
    os.environ.setdefault("VANTAGE_PORT", str(a.port))
    app = create_app(a.catalog, a.org, token=resolve_token() or "")
    uvicorn.run(app, host=a.host, port=a.port, server_header=False)


def cmd_synth(a):
    cat = _catalog(a)
    org = demo_org() if a.demo else random_org(cat, a.seed, a.maturity)
    save_org(org, a.out)
    print(f"wrote {a.out}")


def cmd_demo(a):
    cat, org = _org(a)
    cov = compute_coverage(cat, org)
    s = cov.summary()
    print(f"== {org.name} ({len(cat.techniques)} techniques, {len(cat.detections)} detections, "
          f"{len(cat.controls)} controls) ==")
    print(f"[1] Compliant but blind: claimed {s['claimed_pct']}% vs true {s['true_pct']}% "
          f"({s['paper_only']} paper-only techniques, {len(cov.dead_detections)} dead rules)")
    spofs = rank_spofs(cat, org, top=1)
    if spofs:
        sp = spofs[0]
        print(f"[2] SPOF: losing {sp.kind} '{sp.node}' blinds {len(sp.techniques_gone_dark)} techniques "
              f"({sp.pct_of_matrix}% of matrix)")
    top = recommend(cat, org, max_steps=1, actions=("onboard_log_source",))
    if top:
        r = top[0]
        print(f"[3] Cheapest win: {r.action} '{r.target}' (cost {r.cost:g}) -> "
              f"+{len(r.new_techniques)} techniques")
    before = score_zero_trust(org.zero_trust, cat)
    zt = copy.deepcopy(org.zero_trust)
    zt.open_flows.discard(frozenset({"finance", "general"}))
    zt.open_flows.discard(frozenset({"servers", "general"}))
    after = score_zero_trust(zt, cat)
    print(f"[4] ZT delta: microsegment finance/servers from general -> score {before.score} -> "
          f"{after.score}, exposed lateral techniques {len(before.exposed_lateral_techniques)} -> "
          f"{len(after.exposed_lateral_techniques)}")
    opts = (f" --catalog {a.catalog}" if is_real(a) else "") + (f" --org {a.org}" if a.org else "")
    print(f"[5] Audit report: run `python -m vantage report{opts} --out report.md --pdf report.pdf`")
    if not cat.mitigations:
        ev = automap.evaluate(cat)
        print(f"[+] Auto-map (TF-IDF) vs seed labels @k={ev['k']}: P={ev['precision']} R={ev['recall']}")
    blind = cov.by_status(CoverageStatus.BLIND)
    shown = ", ".join(blind[:15]) + (f" ... (+{len(blind) - 15})" if len(blind) > 15 else "")
    print(f"[+] Blind techniques ({len(blind)}): {shown or 'none'}")


def _positive_int(text: str) -> int:
    """argparse type: an integer >= 1 (matches the API bounds)."""
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {text!r}") from None
    if v < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {v}")
    return v


def _positive_float(text: str) -> float:
    """argparse type: a number > 0."""
    try:
        v = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a positive number, got {text!r}") from None
    if not v > 0:
        raise argparse.ArgumentTypeError(f"must be > 0, got {text}")
    return v


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vantage", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    cat_help = ("catalog: 'seed' (offline toy, default), 'real' (ATT&CK + CIS + Sigma built by "
                "`python -m vantage.ingest.build`), 'nist' (same, NIST 800-53 rev5 controls) or a JSON path")

    def add(name, fn, help_, org=True):
        sp = sub.add_parser(name, help=help_)
        if org:
            sp.add_argument("--org", help="org posture YAML (default: built-in demo org)")
        sp.add_argument("--catalog", default="seed", help=cat_help)
        sp.set_defaults(fn=fn)
        return sp

    add("coverage", cmd_coverage, "coverage summary + heatmap")
    f = add("failure", cmd_failure, "failure propagation / SPOF ranking")
    f.add_argument("--kind", choices=["log_source", "detection", "control"], default="log_source",
                   help="node type to fail; 'control' = a claimed control lapses (techniques lose their claim). "
                        "Without --node, log_source/detection rank both detection-side kinds together")
    f.add_argument("--node", help="fail this one node id instead of ranking all single points of failure")
    f.add_argument("--top", type=_positive_int, default=10, help="how many SPOFs to list (default 10)")
    r = add("recommend", cmd_recommend, "greedy set-cover recommendations")
    r.add_argument("--budget", type=_positive_float, help="total onboarding cost budget, > 0 (default: no limit)")
    r.add_argument("--steps", type=_positive_int, default=5, help="maximum number of recommended actions (default 5)")
    r.add_argument("--log-sources-only", action="store_true", help="only 'onboard log source' actions")
    add("zt", cmd_zt, "Zero-Trust posture score")
    rp = add("report", cmd_report, "compliant-but-undetectable audit report (markdown / PDF)")
    rp.add_argument("--out", help="write the markdown report here (default: stdout)")
    rp.add_argument("--pdf", help="also render a PDF (needs the 'report' extra: reportlab)")
    g = add("graph", cmd_graph, "export graph (json or cypher for optional Neo4j)")
    g.add_argument("--format", choices=["json", "cypher"], default="json", help="output format (default json)")
    nv = add("navigator", cmd_navigator, "export an ATT&CK Navigator layer JSON")
    nv.add_argument("--out", help="write the layer here (default: stdout)")
    sv = add("serve", cmd_serve, "FastAPI + ATT&CK heatmap UI (localhost only by default)")
    sv.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1; keep it local)")
    sv.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    add("demo", cmd_demo, "run the five demo scenarios")
    am = add("automap", cmd_automap, "map free-text control to ATT&CK", org=False)
    am.add_argument("text", nargs="?", default="", help="control text to map (required unless --eval)")
    am.add_argument("-k", type=_positive_int, default=5, help="number of techniques to return (default 5)")
    am.add_argument("--eval", action="store_true", help="evaluate the mapper against the catalog's own labels")
    am.add_argument("--method", choices=["tfidf", "embed", "bridge", "bridge-embed"], default="tfidf",
                    help="tfidf/embed: match technique text; bridge*: route through ATT&CK mitigations "
                         "(real catalog only); embed variants need the 'ml' extra")
    sy = add("synth", cmd_synth, "write a synthetic org YAML", org=False)
    sy.add_argument("--out", required=True, help="output YAML path")
    sy.add_argument("--seed", type=int, default=0, help="random seed (default 0)")
    sy.add_argument("--maturity", type=float, default=0.5, help="0..1: share of controls/log sources/rules adopted")
    sy.add_argument("--demo", action="store_true", help="write the built-in Acme demo org instead")
    return p


_EXTRA = {"uvicorn": "api", "fastapi": "api", "starlette": "api", "reportlab": "report", "openpyxl": "data",
          "sentence_transformers": "ml"}


def main(argv: list[str] | None = None) -> int:
    """Entry point. Expected user errors exit 2 with a one-line hint instead of a traceback."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "automap" and not args.eval and not args.text.strip():
        parser.error("automap: give the control text to map, or --eval")
    try:
        args.fn(args)
    except ModuleNotFoundError as e:
        extra = _EXTRA.get((e.name or "").split(".")[0])
        hint = f"pip install 'vantage[{extra}]'" if extra else "check your installation"
        print(f"vantage: missing optional dependency {e.name!r}: {hint}", file=sys.stderr)
        return 2
    except (ValidationError, FileNotFoundError, RuntimeError, ValueError) as e:
        print(f"vantage: error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
