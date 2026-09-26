"""FastAPI layer + static ATT&CK heatmap UI.

    python -m vantage serve --catalog real          # http://127.0.0.1:8000

Security: read-only, binds to localhost by default, and if ``VANTAGE_API_TOKEN`` is set every
/api route requires ``Authorization: Bearer <token>``. The coverage map is sensitive (it is a
list of blind spots), so never expose this on a public interface.
"""
from __future__ import annotations

import copy
import hmac
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .catalog import load_catalog
from .coverage import compute_coverage
from .failure import rank_spofs
from .io import load_org
from .models import CoverageStatus, OrgPosture
from .navigator import to_layer
from .recommend import recommend
from .report import audit_report, tactic_table
from .selectors import expand_org
from .synth import demo_org
from .zerotrust import score_zero_trust

WEB = Path(__file__).resolve().parent / "web"
REAL_DEMO_ORG = Path(__file__).resolve().parent.parent / "examples" / "real" / "acme-real.yaml"
_RANK = {CoverageStatus.DEFENDED: 3, CoverageStatus.DETECTED_ONLY: 2, CoverageStatus.PAPER_ONLY: 1,
         CoverageStatus.BLIND: 0}


class WhatIf(BaseModel):
    """Hypothetical changes applied on top of the declared posture (never persisted)."""
    disable_log_sources: list[str] = Field(default_factory=list, max_length=500)
    enable_log_sources: list[str] = Field(default_factory=list, max_length=500)
    disable_controls: list[str] = Field(default_factory=list, max_length=500)
    deploy_all_rules: bool = False


def _auth(authorization: str | None = Header(default=None)) -> None:
    token = os.environ.get("VANTAGE_API_TOKEN")
    if not token:
        return
    given = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(given.encode(), token.encode()):
        raise HTTPException(401, "missing or invalid token")


def create_app(catalog: str | None = "seed", org_path: str | None = None) -> FastAPI:
    cat = load_catalog(catalog)
    if org_path:
        org = load_org(org_path)
    elif catalog not in (None, "", "seed") and REAL_DEMO_ORG.exists():
        org = load_org(REAL_DEMO_ORG)
    else:
        org = demo_org()
    expand_org(cat, org)
    cat.validate_org(org)

    app = FastAPI(title="VANTAGE", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json")
    api = [Depends(_auth)]

    def apply(w: WhatIf | None) -> OrgPosture:
        o = copy.deepcopy(org)
        if w:
            o.ingested_log_sources = (o.ingested_log_sources - set(w.disable_log_sources)) | (
                set(w.enable_log_sources) & cat.log_sources.keys())
            o.claimed_controls -= set(w.disable_controls)
            if w.deploy_all_rules:
                o.deployed_detections = set(cat.detections)
        return o

    def matrix(cov) -> list[dict]:
        order = cat.meta.get("tactic_order") or sorted({x for t in cat.techniques.values()
                                                        for x in t.all_tactics})
        subs: dict[str, list[str]] = {}
        for tid in cat.techniques:
            if "." in tid and tid.split(".")[0] in cat.techniques:
                subs.setdefault(tid.split(".")[0], []).append(tid)
        cols = []
        for tac in order:
            cells = []
            for t in cat.techniques.values():
                if tac not in t.all_tactics or ("." in t.id and t.id.split(".")[0] in cat.techniques):
                    continue
                kids = sorted(subs.get(t.id, []))
                sts = [cov.status[t.id]] + [cov.status[k] for k in kids]
                cells.append({
                    "id": t.id, "name": t.name, "status": cov.status[t.id].value,
                    "best": max(sts, key=_RANK.get).value,
                    "subs": len(kids),
                    "subs_defended": sum(cov.status[k] == CoverageStatus.DEFENDED for k in kids),
                    "rules": len(cov.detected_by[t.id]) + sum(len(cov.detected_by[k]) for k in kids),
                })
            cells.sort(key=lambda c: c["name"])
            cols.append({"tactic": tac, "name": cat.meta.get("tactic_names", {}).get(tac, tac),
                         "techniques": cells})
        return cols

    def coverage_payload(o: OrgPosture) -> dict:
        cov = compute_coverage(cat, o)
        s = cov.summary()
        s["dead_detections"] = len(s["dead_detections"])
        s["live_detections"] = sum(1 for d in o.deployed_detections if d not in cov.dead_detections)
        return {"summary": s, "matrix": matrix(cov), "tactics": tactic_table(cat, cov),
                "zero_trust": score_zero_trust(o.zero_trust, cat).score}

    @app.get("/api/meta", dependencies=api)
    def meta():
        return {
            "version": __version__, "org": org.name,
            "catalog": {"techniques": len(cat.techniques), "controls": len(cat.controls),
                        "detections": len(cat.detections), "log_sources": len(cat.log_sources),
                        "mitigations": len(cat.mitigations), **{k: v for k, v in cat.meta.items()
                                                                if k in ("attack_version", "cis", "sigma")}},
            "log_sources": sorted(
                ({"id": ls.id, "cost": ls.cost, "ingested": ls.id in org.ingested_log_sources,
                  "rules": sum(1 for d in cat.detections.values() if ls.id in d.requires)}
                 for ls in cat.log_sources.values()), key=lambda x: (-x["rules"], x["id"])),
            "controls": [{"id": c.id, "title": c.title, "claimed": c.id in org.claimed_controls,
                          "ig": c.ig, "techniques": len(c.mitigates)} for c in cat.controls.values()],
        }

    @app.get("/api/coverage", dependencies=api)
    def coverage_get():
        return coverage_payload(org)

    @app.post("/api/coverage", dependencies=api)
    def coverage_post(w: WhatIf):
        return coverage_payload(apply(w))

    @app.get("/api/technique/{tid}", dependencies=api)
    def technique(tid: str):
        t = cat.techniques.get(tid.upper())
        if not t:
            raise HTTPException(404, "unknown technique")
        cov = compute_coverage(cat, org)
        rel = [x for x in cat.techniques if x == t.id or x.startswith(t.id + ".")]

        def det(d):
            x = cat.detections[d]
            return {"id": d, "title": x.title, "level": x.level, "requires": sorted(x.requires)}
        return {
            "id": t.id, "name": t.name, "tactics": list(t.all_tactics), "description": t.description[:1500],
            "status": cov.status[t.id].value,
            "claimed_by": [{"id": c, "title": cat.controls[c].title} for c in sorted(cov.claimed[t.id])],
            "live_rules": [det(d) for d in sorted(cov.detected_by[t.id])][:50],
            "dead_rules": [det(d) for d in sorted(cov.dead_detections) if t.id in cat.detections[d].techniques][:50],
            "subtechniques": [{"id": x, "name": cat.techniques[x].name, "status": cov.status[x].value}
                              for x in sorted(rel) if x != t.id],
        }

    @app.post("/api/failure", dependencies=api)
    def failure(w: WhatIf | None = None, top: int = Query(10, ge=1, le=100)):
        return [{"kind": i.kind, "node": i.node, "dark": len(i.techniques_gone_dark),
                 "pct": i.pct_of_matrix, "techniques": list(i.techniques_gone_dark[:40])}
                for i in rank_spofs(cat, apply(w), top)]

    @app.post("/api/recommend", dependencies=api)
    def recs(w: WhatIf | None = None, steps: int = Query(5, ge=1, le=25),
             log_sources_only: bool = True, budget: float | None = Query(None, gt=0)):
        acts = ("onboard_log_source",) if log_sources_only else ("deploy_detection", "onboard_log_source")
        return [{"action": r.action, "target": r.target, "cost": r.cost, "new": len(r.new_techniques),
                 "techniques": list(r.new_techniques[:40]), "enables": len(r.enables)}
                for r in recommend(cat, apply(w), max_steps=steps, budget=budget, actions=acts)]

    @app.get("/api/zt", dependencies=api)
    def zt():
        s = score_zero_trust(org.zero_trust, cat)
        return {"score": s.score, "components": s.components,
                "exposed_lateral_techniques": list(s.exposed_lateral_techniques)}

    mappers: dict = {}

    @app.get("/api/automap", dependencies=api)
    def automap_(text: str = Query(..., min_length=3, max_length=4000),
                 method: str = Query("tfidf", pattern="^(tfidf|embed|bridge|bridge-embed)$"),
                 k: int = Query(10, ge=1, le=50)):
        from .cli import make_mapper
        if method.startswith("bridge") and not cat.mitigations:
            method = "tfidf"
        if method not in mappers:
            try:
                mappers[method] = make_mapper(cat, method)
            except RuntimeError as e:
                raise HTTPException(501, str(e)) from e
        return [{"id": t, "name": cat.techniques[t].name, "score": s} for t, s in mappers[method].rank(text, k)]

    @app.get("/api/report", dependencies=api, response_class=PlainTextResponse)
    def report():
        return audit_report(cat, org)

    @app.get("/api/navigator", dependencies=api)
    def navigator():
        return to_layer(cat, compute_coverage(cat, org), f"VANTAGE: {org.name}")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB / "index.html")

    app.mount("/static", StaticFiles(directory=WEB), name="static")
    return app


def app_from_env() -> FastAPI:  # for `uvicorn vantage.api:app_from_env --factory`
    return create_app(os.environ.get("VANTAGE_CATALOG", "seed"), os.environ.get("VANTAGE_ORG"))
