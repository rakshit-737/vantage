"""FastAPI layer + static ATT&CK heatmap UI.

    python -m vantage serve --catalog real          # http://127.0.0.1:8000

Security (the coverage map is a list of blind spots, so treat it as sensitive):

* binds to localhost by default; ``Host`` headers other than localhost (plus
  ``VANTAGE_ALLOWED_HOSTS``) are rejected, which defeats DNS rebinding from a web page;
* ``vantage serve`` and the Docker entrypoint require a bearer token on every /api route: the
  value of ``VANTAGE_API_TOKEN``, or a random one generated at start-up and printed as a
  ``http://127.0.0.1:8000/#token=...`` link (opt out only with ``VANTAGE_ALLOW_NO_AUTH=1``);
* request bodies are capped at 64 KiB and every what-if id at 200 characters;
* OpenAPI docs are off unless ``VANTAGE_API_DOCS=1``; responses carry a strict CSP.
"""
from __future__ import annotations

import copy
import hmac
import os
import secrets
import sys
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StringConstraints

from . import __version__
from .catalog import load_catalog
from .coverage import compute_coverage
from .failure import rank_control_spofs, rank_spofs
from .io import load_org
from .models import CoverageStatus, OrgPosture
from .navigator import to_layer
from .recommend import recommend
from .report import audit_report, tactic_table
from .selectors import expand_org
from .synth import demo_org
from .zerotrust import score_zero_trust

WEB = Path(__file__).resolve().parent / "web"
REAL_DEMO_ORG = Path(__file__).resolve().parent / "postures" / "acme-real.yaml"  # shipped in the wheel
_RANK = {CoverageStatus.DEFENDED: 3, CoverageStatus.DETECTED_ONLY: 2, CoverageStatus.PAPER_ONLY: 1,
         CoverageStatus.BLIND: 0}


MAX_BODY = 64 * 1024
LOCAL_HOSTS = ["127.0.0.1", "localhost", "::1", "[::1]"]
NodeId = Annotated[str, StringConstraints(max_length=200)]


class WhatIf(BaseModel):
    """Hypothetical changes applied on top of the declared posture (never persisted)."""
    disable_log_sources: list[NodeId] = Field(default_factory=list, max_length=500)
    enable_log_sources: list[NodeId] = Field(default_factory=list, max_length=500)
    disable_controls: list[NodeId] = Field(default_factory=list, max_length=500)
    deploy_all_rules: bool = False


def resolve_token() -> str | None:
    """Token for a served instance: $VANTAGE_API_TOKEN, else a fresh random one (printed), unless
    VANTAGE_ALLOW_NO_AUTH=1 explicitly turns authentication off."""
    tok = os.environ.get("VANTAGE_API_TOKEN")
    if tok:
        return tok
    if os.environ.get("VANTAGE_ALLOW_NO_AUTH") == "1":
        print("WARNING: VANTAGE_ALLOW_NO_AUTH=1, the API is unauthenticated", file=sys.stderr)
        return None
    tok = secrets.token_urlsafe(32)
    port = os.environ.get("VANTAGE_PORT", "8000")
    print(f"VANTAGE API token generated. Open http://127.0.0.1:{port}/#token={tok}", file=sys.stderr, flush=True)
    return tok


class _BodyLimit:
    """Pure-ASGI guard: 413 for bodies over MAX_BODY (declared or streamed)."""

    def __init__(self, app, limit: int = MAX_BODY):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k == b"content-length" and v.isdigit() and int(v) > self.limit:
                return await _reject(send)
        seen = 0

        async def capped():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.limit:
                    raise _TooLarge
            return msg
        try:
            return await self.app(scope, capped, send)
        except _TooLarge:
            return await _reject(send)


class _TooLarge(Exception):
    pass


async def _reject(send) -> None:
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"text/plain"), (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": b"request body too large"})


_HEADERS = [(b"content-security-policy", b"default-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
            (b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
            (b"x-frame-options", b"DENY")]


class _SecurityHeaders:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_h(msg):
            if msg["type"] == "http.response.start":
                msg["headers"] = list(msg.get("headers", [])) + _HEADERS
            await send(msg)
        return await self.app(scope, receive, send_h)


def create_app(catalog: str | None = "seed", org_path: str | None = None, token: str | None = None,
               allowed_hosts: list[str] | None = None) -> FastAPI:
    """Build the app. ``token``: bearer token required on /api (default: $VANTAGE_API_TOKEN, none if
    unset - the CLI and Docker entrypoints always pass one via ``resolve_token``)."""
    token = token if token is not None else os.environ.get("VANTAGE_API_TOKEN") or None
    cat = load_catalog(catalog)
    if org_path:
        org = load_org(org_path)
    elif catalog not in (None, "", "seed"):
        org = load_org(REAL_DEMO_ORG.with_name("acme-nist.yaml") if catalog == "nist" else REAL_DEMO_ORG)
    else:
        org = demo_org()
    expand_org(cat, org)
    cat.validate_org(org)

    docs = os.environ.get("VANTAGE_API_DOCS") == "1"
    app = FastAPI(title="VANTAGE", version=__version__, docs_url="/api/docs" if docs else None,
                  redoc_url=None, openapi_url="/api/openapi.json" if docs else None)
    hosts = allowed_hosts or [*LOCAL_HOSTS, *filter(None, os.environ.get("VANTAGE_ALLOWED_HOSTS", "").split(","))]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    app.add_middleware(_BodyLimit)
    app.add_middleware(_SecurityHeaders)

    def _auth(authorization: str | None = Header(default=None)) -> None:
        if not token:
            return
        given = (authorization or "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(given.encode(), token.encode()):
            raise HTTPException(401, "missing or invalid token")
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
    def failure(w: WhatIf | None = None, top: int = Query(10, ge=1, le=100),
                kind: str = Query("detection", pattern="^(detection|control)$")):
        rank = rank_control_spofs if kind == "control" else rank_spofs
        return [{"kind": i.kind, "node": i.node, "dark": len(i.techniques_gone_dark),
                 "pct": i.pct_of_matrix, "techniques": list(i.techniques_gone_dark[:40])}
                for i in rank(cat, apply(w), top)]

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
    """Docker entrypoint: always authenticated (see ``resolve_token``)."""
    return create_app(os.environ.get("VANTAGE_CATALOG", "seed"), os.environ.get("VANTAGE_ORG"),
                      token=resolve_token() or "")
