#!/usr/bin/env python
"""Pre-render the web UI as a static site (for GitHub Pages) from the API's own responses.

    python scripts/export_demo.py --catalog real --out docs/demo

What-if toggles and auto-mapping need a live API, so the static page shows the baseline posture
only. The output holds ids, names, counts and Sigma rule titles (DRL 1.1, attribution via the
SigmaHQ link in the docs); no CIS workbook text is exported.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from vantage.api import WEB, create_app  # noqa: E402


def dump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, separators=(",", ":")), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default="real")
    ap.add_argument("--out", default=str(ROOT / "docs" / "demo"))
    a = ap.parse_args()
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    data = out / "data"
    c = TestClient(create_app(a.catalog))
    meta = c.get("/api/meta").json()
    meta["controls"] = [{k: x[k] for k in ("id", "claimed", "ig", "techniques")} for x in meta["controls"]]
    dump(data / "meta.json", meta)
    cov = c.get("/api/coverage").json()
    dump(data / "coverage.json", cov)
    dump(data / "failure.json", c.post("/api/failure?top=8", json={}).json())
    dump(data / "recommend.json", c.post("/api/recommend?steps=6&log_sources_only=true", json={}).json())
    for col in cov["matrix"]:
        for t in col["techniques"]:
            r = c.get(f"/api/technique/{t['id']}").json()
            r["description"] = r["description"][:600]
            # control ids only: the CIS workbook text is CC BY-NC-ND and is not redistributed
            r["claimed_by"] = [{"id": x["id"], "title": ""} for x in r["claimed_by"]]
            for key in ("live_rules", "dead_rules"):
                r[key] = r[key][:12]
            dump(data / "technique" / f"{t['id']}.json", r)
    html = (WEB / "index.html").read_text(encoding="utf-8")
    html = html.replace('href="/static/style.css"', 'href="style.css"').replace(
        '<script src="/static/app.js"></script>',
        '<script>window.VANTAGE_STATIC = "data/";</script>\n<script src="app.js"></script>')
    html = html.replace('<a href="/api/report" target="_blank" rel="noopener">Audit report (markdown)</a> &middot;',
                        "Static snapshot of the synthetic Acme posture &middot;")
    html = html.replace('<a href="/api/navigator" target="_blank" rel="noopener">Navigator layer</a> &middot;\n'
                        '      <a href="/api/docs" target="_blank" rel="noopener">API docs</a>',
                        '<a href="../">Back to the docs</a>')
    (out / "index.html").write_text(html, encoding="utf-8")
    for f in ("app.js", "style.css"):
        shutil.copy(WEB / f, out / f)
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    print(f"wrote {out} ({sum(1 for _ in out.rglob('*.json'))} JSON files, {size / 1e6:.2f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
