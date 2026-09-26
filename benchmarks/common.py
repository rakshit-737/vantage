"""Shared helpers for the benchmark scripts (run from the repo root)."""
from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vantage import paths  # noqa: E402
from vantage.models import Catalog, Control, Mitigation, Technique  # noqa: E402

RESULTS = ROOT / "results"
FIGS = ROOT / "docs" / "figures"


def need(*names: str) -> Path:
    d = paths.data_dir()
    missing = [n for n in names if not (d / n).exists()]
    if missing:
        raise SystemExit(f"missing {missing} in {d}: run scripts/download_data.py")
    return d


def eval_catalog_v82() -> Catalog:
    """ATT&CK v8.2 techniques + mitigations with the *unmodified* official CIS v8 labels.

    This is the apples-to-apples setting: the CIS mapping was authored against v8.2."""
    from vantage.ingest.attack import load_attack
    from vantage.ingest.cis import load_cis
    d = need(paths.ATTACK_CIS_FILE, paths.CIS_FILE)
    a = load_attack(d / paths.ATTACK_CIS_FILE, paths.ATTACK_CIS_VERSION)
    sg = load_cis(d / paths.CIS_FILE)
    techs = {t: Technique(t, v["full_name"], (v["tactics"] or ["unknown"])[0], v["description"],
                          tuple(v["tactics"])) for t, v in a.techniques.items()}
    unknown = sum(1 for s in sg.values() for t in s.techniques if t not in techs)
    ctrls = {s.id: Control(s.id, "CIS v8", s.title, frozenset(t for t in s.techniques if t in techs),
                           s.description, s.ig, s.function) for s in sg.values()}
    mits = {m: Mitigation(m, v["name"], v["description"], frozenset(v["techniques"]))
            for m, v in a.mitigations.items()}
    return Catalog(techs, ctrls, {}, {}, mits, {"attack_version": "8.2", "labels_not_in_bundle": unknown})


def write_result(name: str, payload: dict) -> Path:
    RESULTS.mkdir(exist_ok=True)
    payload = {"generated": time.strftime("%Y-%m-%d"), "python": platform.python_version(),
               "platform": platform.platform(terse=True), **payload}
    p = RESULTS / f"{name}.json"
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def md_table(rows: list[dict], cols: list[str]) -> str:
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    return "\n".join(out)
