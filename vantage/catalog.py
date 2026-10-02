"""Catalog loading: the offline toy seed catalog, or the real-data catalog built from
ATT&CK STIX + CIS v8 official mapping + SigmaHQ (see vantage.ingest.build)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from . import paths
from .models import Catalog, Control, Detection, LogSource, Mitigation, Technique, ValidationError
from .seed import load_seed_catalog


def catalog_from_dict(d: dict) -> Catalog:
    cat = Catalog(
        techniques={k: Technique(v["id"], v["name"], v["tactic"], v.get("description", ""),
                                 tuple(v.get("tactics", ()))) for k, v in d["techniques"].items()},
        controls={k: Control(v["id"], v.get("framework", ""), v["title"], frozenset(v["mitigates"]),
                             v.get("text", ""), v.get("ig"), v.get("function", ""),
                             frozenset(v.get("baselines", ())))
                  for k, v in d["controls"].items()},
        log_sources={k: LogSource(v["id"], v.get("name", k), float(v.get("cost", 1.0)))
                     for k, v in d["log_sources"].items()},
        detections={k: Detection(v["id"], v["title"], frozenset(v["techniques"]), frozenset(v["requires"]),
                                 float(v.get("cost", 1.0)), v.get("level", ""), v.get("status", ""))
                    for k, v in d["detections"].items()},
        mitigations={k: Mitigation(v["id"], v["name"], v.get("description", ""), frozenset(v["techniques"]))
                     for k, v in d.get("mitigations", {}).items()},
        meta=d.get("meta", {}),
    )
    cat.validate()
    return cat


@lru_cache(maxsize=4)
def _load_json(path: str) -> Catalog:
    with open(path, encoding="utf-8") as fh:
        return catalog_from_dict(json.load(fh))


def load_catalog(which: str | None = None) -> Catalog:
    """which: 'seed' (default, offline toy), 'real' (built catalog, CIS v8 controls), 'nist'
    (built catalog with NIST SP 800-53 rev5 controls), or a path to catalog JSON."""
    if which in (None, "", "seed"):
        return load_seed_catalog()
    path = {"real": paths.catalog_path(), "nist": paths.nist_catalog_path()}.get(which) or Path(which)
    if not path.exists():
        raise ValidationError(f"catalog {path} not found: run `python -m vantage.download` and "
                              "`python -m vantage.ingest.build` (or set VANTAGE_DATA_DIR)")
    return _load_json(str(path))
