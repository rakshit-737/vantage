"""Write a tiny 'real-format' catalog JSON built from the committed test fixtures (CI smoke tests
of the real-catalog code path without downloading any dataset).

    python scripts/fixture_catalog.py /tmp/vd/processed/catalog.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests.conftest import CIS_ROWS, FIX  # noqa: E402
from vantage.ingest.attack import load_attack  # noqa: E402
from vantage.ingest.build import build_catalog  # noqa: E402
from vantage.ingest.cis import parse_rows  # noqa: E402
from vantage.ingest.sigma import load_rules  # noqa: E402

if __name__ == "__main__":
    out = Path(sys.argv[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    d = build_catalog(load_attack(FIX / "mini-attack.json"), parse_rows(CIS_ROWS), load_rules(FIX / "sigma"))
    out.write_text(json.dumps(d), encoding="utf-8")
    print(f"wrote {out}")
