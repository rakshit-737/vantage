"""Shared helpers for the benchmark scripts (run from the repo root)."""
from __future__ import annotations

import csv
import gzip
import io
import json
import os
import platform
import subprocess  # nosec B404 - fixed git command, no shell
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


def _git_commit() -> tuple[str, bool]:
    """(HEAD sha, working tree has uncommitted changes to tracked code) or ("unknown", False)."""
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,  # nosec B603 B607
                             check=True, timeout=10).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no", "--", "vantage", "benchmarks"],
                               cwd=ROOT, capture_output=True, text=True, check=True,  # nosec B603 B607
                               timeout=10).stdout.strip()
        return sha, bool(dirty)
    except (OSError, subprocess.SubprocessError):
        return "unknown", False


def provenance() -> dict:
    """Where a result was produced: commit, and the GitHub Actions run when there is one."""
    env = os.environ
    if env.get("GITHUB_RUN_ID"):
        run = env["GITHUB_RUN_ID"]
        server = env.get("GITHUB_SERVER_URL", "https://github.com")
        url = f"{server}/{env.get('GITHUB_REPOSITORY', '')}/actions/runs/{run}"
        return {"commit": env.get("GITHUB_SHA", "unknown"), "run_id": run, "run_url": url,
                "workflow": env.get("GITHUB_WORKFLOW", ""), "runner": env.get("ImageOS", env.get("RUNNER_OS", "")),
                "python": platform.python_version(), "platform": platform.platform(terse=True)}
    sha, dirty = _git_commit()
    return {"commit": sha + ("+uncommitted" if dirty else ""), "run_id": "local", "run_url": "",
            "workflow": "", "runner": "local", "python": platform.python_version(),
            "platform": platform.platform(terse=True)}


def provenance_line(prov: dict | None = None) -> str:
    """One-line Markdown footer naming the run that produced a results file."""
    p = prov or provenance()
    where = (f"GitHub Actions `{p['workflow']}` run [{p['run_id']}]({p['run_url']})" if p["run_id"] != "local"
             else "a local run")
    return f"_Source: {where} at commit `{p['commit'][:12]}` ({p['platform']}, Python {p['python']})._"


def write_result(name: str, payload: dict) -> Path:
    RESULTS.mkdir(exist_ok=True)
    payload = {"generated": time.strftime("%Y-%m-%d"), "python": platform.python_version(),
               "platform": platform.platform(terse=True), "provenance": provenance(), **payload}
    p = RESULTS / f"{name}.json"
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def write_md(name: str, lines: list[str]) -> Path:
    """results/<name>.md with the provenance footer appended."""
    RESULTS.mkdir(exist_ok=True)
    p = RESULTS / f"{name}.md"
    p.write_text("\n".join([*lines, "", provenance_line()]) + "\n", encoding="utf-8")
    return p


def write_csv_gz(name: str, header: list[str], rows: list[list]) -> Path:
    """Deterministic gzip CSV (fixed mtime, no file name in the header) under results/."""
    RESULTS.mkdir(exist_ok=True)
    sio = io.StringIO()
    w = csv.writer(sio, lineterminator="\n")
    w.writerow(header)
    w.writerows(rows)
    text = sio.getvalue()
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=9) as gz:
        gz.write(text.encode("utf-8"))
    p = RESULTS / f"{name}.csv.gz"
    p.write_bytes(buf.getvalue())
    return p


def sign_flip_p(diffs: list[float], draws: int = 20_000, seed: int = 0) -> float:
    """Two-sided paired sign-flip permutation p-value for mean(diffs) = 0, as (k + 1) / (draws + 1),
    so it is never 0. Seeded numpy generator: identical on every platform."""
    import numpy as np
    d = np.asarray(diffs, dtype=float)
    if d.size == 0:
        return 1.0
    obs = abs(d.mean())
    rng = np.random.default_rng(seed)
    signs = rng.integers(0, 2, size=(draws, d.size), dtype=np.int8) * 2 - 1
    null = np.abs((signs * d).mean(axis=1))
    k = int((null >= obs - 1e-12).sum())
    return (k + 1) / (draws + 1)


def holm(pvals: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (monotone, capped at 1) for one family of tests."""
    order = sorted(pvals, key=lambda k: (pvals[k], k))
    m, out, run = len(order), {}, 0.0
    for i, k in enumerate(order):
        run = max(run, min(1.0, (m - i) * pvals[k]))
        out[k] = run
    return out


def fmt_p(p: float) -> str:
    """p-value for tables: two significant digits, never printed as 0."""
    return f"{p:.2g}" if p >= 0.001 else f"{p:.1e}"


def md_table(rows: list[dict], cols: list[str]) -> str:
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    return "\n".join(out)
