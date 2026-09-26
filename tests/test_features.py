import json

import pytest

from vantage import automap
from vantage.cli import main
from vantage.coverage import compute_coverage
from vantage.failure import rank_spofs, simulate_failure
from vantage.navigator import to_layer
from vantage.recommend import recommend
from vantage.report import audit_report, heatmap, tactic_table
from vantage.seed import load_seed_catalog
from vantage.synth import demo_org, random_org


@pytest.fixture
def cat():
    return load_seed_catalog()


@pytest.mark.parametrize("seed", range(6))
def test_fast_spof_ranking_matches_brute_force(cat, seed):
    org = random_org(cat, seed, 0.6)
    fast = {(i.kind, i.node): i.techniques_gone_dark for i in rank_spofs(cat, org)}
    brute = {}
    for ls in org.ingested_log_sources:
        i = simulate_failure(cat, org, "log_source", ls)
        if i.techniques_gone_dark:
            brute[("log_source", ls)] = i.techniques_gone_dark
    for d in org.deployed_detections:
        i = simulate_failure(cat, org, "detection", d)
        if i.techniques_gone_dark:
            brute[("detection", d)] = i.techniques_gone_dark
    assert fast == brute


def test_recommend_action_filter(cat):
    plan = recommend(cat, demo_org(), max_steps=10, actions=("onboard_log_source",))
    assert plan and all(r.action == "onboard_log_source" for r in plan)
    plan = recommend(cat, demo_org(), max_steps=10, actions=("deploy_detection",))
    assert all(r.action == "deploy_detection" for r in plan)


def test_navigator_layer(cat):
    org = demo_org()
    layer = to_layer(cat, compute_coverage(cat, org))
    assert layer["domain"] == "enterprise-attack"
    t = {x["techniqueID"]: x for x in layer["techniques"]}
    assert t["T1053.005"]["score"] == 1 and "paper_only" in t["T1053.005"]["comment"]


def test_tactic_table_counts(cat):
    cov = compute_coverage(cat, demo_org())
    rows = tactic_table(cat, cov)
    assert sum(r["total"] for r in rows) == len(cat.techniques)
    assert "tactic" in heatmap(cat, cov, max_cells=10)  # compact per-tactic view


def test_pdf_export(tmp_path, cat):
    pytest.importorskip("reportlab")
    from vantage.pdf import markdown_to_pdf
    p = tmp_path / "r.pdf"
    markdown_to_pdf(audit_report(cat, demo_org()), str(p))
    assert p.read_bytes()[:4] == b"%PDF" and p.stat().st_size > 2000


def test_bridge_mapper_and_eval(mini_cat):
    m = automap.MitigationBridgeMapper(mini_cat, "tfidf")
    top = m.rank("protect credentials in lsass with strong password policies", 3)
    assert top[0][0] == "T1003.001"
    ev = automap.evaluate_mapper(m, mini_cat, ks=(1, 2), depth=10)
    assert ev["controls"] == 3 and 0 <= ev["P@1"] <= 1 and ev["MAP@10"] > 0.5


def test_bridge_requires_mitigations(cat):
    with pytest.raises(ValueError):
        automap.MitigationBridgeMapper(cat)


def test_baselines(mini_cat):
    pop = automap.PopularityBaseline(mini_cat)
    c = mini_cat.controls["CIS-5.2"]
    assert "T1003.001" not in [t for t, _ in pop.rank_for(c, 10)]  # leave-one-out
    rnd = automap.RandomBaseline(mini_cat)
    assert rnd.rank("x", 3) == rnd.rank("x", 3) and len(rnd.rank("x", 3)) == 3
    ev = automap.evaluate_mapper(pop, mini_cat, ks=(1,), depth=5)
    assert ev["mapper"] == "baseline-popularity"


@pytest.mark.parametrize("argv", [["navigator"], ["recommend", "--log-sources-only"],
                                  ["automap", "--method", "tfidf", "rdp lateral movement"]])
def test_cli_new_commands(argv, capsys):
    assert main(argv) == 0
    assert capsys.readouterr().out


def test_cli_report_pdf_and_navigator_file(tmp_path, capsys):
    pytest.importorskip("reportlab")
    pdf, nav = tmp_path / "r.pdf", tmp_path / "l.json"
    assert main(["report", "--pdf", str(pdf)]) == 0
    assert main(["navigator", "--out", str(nav)]) == 0
    assert pdf.exists() and json.loads(nav.read_text())["techniques"]


def test_cli_with_catalog_path(tmp_path, mini_dict, capsys):
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps(mini_dict))
    org = tmp_path / "org.yaml"
    org.write_text("name: mini\nclaimed_controls: ['@ig2']\ningested_log_sources: ['windows/security']\n"
                   "deployed_detections: ['@all']\n")
    assert main(["demo", "--catalog", str(p), "--org", str(org)]) == 0
    out = capsys.readouterr().out
    assert "Compliant but blind" in out
