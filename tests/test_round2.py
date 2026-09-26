"""NIST 800-53 ingest, rule-quality weighting, bootstrap CIs and the static demo export."""
import json

import pytest

from vantage import automap
from vantage.catalog import load_catalog
from vantage.coverage import compute_coverage, rule_quality
from vantage.ingest.build import nist_controls, with_nist
from vantage.ingest.nist import load_nist, parse_mapping
from vantage.models import Catalog, Detection, LogSource, OrgPosture, Technique
from vantage.selectors import expand_org
from vantage.synth import demo_org

NIST_DOC = {
    "metadata": {"attack_version": "16.1", "mapping_framework": "nist_800_53",
                 "mapping_framework_version": "rev5", "capability_groups": {"AC": "Access Control",
                                                                            "IA": "Identification"}},
    "mapping_objects": [
        {"capability_id": "AC-2", "capability_description": "Account Management", "mapping_type": "mitigates",
         "attack_object_id": "T1078"},
        {"capability_id": "AC-2", "capability_description": "Account Management", "mapping_type": "mitigates",
         "attack_object_id": "T1086"},
        {"capability_id": "IA-2", "capability_description": "Identification and Authentication",
         "mapping_type": "mitigates", "attack_object_id": "T1110"},
        {"capability_id": None, "mapping_type": None, "attack_object_id": "T1496.002", "status": "non_mappable"},
    ],
}


def test_nist_parse_mapping(tmp_path):
    ctrls, meta = parse_mapping(NIST_DOC)
    assert set(ctrls) == {"NIST-AC-2", "NIST-IA-2"}
    assert ctrls["NIST-AC-2"].techniques == {"T1078", "T1086"}
    assert ctrls["NIST-AC-2"].family_name == "Access Control"
    assert meta["skipped_objects"] == 1 and meta["attack_version"] == "16.1"
    p = tmp_path / "n.json"
    p.write_text(json.dumps(NIST_DOC), encoding="utf-8")
    assert set(load_nist(p)[0]) == set(ctrls)


def test_nist_controls_carry_forward(mini_attack):
    ctrls, _ = parse_mapping(NIST_DOC)
    out, stats = nist_controls(ctrls, mini_attack)
    assert "T1059.001" in out["NIST-AC-2"]["mitigates"]  # T1086 revoked -> T1059.001 in the fixture
    assert out["NIST-AC-2"]["framework"].startswith("NIST")
    assert stats.get("carried_forward_revoked", 0) >= 1
    cat = with_nist({"meta": {"x": 1}, "controls": {"CIS-1.1": {}}}, ctrls, {"attack_version": "16.1"}, mini_attack)
    assert set(cat["controls"]) == {"NIST-AC-2", "NIST-IA-2"} and cat["meta"]["nist"]["controls"] == 2


def test_family_selector():
    cat = load_catalog("seed")
    from vantage.models import Control
    cat.controls["NIST-AC-2"] = Control("NIST-AC-2", "NIST", "AC-2", frozenset())
    cat.controls["NIST-IA-2"] = Control("NIST-IA-2", "NIST", "IA-2", frozenset())
    org = expand_org(cat, OrgPosture("x", {"@family:ac"}, set(), set()))
    assert org.claimed_controls == {"NIST-AC-2"}
    org = expand_org(cat, OrgPosture("x", {"NIST-*"}, set(), set()))
    assert org.claimed_controls == {"NIST-AC-2", "NIST-IA-2"}


def _one_technique_cat(rules):
    return Catalog({"T1001": Technique("T1001", "x", "c2")}, {}, {"ls": LogSource("ls", "ls")},
                   {d.id: d for d in rules})


def test_rule_quality_and_weighted_coverage():
    hi = Detection("a", "a", frozenset({"T1001"}), frozenset({"ls"}), level="critical", status="stable")
    lo = Detection("b", "b", frozenset({"T1001"}), frozenset({"ls"}), level="low", status="experimental")
    assert rule_quality(hi) == 1.0 and rule_quality(lo) == pytest.approx(0.3)
    assert rule_quality(Detection("c", "c", frozenset(), frozenset({"ls"}))) == pytest.approx(0.56)
    cat = _one_technique_cat([lo])
    from vantage.models import Control
    cat.controls["C"] = Control("C", "f", "C", frozenset({"T1001"}))
    cov = compute_coverage(cat, OrgPosture("o", {"C"}, {"ls"}, {"b"}))
    assert cov.true_pct == 100.0 and cov.weighted_true_pct == pytest.approx(30.0)
    # noisy-OR: two weak rules beat one
    cat.detections["b2"] = Detection("b2", "b2", frozenset({"T1001"}), frozenset({"ls"}), level="low",
                                     status="experimental")
    cov = compute_coverage(cat, OrgPosture("o", {"C"}, {"ls"}, {"b", "b2"}))
    assert cov.weighted_true_pct == pytest.approx(100 * (1 - 0.7 * 0.7))
    assert cov.summary()["weighted_true_pct"] == 51.0


def test_weighted_never_exceeds_true_on_seed():
    cat = load_catalog("seed")
    cov = compute_coverage(cat, demo_org())
    assert 0 < cov.weighted_true_pct <= cov.true_pct


def test_bootstrap_ci_and_evaluate_ci():
    lo, hi = automap.bootstrap_ci([0.0, 1.0] * 50)
    assert 0.35 < lo < 0.5 < hi < 0.65
    assert automap.bootstrap_ci([]) == (0.0, 0.0)
    assert automap.bootstrap_ci([0.2] * 10) == (pytest.approx(0.2), pytest.approx(0.2))
    cat = load_catalog("seed")
    r = automap.evaluate_mapper(automap.TfidfMapper(cat), cat, (5,), ci=True)
    assert r["MAP@200_ci"][0] <= r["MAP@200"] <= r["MAP@200_ci"][1]
    assert set(automap.per_control_scores(automap.TfidfMapper(cat), cat, (5,))) == {"P@5", "R@5", "MAP@200"}


def test_export_static_demo(tmp_path, monkeypatch):
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    out = tmp_path / "demo"
    subprocess.run([sys.executable, str(root / "scripts" / "export_demo.py"), "--catalog", "seed", "--out", str(out)],
                   check=True, capture_output=True)
    html = (out / "index.html").read_text(encoding="utf-8")
    assert 'window.VANTAGE_STATIC = "data/"' in html and "/static/" not in html
    cov = json.loads((out / "data" / "coverage.json").read_text(encoding="utf-8"))
    first = cov["matrix"][0]["techniques"][0]["id"]
    assert (out / "data" / "technique" / f"{first}.json").exists()
    for f in ("meta", "failure", "recommend"):
        assert (out / "data" / f"{f}.json").exists()
