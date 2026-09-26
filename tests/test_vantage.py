import copy

import pytest

from vantage import automap
from vantage.cli import main
from vantage.coverage import compute_coverage, live_detections
from vantage.failure import rank_spofs, simulate_failure
from vantage.graph import build_graph, techniques_reachable_from, to_cypher, to_json
from vantage.io import load_org, org_from_dict, org_to_dict, save_org
from vantage.models import CoverageStatus, Detection, OrgPosture, Segment, Technique, ValidationError, ZeroTrustFacts
from vantage.recommend import recommend
from vantage.report import audit_report
from vantage.seed import load_seed_catalog
from vantage.synth import demo_org, random_org
from vantage.zerotrust import score_zero_trust


@pytest.fixture
def cat():
    return load_seed_catalog()


@pytest.fixture
def org():
    return demo_org()


def empty_org(**kw):
    base = dict(name="x", claimed_controls=set(), ingested_log_sources=set(), deployed_detections=set())
    base.update(kw)
    return OrgPosture(**base)


# ---- contracts -------------------------------------------------------------
def test_technique_id_validation():
    with pytest.raises(ValidationError):
        Technique("T12", "bad", "execution")
    Technique("T1059.001", "ok", "execution")


def test_detection_requires_log_source():
    with pytest.raises(ValidationError):
        Detection("d", "t", frozenset({"T1059"}), frozenset())


def test_seed_catalog_valid(cat):
    assert len(cat.techniques) >= 30
    cat.validate()


def test_validate_org_rejects_unknown(cat):
    with pytest.raises(ValidationError):
        cat.validate_org(empty_org(claimed_controls={"CIS-99.9"}))


def test_zt_validation():
    zt = ZeroTrustFacts(segments=[Segment("a")], open_flows={frozenset({"a", "b"})})
    with pytest.raises(ValidationError):
        zt.validate()
    with pytest.raises(ValidationError):
        ZeroTrustFacts(privileged_accounts=1, pam_vaulted=2).validate()


# ---- coverage --------------------------------------------------------------
def test_detection_dead_without_log_source(cat):
    assert live_detections(cat, {"sig_schtask"}, set()) == set()
    assert live_detections(cat, {"sig_schtask"}, {"win_security"}) == {"sig_schtask"}


def test_coverage_four_states(cat):
    org = empty_org(claimed_controls={"CIS-9.7"}, ingested_log_sources={"proxy", "dns"},
                    deployed_detections={"sig_dns_tunnel"})
    cov = compute_coverage(cat, org)
    assert cov.status["T1566.001"] == CoverageStatus.PAPER_ONLY
    assert cov.status["T1071.004"] == CoverageStatus.DETECTED_ONLY
    assert cov.status["T1190"] == CoverageStatus.BLIND
    org.claimed_controls.add("CIS-9.2")
    assert compute_coverage(cat, org).status["T1071.004"] == CoverageStatus.DEFENDED


def test_demo_compliant_but_blind(cat, org):
    cov = compute_coverage(cat, org)
    assert cov.claimed_pct > cov.true_pct + 30
    assert "sig_schtask" in cov.dead_detections
    assert cov.status["T1053.005"] == CoverageStatus.PAPER_ONLY
    s = cov.summary()
    assert sum(s[st.value] for st in CoverageStatus) == s["techniques"]


# ---- failure propagation ---------------------------------------------------
def test_edr_is_top_spof(cat, org):
    top = rank_spofs(cat, org, top=1)[0]
    assert (top.kind, top.node) == ("log_source", "edr")
    assert "T1486" in top.techniques_gone_dark


def test_redundant_detection_is_not_spof(cat):
    org = empty_org(ingested_log_sources={"sysmon", "edr"},
                    deployed_detections={"sig_lsass_access", "sig_edr_cred"})
    assert simulate_failure(cat, org, "detection", "sig_lsass_access").techniques_gone_dark == ()


def test_failure_bad_kind(cat, org):
    with pytest.raises(ValueError):
        simulate_failure(cat, org, "nope", "x")


# ---- recommender -----------------------------------------------------------
def test_recommend_top_is_best_ratio(cat, org):
    plan = recommend(cat, org)
    assert plan[0].target == "win_security"
    assert len(plan[0].new_techniques) == 8
    ratios = [r.ratio for r in plan]
    assert ratios[0] == max(ratios)


def test_recommend_never_repeats_and_improves(cat, org):
    plan = recommend(cat, org, max_steps=20)
    covered = set()
    for r in plan:
        assert not covered & set(r.new_techniques)
        covered |= set(r.new_techniques)


def test_recommend_budget(cat, org):
    plan = recommend(cat, org, budget=2)
    assert sum(r.cost for r in plan) <= 2


# ---- zero trust ------------------------------------------------------------
def test_microsegmentation_raises_score(cat, org):
    before = score_zero_trust(org.zero_trust, cat)
    zt = copy.deepcopy(org.zero_trust)
    zt.open_flows = {frozenset({"hr", "general"})}
    after = score_zero_trust(zt, cat)
    assert after.score > before.score
    assert before.exposed_lateral_techniques and not after.exposed_lateral_techniques


def test_perfect_zt_is_100():
    zt = ZeroTrustFacts(segments=[Segment("a", 3), Segment("b")], mfa_coverage=1.0,
                        privileged_accounts=2, pam_vaulted=2, device_posture_checks=True,
                        stale_accounts=0, total_accounts=10)
    assert score_zero_trust(zt).score == 100.0


# ---- automap ---------------------------------------------------------------
def test_automap_ranks_obvious(cat):
    top = automap.TfidfMapper(cat).rank("dump credentials from lsass", 1)
    assert top[0][0] == "T1003.001"


def test_automap_eval_beats_floor(cat):
    ev = automap.evaluate(cat, k=5)
    assert ev["recall"] >= 0.5 and ev["precision"] >= 0.4


# ---- graph / io / synth / report / cli -------------------------------------
def test_graph_reachability_matches_catalog(cat, org):
    g = build_graph(cat, org)
    assert techniques_reachable_from(g, "sysmon") >= {"T1059.001", "T1547.001"}
    assert g.nodes["T1053.005"]["status"] == "paper_only"
    import json
    assert len(json.loads(to_json(g))["nodes"]) == g.number_of_nodes()
    cy = to_cypher(g)
    assert "MERGE (n:Technique" in cy and "DETECTS" in cy


def test_yaml_roundtrip(tmp_path, org):
    p = tmp_path / "org.yaml"
    save_org(org, p)
    back = load_org(p)
    assert org_to_dict(back) == org_to_dict(org)


def test_org_from_dict_rejects_garbage():
    with pytest.raises(ValidationError):
        org_from_dict(["not", "a", "mapping"])


@pytest.mark.parametrize("seed", range(5))
def test_random_org_valid_and_deterministic(cat, seed):
    a, b = random_org(cat, seed, 0.5), random_org(cat, seed, 0.5)
    cat.validate_org(a)
    assert org_to_dict(a) == org_to_dict(b)


def test_maturity_increases_true_coverage(cat):
    lo = sum(compute_coverage(cat, random_org(cat, s, 0.1)).true_pct for s in range(20))
    hi = sum(compute_coverage(cat, random_org(cat, s, 0.9)).true_pct for s in range(20))
    assert hi > lo


def test_report_contains_sections(cat, org):
    text = audit_report(cat, org)
    for h in ("Compliant but undetectable", "Single points of failure", "Recommended next actions"):
        assert h in text
    assert "T1053.005" in text


@pytest.mark.parametrize("argv", [["demo"], ["coverage"], ["failure"], ["recommend"], ["zt"],
                                  ["report"], ["graph", "--format", "cypher"],
                                  ["automap", "--eval"], ["automap", "patch web apps"]])
def test_cli_commands(argv, capsys):
    assert main(argv) == 0
    assert capsys.readouterr().out


def test_cli_synth_then_load(tmp_path, capsys):
    p = tmp_path / "o.yaml"
    assert main(["synth", "--out", str(p), "--seed", "3"]) == 0
    assert main(["coverage", "--org", str(p)]) == 0
