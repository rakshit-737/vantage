"""Round-3 modules: CTID / OSCAL parsers, framework registry, cross-framework transfer mapper."""
from __future__ import annotations

import json
import shutil

import pytest

from vantage import automap, frameworks, paths
from vantage.ingest.ctid import load_ctid, parse_ctid
from vantage.ingest.oscal import load_catalog_with_baselines, norm_id, parse_catalog, parse_profile
from vantage.models import Control
from vantage.transfer import PriorTransferBaseline, TransferMapper, average_precision

from .conftest import FIX

CT = FIX / "ctid"


# -- CTID ------------------------------------------------------------------------------------------
def test_parse_ctid_skips_non_mappable_and_drops_comments():
    caps, meta = load_ctid(CT / "mini-ctid.json")
    assert set(caps) == {"AC-02", "AC-03", "EDR"}          # AC-04 is non_mappable only
    assert caps["AC-02"].techniques == {"T1003.001", "T1086"}  # ids upper-cased
    assert caps["AC-02"].group_name == "Access Control"
    assert caps["EDR"].scores == {"T1059.001": "significant"} and caps["EDR"].categories == {"detect"}
    assert meta["attack_version"] == "16.1" and meta["skipped_objects"] == {"type_non_mappable": 1}
    # label-leak guard: the per-pair comments never reach any text field
    assert all("LEAK" not in (c.name + c.group_name) for c in caps.values())


def test_parse_ctid_ignores_incomplete_objects():
    caps, meta = parse_ctid({"mapping_objects": [{"capability_id": "X", "mapping_type": "mitigates"}]})
    assert caps == {} and meta["skipped_objects"] == {"no_capability_or_technique": 1}


# -- OSCAL -----------------------------------------------------------------------------------------
def test_norm_id():
    assert norm_id("ac-2") == "AC-02"
    assert norm_id("ac-2.1") == "AC-02(01)"
    assert norm_id(" SI-4.12 ") == "SI-04(12)"


def test_parse_catalog_params_enhancements_withdrawn():
    cat = parse_catalog(json.loads((CT / "mini-catalog.json").read_text()))
    assert set(cat) == {"AC-02", "AC-02(01)", "AC-03", "AC-13"}
    assert "[prerequisites and criteria]" in cat["AC-02"].statement   # param substituted
    assert "{{" not in cat["AC-02"].statement
    assert cat["AC-02"].family == "AC" and cat["AC-02"].family_name == "Access Control"
    assert cat["AC-02"].guidance == "Accounts are managed."
    assert cat["AC-13"].withdrawn and not cat["AC-03"].withdrawn


def test_profiles_and_baselines():
    assert parse_profile(json.loads((CT / "LOW.json").read_text())) == {"AC-02"}
    cat = load_catalog_with_baselines(CT / "mini-catalog.json", {"LOW": CT / "LOW.json",
                                                                 "MODERATE": CT / "MODERATE.json"})
    assert cat["AC-02"].baselines == {"LOW", "MODERATE"}
    assert cat["AC-02(01)"].baselines == {"MODERATE"} and cat["AC-13"].baselines == set()


# -- framework registry (fixture data dir) -----------------------------------------------------------
@pytest.fixture
def fixture_data_dir(tmp_path, monkeypatch):
    shutil.copy(CT / "mini-ctid.json", tmp_path / paths.NIST_FILE)
    d = tmp_path / paths.CTID_DIR
    d.mkdir()
    shutil.copy(CT / "mini-catalog.json", d / paths.OSCAL_CATALOG)
    for b, f in paths.OSCAL_BASELINES.items():
        src = CT / ("LOW.json" if b == "LOW" else "MODERATE.json")
        shutil.copy(src, d / f)
    shutil.copy(CT / "mini-ctid.json", d / paths.CTID_FRAMEWORKS["AWS"][0])
    monkeypatch.setenv("VANTAGE_DATA_DIR", str(tmp_path))
    return tmp_path


def test_nist_framework_carries_forward_and_uses_statement(fixture_data_dir, mini_attack):
    fw = frameworks.nist_framework(mini_attack)
    ac2, ac3 = fw.controls["NIST:AC-02"], fw.controls["NIST:AC-03"]
    assert ac2.mitigates == {"T1003.001", "T1059.001"}     # T1086 revoked-by T1059.001
    assert ac3.mitigates == {"T1021.002"}                   # T1064 is deprecated -> dropped
    assert fw.stats["carried_forward_revoked"] == 1 and fw.stats["dropped_deprecated_or_unknown"] == 1
    assert "prerequisites and criteria" in ac2.text and "LEAK" not in ac2.text
    title = frameworks.nist_framework(mini_attack, text="title").controls["NIST:AC-02"]
    assert "prerequisites" not in title.text


def test_baseline_techniques_moderate_superset_of_low(fixture_data_dir, mini_attack):
    fw = frameworks.nist_framework(mini_attack)
    base = frameworks.baseline_techniques(fw, frameworks.load_oscal())
    assert base["LOW"] == {"T1003.001", "T1059.001"}
    assert base["MODERATE"] >= base["LOW"] and "T1021.002" in base["MODERATE"]


def test_ctid_framework_and_cis_stats(fixture_data_dir, mini_attack, mini_cat):
    aws = frameworks.ctid_framework("AWS", mini_attack)
    assert aws.controls["AWS:EDR"].mitigates == {"T1059.001"} and aws.source_attack == "16.1"
    cis = frameworks.cis_framework(mini_cat.controls, {"carried_forward_revoked": 3})
    assert cis.stats["carried_forward_revoked"] == 3 and all(k.startswith("CIS:") for k in cis.controls)
    assert frameworks.source_universe(None, mini_attack) == frozenset(mini_attack.techniques)


# -- transfer --------------------------------------------------------------------------------------
def test_average_precision_hand_computed():
    # hits at ranks 1 and 3 of gold size 2: (1/1 + 2/3) / 2
    assert average_precision(["a", "x", "b"], {"a", "b"}) == pytest.approx((1 + 2 / 3) / 2)
    assert average_precision(["x"], set()) == 0.0
    assert average_precision(["x", "a"], {"a"}, depth=1) == 0.0


def test_paired_bootstrap_ci():
    m, lo, hi = automap.paired_bootstrap_ci([1.0, 1.0, 1.0], [0.0, 0.0, 0.0])
    assert m == lo == hi == 1.0
    with pytest.raises(ValueError):
        automap.paired_bootstrap_ci([1.0], [])


def _train(mini_cat):
    return [Control("A", "X", "Allowlist scripts", frozenset({"T1059.001"}), "powershell scripts"),
            Control("B", "X", "Protect credentials", frozenset({"T1003.001"}), "lsass credential dumping"),
            Control("C", "X", "Segment network", frozenset({"T1021.002", "T1003.001"}), "smb lateral")]


def test_transfer_mapper_leave_one_out_excludes_query(mini_cat):
    train = _train(mini_cat)
    tm = TransferMapper(mini_cat, train, beta=1.0, gamma=1.0)
    # T1059.001 is mapped only by control A: with A held out, kNN and prior give it nothing,
    # so its score is the bridge score alone.
    a = train[0]
    ex = dict(zip(tm.ids, tm.scores(automap.control_text(a), exclude=a), strict=True))
    bridge = dict(zip(tm.ids, tm._bridge(automap.control_text(a)), strict=True))
    assert ex["T1059.001"] == pytest.approx(bridge["T1059.001"])
    full = dict(zip(tm.ids, tm.scores(automap.control_text(a)), strict=True))
    assert full["T1059.001"] > ex["T1059.001"]
    assert [t for t, _ in tm.rank_for(a, 3)] == [t for t, _ in automap._top(tm.ids, ex.values(), 3)]


def test_transfer_mapper_fit_universe_and_nested(mini_cat):
    tm = TransferMapper(mini_cat, _train(mini_cat), universe=frozenset({"T1059.001", "T1003.001"}))
    assert set(tm.ids) == {"T1059.001", "T1003.001"}
    assert tm.beta is not None and 0 <= tm.fit_map <= 1
    nested = tm.nested_loo_aps()
    assert set(nested) == {"A", "B", "C"} and all(0 <= v <= 1 for v in nested.values())
    # nested LOO can never beat the tuned LOO it is derived from on average
    assert sum(nested.values()) / 3 <= tm.fit_map + 1e-9
    with pytest.raises(ValueError):
        TransferMapper(mini_cat, [Control("Z", "X", "t", frozenset({"T9999"}))])


def test_prior_baseline_is_leave_one_out(mini_cat):
    train = _train(mini_cat)
    pb = PriorTransferBaseline(train, "X")
    assert "T1059.001" not in [t for t, _ in pb.rank_for(train[0], 10)]
    assert pb.rank("anything", 1)[0][0] == "T1003.001"


# -- real data invariants ----------------------------------------------------------------------------
@pytest.mark.realdata
def test_crossframework_headline_invariants():
    d = paths.data_dir()
    if not (d / paths.CTID_DIR / paths.OSCAL_CATALOG).exists() or not paths.have_real_data():
        pytest.skip("cross-framework data not downloaded")
    from vantage.catalog import load_catalog
    from vantage.ingest.attack import load_attack
    attack = load_attack(d / paths.ATTACK_FILE, paths.ATTACK_VERSION)
    cat = load_catalog("real")
    fws = frameworks.all_frameworks(attack, cat.controls, cis_stats=cat.meta.get("cis"))
    assert len(fws) == 8
    assert fws["CIS v8"].stats["carried_forward_revoked"] == 134
    base = frameworks.baseline_techniques(fws["NIST 800-53"], frameworks.load_oscal())
    assert base["LOW"] <= base["MODERATE"] <= base["HIGH"]
    assert len(base["MODERATE"]) == len(fws["NIST 800-53"].techniques) == 466
