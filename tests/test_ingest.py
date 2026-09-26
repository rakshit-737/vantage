import json
import zipfile

import pytest

from vantage.catalog import load_catalog
from vantage.coverage import compute_coverage
from vantage.ingest.attack import clean_text
from vantage.ingest.cis import parse_rows
from vantage.ingest.sigma import load_rules, logsource_cost, logsource_id, parse_rule
from vantage.models import CoverageStatus, OrgPosture, ValidationError
from vantage.selectors import expand_org

from .conftest import CIS_ROWS, FIX

PS, SCHT, LSASS = (f"00000000-0000-0000-0000-00000000000{i}" for i in (1, 2, 3))


# ---- ATT&CK STIX -----------------------------------------------------------
def test_attack_parses_active_techniques(mini_attack):
    a = mini_attack
    assert a.version == "99.0"
    assert a.tactic_order == ["execution", "persistence", "credential-access", "lateral-movement"]
    assert "T1086" not in a.techniques and "T1064" not in a.techniques
    assert a.techniques["T1053.005"]["tactics"] == ["execution", "persistence"]
    assert a.techniques["T1059.001"]["full_name"] == "Command and Scripting Interpreter: PowerShell"


def test_attack_revoked_and_deprecated_resolution(mini_attack):
    assert mini_attack.resolve("T1086") == "T1059.001"
    assert mini_attack.resolve("t1059") == "T1059"
    assert mini_attack.resolve("T1064") is None
    assert "T1064" in mini_attack.deprecated


def test_attack_mitigations(mini_attack):
    assert mini_attack.mitigations["M1042"]["techniques"] == {"T1059", "T1059.001"}


def test_clean_text_strips_citations_and_links():
    assert clean_text("Use [PowerShell](https://x) now. (Citation: Foo 2020)") == "Use PowerShell now."


# ---- CIS -------------------------------------------------------------------
def test_cis_parse_rows():
    sg = parse_rows(CIS_ROWS)
    assert set(sg) == {"CIS-2.7", "CIS-5.2", "CIS-12.2", "CIS-8.2"}
    assert sg["CIS-2.7"].techniques == {"T1086", "T1059"} and sg["CIS-2.7"].ig == 3
    assert sg["CIS-5.2"].ig == 1
    assert sg["CIS-8.2"].techniques == set()  # "N" rows are not mappings


def test_cis_xlsx_roundtrip(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    from vantage.ingest.cis import SHEET, load_cis
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = SHEET
    for r in CIS_ROWS:
        ws.append(r)
    p = tmp_path / "cis.xlsx"
    wb.save(p)
    assert load_cis(p)["CIS-12.2"].techniques == {"T1021.002", "T1064"}


# ---- Sigma -----------------------------------------------------------------
def test_sigma_logsource_id_and_cost():
    assert logsource_id({"product": "Windows", "category": "process_creation"}) == "windows/process_creation"
    assert logsource_id({"category": "proxy"}) == "proxy"
    assert logsource_id(None) == "unknown"
    assert logsource_cost("windows/security") == 1.0
    assert logsource_cost("windows/process_creation") == 1.5
    assert logsource_cost("linux/auditd") == 2.0


def test_sigma_parse_rule_tags():
    r = parse_rule({"title": "x", "logsource": {"product": "aws", "service": "cloudtrail"},
                    "tags": ["attack.t1078", "attack.T1098.001", "attack.persistence", "cve.2021-1"]})
    assert r.techniques == ("T1078", "T1098.001") and r.logsource == "aws/cloudtrail"
    assert parse_rule({"title": "no logsource"}) is None


def test_sigma_load_dir_filters_status():
    rules = load_rules(FIX / "sigma")
    assert {r.id for r in rules} == {PS, SCHT, LSASS, "00000000-0000-0000-0000-000000000004"}


def test_sigma_load_zip_skips_deprecated_folder(tmp_path):
    z = tmp_path / "rules.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for p in (FIX / "sigma").glob("*.yml"):
            zf.write(p, f"rules/windows/{p.name}")
        zf.write(FIX / "sigma" / "schtask.yml", "deprecated/windows/old.yml")
        zf.writestr("rules/broken.yml", "title: [unclosed")
    assert len(load_rules(z)) == 4


# ---- build + catalog -------------------------------------------------------
def test_build_catalog_forwards_revoked_and_drops_deprecated(mini_dict):
    m = mini_dict["meta"]
    assert m["cis"]["carried_forward_revoked"] == 1
    assert m["cis"]["dropped_deprecated_or_unknown"] == 1
    assert set(mini_dict["controls"]["CIS-2.7"]["mitigates"]) == {"T1059", "T1059.001"}
    assert m["sigma"]["kept"] == 3 and m["sigma"]["skipped_no_attack_tag"] == 1
    assert mini_dict["detections"][LSASS]["techniques"] == ["T1003.001", "T1059.001"]  # T1086 carried forward


def test_catalog_json_roundtrip(tmp_path, mini_dict):
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps(mini_dict))
    cat = load_catalog(str(p))
    assert cat.techniques["T1053.005"].all_tactics == ("execution", "persistence")
    assert cat.controls["CIS-5.2"].ig == 1
    assert cat.mitigations["M1027"].techniques == frozenset({"T1003.001"})


def test_load_catalog_missing_path():
    with pytest.raises(ValidationError):
        load_catalog("does/not/exist.json")


def test_selectors_expand(mini_cat):
    org = OrgPosture("o", {"@ig1"}, {"windows/*"}, {"@status:stable|test&@min-level:medium"})
    expand_org(mini_cat, org)
    assert org.claimed_controls == {"CIS-5.2", "CIS-8.2"}
    assert org.ingested_log_sources == {"windows/process_creation", "windows/security", "windows/process_access"}
    assert org.deployed_detections == {PS, SCHT}
    mini_cat.validate_org(org)


def test_selectors_reject_unknown(mini_cat):
    with pytest.raises(ValidationError):
        expand_org(mini_cat, OrgPosture("o", {"@ig9"}, set(), set()))
    with pytest.raises(ValidationError):
        expand_org(mini_cat, OrgPosture("o", set(), set(), {"@min-level:extreme"}))
    with pytest.raises(ValidationError):
        expand_org(mini_cat, OrgPosture("o", set(), {"@bogus"}, set()))


def test_real_style_coverage(mini_cat):
    org = expand_org(mini_cat, OrgPosture("o", {"@all"}, {"windows/security"}, {"@all"}))
    cov = compute_coverage(mini_cat, org)
    assert cov.status["T1003.001"] == CoverageStatus.PAPER_ONLY  # rule deployed, process_access not ingested
    assert cov.status["T1053.005"] == CoverageStatus.DETECTED_ONLY
    assert cov.dead_detections == {PS, LSASS}
