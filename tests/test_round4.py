"""Control-failure SPOFs, CLI error handling and packaged posture files."""
from __future__ import annotations

import pytest

from vantage import cli, paths
from vantage.failure import rank_control_spofs, simulate_failure
from vantage.seed import load_seed_catalog
from vantage.synth import demo_org, random_org


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_control_spofs_match_brute_force(seed):
    cat = load_seed_catalog()
    org = demo_org() if seed == 0 else random_org(cat, seed, 0.6)
    fast = {i.node: set(i.techniques_gone_dark) for i in rank_control_spofs(cat, org)}
    for c in org.claimed_controls:
        brute = set(simulate_failure(cat, org, "control", c).techniques_gone_dark)
        assert fast.get(c, set()) == brute


def test_cli_version_and_errors(capsys, tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0 and "vantage" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["automap"])
    monkeypatch.setenv("VANTAGE_DATA_DIR", str(tmp_path))
    assert cli.main(["coverage", "--catalog", "real"]) == 2
    assert "python -m vantage.download" in capsys.readouterr().err
    assert cli.main(["failure", "--kind", "control", "--top", "2"]) == 0


def test_posture_files_ship_inside_package():
    assert cli.REAL_DEMO_ORG.exists() and cli.NIST_DEMO_ORG.exists()
    assert "postures" in cli.REAL_DEMO_ORG.parts


def test_data_dir_default_outside_checkout(monkeypatch, tmp_path):
    monkeypatch.delenv("VANTAGE_DATA_DIR", raising=False)
    monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)          # no pyproject.toml -> installed wheel
    assert paths.data_dir().parts[-2:] == (".vantage", "data")


def test_cypher_literals_are_typed():
    from vantage.graph import build_graph, to_cypher
    cy = to_cypher(build_graph(load_seed_catalog(), demo_org()))
    assert "n.claimed = true" in cy and 'n.claimed = "True"' not in cy
    assert "CREATE CONSTRAINT technique_id IF NOT EXISTS" in cy
    assert "MATCH (a:Detection {id:" in cy


def test_fixture_catalog_script(tmp_path, monkeypatch):
    import subprocess
    import sys
    out = tmp_path / "processed" / "catalog.json"
    subprocess.run([sys.executable, str(paths.REPO_ROOT / "scripts" / "fixture_catalog.py"), str(out)], check=True)
    monkeypatch.setenv("VANTAGE_DATA_DIR", str(tmp_path))
    org = str(paths.REPO_ROOT / "tests" / "fixtures" / "mini-org.yaml")
    assert cli.main(["coverage", "--catalog", "real", "--org", org]) == 0


def test_baseline_selector(mini_cat):
    import dataclasses

    from vantage.models import OrgPosture
    from vantage.selectors import expand_org
    ids = sorted(mini_cat.controls)
    mini_cat.controls[ids[0]] = dataclasses.replace(mini_cat.controls[ids[0]], baselines=frozenset({"LOW",
                                                                                                    "MODERATE"}))
    mini_cat.controls[ids[1]] = dataclasses.replace(mini_cat.controls[ids[1]], baselines=frozenset({"MODERATE"}))
    low = expand_org(mini_cat, OrgPosture("x", {"@baseline:LOW"}, set(), set()))
    mod = expand_org(mini_cat, OrgPosture("x", {"@baseline:moderate"}, set(), set()))
    assert low.claimed_controls == {ids[0]} and mod.claimed_controls == {ids[0], ids[1]}
