"""Input validation (posture YAML, selectors, CLI bounds), the streamed-body limit and the
benchmark statistics helpers."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from vantage import cli
from vantage.io import load_org
from vantage.models import OrgPosture, ValidationError
from vantage.selectors import expand_org

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("text, needle", [
    ("name: [\n", "invalid YAML"),
    ("name: x\nclaimed_controls: 5\n", "'claimed_controls' must be a list of strings"),
    ("name: x\nzero_trust: {segments: [finance]}\n", "segments"),
    ("name: x\nzero_trust: [1]\n", "'zero_trust' must be a mapping"),
    ("name: x\nzero_trust: {open_flows: [[a]]}\n", "open_flows"),
    ("name: x\nzero_trust: {mfa_coverage: high}\n", "mfa_coverage"),
    ("- just a list\n", "mapping with a 'name'"),
])
def test_malformed_posture_is_one_clean_error(tmp_path, capsys, text, needle):
    f = tmp_path / "org.yaml"
    f.write_text(text, encoding="utf-8")
    with pytest.raises(ValidationError, match="org.yaml"):
        load_org(f)
    assert cli.main(["coverage", "--org", str(f)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("vantage: error: ") and needle in err and "Traceback" not in err
    assert len(err.strip().splitlines()) == 1


@pytest.mark.parametrize("org", [
    OrgPosture("o", {"@family:ZZ"}, set(), set()),
    OrgPosture("o", {"NIST-QQ-*"}, set(), set()),
    OrgPosture("o", {"@baseline:LOW"}, set(), set()),          # mini catalog has no baselines
    OrgPosture("o", set(), {"nosuch/*"}, set()),
    OrgPosture("o", set(), set(), {"@status:stabel"}),
    OrgPosture("o", set(), set(), {"@logsource:nosuch/*"}),
])
def test_selectors_that_match_nothing_are_errors(mini_cat, org):
    with pytest.raises(ValidationError):
        expand_org(mini_cat, org)


def test_unknown_baseline_name_is_an_error(mini_cat):
    import dataclasses
    cid = sorted(mini_cat.controls)[0]
    mini_cat.controls[cid] = dataclasses.replace(mini_cat.controls[cid], baselines=frozenset({"LOW"}))
    with pytest.raises(ValidationError, match="HUGE"):
        expand_org(mini_cat, OrgPosture("o", {"@baseline:HUGE"}, set(), set()))
    assert expand_org(mini_cat, OrgPosture("o", {"@baseline:low"}, set(), set())).claimed_controls == {cid}


@pytest.mark.parametrize("argv", [["failure", "--top", "-3"], ["failure", "--top", "0"],
                                  ["recommend", "--steps", "0"], ["recommend", "--budget", "-1"],
                                  ["recommend", "--budget", "nan"], ["automap", "-k", "0", "mfa"]])
def test_cli_rejects_non_positive_bounds(argv, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 2
    assert "vantage" in capsys.readouterr().err


def test_demo_hint_names_the_catalog(capsys):
    assert cli.main(["demo"]) == 0
    assert "report --out report.md" in capsys.readouterr().out


def test_streamed_body_over_limit_gets_413():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vantage.api import MAX_BODY, create_app
    c = TestClient(create_app("seed"), base_url="http://127.0.0.1")

    def chunks():
        for _ in range(10):
            yield b"x" * (MAX_BODY // 8)
    r = c.post("/api/coverage", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    ok = c.post("/api/coverage", content=iter([b'{"disable_log_sources": ', b'["edr"]}']),
                headers={"Content-Type": "application/json"})
    assert ok.status_code == 200 and "summary" in ok.json()


def test_sign_flip_and_holm():
    pytest.importorskip("numpy")
    if not (ROOT / "benchmarks" / "common.py").exists():
        pytest.skip("benchmarks/ is not shipped in the sdist")
    sys.path.insert(0, str(ROOT / "benchmarks"))
    try:
        from common import fmt_p, holm, sign_flip_p
    finally:
        sys.path.pop(0)
    p = sign_flip_p([0.2, 0.3, 0.1, 0.25] * 10, draws=2000)
    assert p == pytest.approx(1 / 2001)            # never 0
    assert sign_flip_p([0.1, -0.1] * 10, draws=2000) == 1.0
    adj = holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adj == {"a": 0.03, "c": 0.06, "b": 0.06}
    assert fmt_p(5e-5) == "5.0e-05" and fmt_p(0.0213) == "0.021"


def _requirements() -> dict[str, list]:
    """pyproject requirements by group ('core' + every extra) as packaging Requirement objects."""
    tomllib = pytest.importorskip("tomllib")  # Python 3.11+
    from packaging.requirements import Requirement
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    groups = {"core": data["dependencies"], **data["optional-dependencies"]}
    return {g: [Requirement(r) for r in reqs] for g, reqs in groups.items()}


def _pins(path: Path) -> dict[str, str]:
    """name -> version for every `name==version` requirement line (comments and hashes skipped)."""
    from packaging.utils import canonicalize_name
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "--")) and "==" in line:
            name, ver = line.split(";")[0].split()[0].split("==")
            out[canonicalize_name(name)] = ver
    return out


def test_min_constraints_cover_every_floor():
    """scripts/min_constraints.py (audited by pip-audit in CI) pins the floor of every requirement."""
    from packaging.utils import canonicalize_name
    from packaging.version import Version
    reqs = _requirements()  # skips on Python 3.10 (no tomllib)
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import min_constraints
    finally:
        sys.path.pop(0)
    got = {canonicalize_name(k): v for k, v in min_constraints.floors().items()}
    for group in reqs.values():
        for r in group:
            lows = [s.version for s in r.specifier if s.operator == ">="]
            assert lows and Version(got[canonicalize_name(r.name)]) == Version(lows[0]), r


def test_docker_lock_satisfies_pyproject():
    """docker/requirements.lock is hash-locked and covers the core + api + report requirements."""
    from packaging.utils import canonicalize_name
    text = (ROOT / "docker/requirements.lock").read_text(encoding="utf-8")
    lock = _pins(ROOT / "docker/requirements.lock")
    assert text.count("--hash=sha256:") >= len(lock)
    reqs = _requirements()
    for r in reqs["core"] + reqs["api"] + reqs["report"]:
        name = canonicalize_name(r.name)
        assert name in lock, f"{name} not in docker/requirements.lock"
        assert r.specifier.contains(lock[name]), f"{name}=={lock[name]} violates {r}"

