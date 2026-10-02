import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vantage.api import create_app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app("seed"), base_url="http://127.0.0.1")


def test_index_and_static(client):
    r = client.get("/")
    assert r.status_code == 200 and "VANTAGE" in r.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/healthz").json() == {"ok": True}


def test_meta(client):
    m = client.get("/api/meta").json()
    assert m["catalog"]["techniques"] == 33
    assert any(ls["id"] == "edr" and ls["ingested"] for ls in m["log_sources"])


def test_coverage_matrix_and_what_if(client):
    base = client.get("/api/coverage").json()
    assert base["summary"]["true_pct"] == 45.5
    ids = {c["id"] for col in base["matrix"] for c in col["techniques"]}
    assert "T1059" not in ids and "T1003" not in ids  # seed has only sub-techniques w/o parents
    what_if = client.post("/api/coverage", json={"disable_log_sources": ["edr"]}).json()
    assert what_if["summary"]["true_pct"] < base["summary"]["true_pct"]
    better = client.post("/api/coverage", json={"enable_log_sources": ["win_security", "sysmon"]}).json()
    assert better["summary"]["true_pct"] > base["summary"]["true_pct"]
    # unknown log sources in what-if are ignored, not injected
    same = client.post("/api/coverage", json={"enable_log_sources": ["nope"]}).json()
    assert same["summary"] == base["summary"]


def test_technique_detail(client):
    t = client.get("/api/technique/t1053.005").json()
    assert t["status"] == "paper_only" and t["dead_rules"][0]["id"] == "sig_schtask"
    assert client.get("/api/technique/T9999").status_code == 404


def test_failure_recommend_zt(client):
    spof = client.post("/api/failure?top=3").json()
    assert spof[0]["node"] == "edr"
    recs = client.post("/api/recommend?steps=2").json()
    assert recs[0]["target"] == "win_security"
    assert client.get("/api/zt").json()["score"] == 53.2


def test_automap_report_navigator(client):
    r = client.get("/api/automap", params={"text": "dump credentials from lsass", "k": 3}).json()
    assert r[0]["id"] == "T1003.001"
    assert client.get("/api/automap", params={"text": "x"}).status_code == 422
    assert "Compliant but undetectable" in client.get("/api/report").text
    layer = client.get("/api/navigator").json()
    assert layer["domain"] == "enterprise-attack" and layer["techniques"]


def test_token_auth(monkeypatch):
    monkeypatch.setenv("VANTAGE_API_TOKEN", "s3cret")
    c = TestClient(create_app("seed"), base_url="http://127.0.0.1")
    assert c.get("/api/meta").status_code == 401
    assert c.get("/api/meta", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/meta", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert c.get("/healthz").status_code == 200


def test_app_on_mini_real_catalog(tmp_path, mini_dict):
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps(mini_dict))
    org = tmp_path / "org.yaml"
    org.write_text("name: mini\nclaimed_controls: ['@all']\ningested_log_sources: ['windows/*']\n"
                   "deployed_detections: ['@all']\n")
    c = TestClient(create_app(str(p), str(org)), base_url="http://127.0.0.1")
    cov = c.get("/api/coverage").json()
    cols = {col["tactic"]: col for col in cov["matrix"]}
    assert list(cols) == ["execution", "persistence", "credential-access", "lateral-movement"]
    t1059 = next(x for x in cols["execution"]["techniques"] if x["id"] == "T1059")
    assert t1059["subs"] == 1 and t1059["best"] == "defended"
    r = c.get("/api/automap", params={"text": "segment the network to stop SMB lateral movement",
                                      "method": "bridge", "k": 2}).json()
    assert r[0]["id"] == "T1021.002"


def test_rejects_foreign_host_dns_rebinding(client):
    c = TestClient(create_app("seed"), base_url="http://attacker.example:8000")
    assert c.get("/api/coverage").status_code == 400
    assert client.get("/api/meta").status_code == 200


def test_body_and_item_size_limits(client):
    big = {"disable_log_sources": ["A" * 70_000]}
    assert client.post("/api/coverage", json=big).status_code == 413
    assert client.post("/api/coverage", json={"disable_log_sources": ["A" * 201]}).status_code == 422
    assert client.post("/api/coverage", json={"disable_log_sources": ["x"] * 501}).status_code == 422
    assert client.post("/api/coverage", json={"disable_log_sources": ["A" * 200]}).status_code == 200


def test_security_headers_and_docs_off(client):
    r = client.get("/")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/docs").status_code == 404 and client.get("/api/openapi.json").status_code == 404


def test_served_app_requires_token_by_default(monkeypatch, capsys):
    from vantage.api import app_from_env, resolve_token
    monkeypatch.delenv("VANTAGE_API_TOKEN", raising=False)
    monkeypatch.delenv("VANTAGE_ALLOW_NO_AUTH", raising=False)
    c = TestClient(app_from_env(), base_url="http://127.0.0.1")
    assert c.get("/api/meta").status_code == 401
    tok = capsys.readouterr().err.split("#token=")[1].split()[0]
    assert c.get("/api/meta", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    monkeypatch.setenv("VANTAGE_ALLOW_NO_AUTH", "1")
    assert resolve_token() is None


def test_control_spof_endpoint(client):
    r = client.post("/api/failure", params={"kind": "control", "top": 3}).json()
    assert r and all(x["kind"] == "control" for x in r)
