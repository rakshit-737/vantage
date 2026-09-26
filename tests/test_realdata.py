"""Checks against the real downloaded datasets. Skipped automatically when data is absent (CI)."""
import pytest

from vantage import automap
from vantage.cli import REAL_DEMO_ORG
from vantage.coverage import compute_coverage
from vantage.failure import rank_spofs
from vantage.io import load_org
from vantage.recommend import recommend
from vantage.selectors import expand_org

pytestmark = pytest.mark.realdata


def test_real_catalog_shape(real_cat):
    assert len(real_cat.techniques) > 600
    assert len(real_cat.controls) == 153                     # CIS v8 has 153 safeguards
    assert sum(1 for c in real_cat.controls.values() if c.mitigates) >= 100
    assert len(real_cat.detections) > 2000
    assert len(real_cat.mitigations) > 40
    assert real_cat.meta["cis"]["carried_forward_revoked"] > 0


def test_real_demo_org_gap(real_cat):
    org = expand_org(real_cat, load_org(REAL_DEMO_ORG))
    real_cat.validate_org(org)
    cov = compute_coverage(real_cat, org)
    assert cov.claimed_pct > cov.true_pct + 20
    assert rank_spofs(real_cat, org, top=1)[0].kind == "log_source"
    top = recommend(real_cat, org, max_steps=1, actions=("onboard_log_source",))[0]
    assert len(top.new_techniques) >= 10


def test_real_bridge_beats_direct_tfidf(real_cat):
    bridge = automap.evaluate_mapper(automap.MitigationBridgeMapper(real_cat, "tfidf"), real_cat, ks=(10,))
    direct = automap.evaluate_mapper(automap.TfidfMapper(real_cat), real_cat, ks=(10,))
    assert bridge["MAP@200"] > direct["MAP@200"]
