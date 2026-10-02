from pathlib import Path

import pytest

from vantage import paths
from vantage.catalog import catalog_from_dict
from vantage.ingest.attack import load_attack
from vantage.ingest.build import build_catalog
from vantage.ingest.cis import parse_rows
from vantage.ingest.sigma import load_rules

from .cis_rows import CIS_ROWS, HEADER, _row  # noqa: F401 - re-exported for tests

FIX = Path(__file__).parent / "fixtures"



@pytest.fixture(scope="session")
def mini_attack():
    return load_attack(FIX / "mini-attack.json")


@pytest.fixture(scope="session")
def mini_dict(mini_attack):
    return build_catalog(mini_attack, parse_rows(CIS_ROWS), load_rules(FIX / "sigma"))


@pytest.fixture
def mini_cat(mini_dict):
    return catalog_from_dict(mini_dict)


@pytest.fixture(scope="session")
def real_cat():
    if not paths.have_real_data():
        pytest.skip("real catalog not built (scripts/download_data.py + python -m vantage.ingest.build)")
    from vantage.catalog import load_catalog
    return load_catalog("real")
