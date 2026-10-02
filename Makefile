PY ?= python
# Real datasets live outside git. Point VANTAGE_DATA_DIR at them (default ./data).
export VANTAGE_DATA_DIR ?= $(CURDIR)/data

.PHONY: install data catalog bench demo demo-real serve test lint report clean

install:
	$(PY) -m pip install -e ".[dev,bench]"

data:            ## download ATT&CK STIX, CIS v8 mapping, SigmaHQ (sha256-verified)
	$(PY) -m vantage.download

catalog: data    ## parse + join into $(VANTAGE_DATA_DIR)/processed/catalog.json
	$(PY) -m vantage.ingest.build

bench: catalog   ## regenerate results/*.md|json and docs/figures/*.png
	$(PY) benchmarks/bench_automap.py
	$(PY) benchmarks/bench_coverage.py
	$(PY) benchmarks/bench_recommend.py

demo:            ## offline toy catalog (no downloads)
	$(PY) -m vantage demo

demo-real: catalog
	$(PY) -m vantage demo --catalog real

serve: catalog
	$(PY) -m vantage serve --catalog real

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check vantage tests scripts benchmarks

report:
	$(PY) -m vantage report --out examples/acme-report.md

clean:
	rm -rf .pytest_cache build *.egg-info
