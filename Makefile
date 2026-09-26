PY ?= python

.PHONY: install demo test lint report clean

install:
	$(PY) -m pip install -e ".[dev]"

demo:
	$(PY) -m vantage demo

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check vantage tests

report:
	$(PY) -m vantage report --out examples/acme-report.md

clean:
	rm -rf .pytest_cache build *.egg-info
