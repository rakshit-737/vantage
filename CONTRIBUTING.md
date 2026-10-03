# Contributing

Thanks for helping. VANTAGE is a defensive, read-only analysis tool. Contributions must keep it
that way: no scanning, no exploit code, and no network calls outside the dataset downloader.

## Setup

```bash
pip install -e ".[dev,bench]"
python -m pytest -q                        # CI-equivalent; realdata tests skip without datasets
python -m ruff check vantage tests scripts benchmarks
python -m bandit -r vantage -q
```

For real-data work:

```bash
export VANTAGE_DATA_DIR=/path/outside/repo
python scripts/download_data.py && python -m vantage.ingest.build
python -m pytest -q -m realdata
```

## Guidelines

- **Never commit datasets** or files larger than about 1 MB. Add download logic with a pinned
  sha256 instead. The CIS workbook is CC BY-NC-ND: do not commit it or derived copies of it.
- Tests must pass without the big datasets. Use the tiny fixtures in `tests/fixtures/` and mark
  real-data tests with `@pytest.mark.realdata`.
- If you change mappings, costs or scoring, re-run `benchmarks/` and update `results/`, the
  README tables and an ADR if a decision changed. Report numbers honestly, including negative results.
- Results must be reproducible: `python scripts/check_results.py` compares regenerated
  `results/` with git `HEAD` (only timing and provenance may differ). Commit results from a
  `realdata` workflow run, so each file names the run and commit it came from.
- When `pyproject.toml` dependencies change, regenerate the Docker lock with the `uv pip compile`
  command in the header of `docker/requirements.lock` (a test checks it still satisfies
  `pyproject.toml`).
- A release bumps `vantage/__init__.py`, `CITATION.cff` (`version` and `date-released`) and the
  CHANGELOG, then re-exports the static demo (`python scripts/export_demo.py --catalog real`) so
  `docs/demo/data/meta.json` carries the new version.
- UI code must write third-party strings (Sigma titles, ATT&CK text) with `textContent`, never
  `innerHTML`.
- Use conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`, `ci:`,
  `refactor:`), one logical change per commit.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.
