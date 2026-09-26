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
- UI code must write third-party strings (Sigma titles, ATT&CK text) with `textContent`, never
  `innerHTML`.
- Use conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`, `ci:`,
  `refactor:`), one logical change per commit.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.
