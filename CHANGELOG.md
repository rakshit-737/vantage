# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-09-26

### Added
- NIST SP 800-53 rev5 as a second control framework, from the CTID Mappings Explorer
  (ATT&CK v16.1, Apache-2.0, sha256-pinned). `python -m vantage.ingest.build` now also writes
  `catalog-nist.json` (`--catalog nist`): 109 controls, 5,236 technique pairs on ATT&CK v19.2.
  New `@family:AC|IA` selector and `examples/real/acme-nist.yaml` (ADR 0008).
- Rule-quality weighting: `weighted_true_pct` scores each defended technique by a noisy-OR of its
  live rules' Sigma level x status (ADR 0007). Reported by `coverage`, the audit report and the
  coverage benchmark.
- Benchmark statistics: 95% bootstrap intervals (1,000 resamples over safeguards) for every
  auto-mapping metric, the random baseline over 10 seeds, and t-intervals for the synthetic-org
  gap. New part D in `bench_coverage.py` compares NIST and CIS claims across telemetry tiers.
- Static demo of the web UI (`scripts/export_demo.py`), published at `/demo/` on the docs site.
- MkDocs Material documentation site on GitHub Pages, with mkdocstrings Python API reference.
- Release workflow: on `v*` tags, builds the wheel and sdist, pushes `ghcr.io/rakshit-737/vantage`
  and creates a GitHub Release with notes from this file.
- Tests grew from 83 to 90.

### Changed
- Re-ran all benchmarks. Every published CIS number is unchanged. The brute-force SPOF check
  took 283 s in this run (63 s before) because the laptop was busy; the one-pass ranking still
  takes about 10 ms and its output is identical.
- `docs/README.md` moved to `docs/adr/index.md`.

## [0.2.0] - 2026-09-26

### Added
- Real-data ingest: ATT&CK Enterprise STIX parser (tactics, sub-techniques, mitigations,
  revoked-by resolution), parser for the official CIS Controls v8 -> ATT&CK v8.2 master mapping,
  and SigmaHQ rule parser (ATT&CK tags, log sources, status and level).
- `scripts/download_data.py`: resumable, sha256-pinned download of ATT&CK v19.2 and v8.2, the CIS
  mapping and SigmaHQ r2026-07-01. `python -m vantage.ingest.build` joins them into a catalog.
- `--catalog real|seed|<path>` on every CLI command, plus posture-file selectors (`@ig2`,
  `windows/*`, `@status:stable|test`, `@min-level:high`).
- Auto-mappers: sentence-transformers embeddings, the ATT&CK mitigation-bridge mapper, and random
  and popularity baselines, with an evaluation harness (P@k, R@k, MAP).
- FastAPI service (`vantage serve`) with what-if coverage, SPOF, recommendations, auto-map, report
  and Navigator endpoints, optional bearer-token auth, and a vanilla-JS ATT&CK heatmap UI.
- ATT&CK Navigator layer export, PDF audit report (reportlab), and a per-tactic heatmap for the
  full matrix.
- Benchmarks (`benchmarks/`) with committed results and figures: auto-mapping vs the official
  CIS mapping, the paper-vs-real coverage gap across telemetry tiers and 100 random orgs, and the
  greedy recommender vs an exact ILP and heuristic baselines.
- Dockerfile and localhost-only compose stack; ADRs in `docs/adr/`; LICENSE, CONTRIBUTING.
- Tests grew from 38 to 83 (ingest fixtures, API, SPOF equivalence property, realdata-marked checks).

### Changed
- Single-point-of-failure ranking is now computed in one pass (4 ms vs 63 s brute force on the
  real catalog, identical results).
- The recommender can be restricted to action types (for example log-source onboarding only).
- The demo reports the top SPOF found instead of a hard-coded EDR scenario.
- The ruff rule set is pinned explicitly; bandit findings are resolved.

## [0.1.0] - 2026-09-26

### Added
- Initial MVP: typed catalog, coverage engine (defended / paper-only / detected-only / blind),
  failure propagation, greedy set-cover recommender, Zero-Trust scorer, TF-IDF auto-mapper,
  Markdown audit report, NetworkX/Cypher export, synthetic orgs, and CLI, all over a hand-written
  33-technique seed catalog.
