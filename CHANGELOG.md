# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-02

### Added
- Round 3, cross-framework: CTID Mappings Explorer CRI Profile v2.1, CSA CCM 4.1 and the AWS, Azure,
  GCP and M365 security-stack mappings; the NIST OSCAL rev5 catalog (control statements) and the
  SP 800-53B LOW/MODERATE/HIGH/PRIVACY baselines. Parsers `vantage.ingest.ctid` and
  `vantage.ingest.oscal`, registry `vantage.frameworks` (ADR 0009).
- `@baseline:LOW|MODERATE|HIGH` selector, with `acme-nist-low.yaml` and `acme-nist-moderate.yaml`
  postures.
- `TransferMapper`: trained on one framework, tested on another, with nested leave-one-out, a
  pre-specified pooled source, per-release candidate sets and paired bootstrap CIs
  (`benchmarks/bench_crossframework.py`, `results/crossframework.md`).
- 12-framework ablation of the paper-vs-defended gap (`bench_ablation.py`, `results/ablation.md`),
  and a published-work comparison stating that no directly comparable benchmark exists
  (`results/published.md`).
- Control-failure SPOFs (`vantage failure --kind control`, `POST /api/failure?kind=control`).
- `vantage --version`, help text on every option, and one-line errors (exit 2) for missing extras
  or data.
- Docs: How it works, Evaluation methodology, Reproduce, a landing-page hero; CITATION.cff,
  issue/PR templates, CODEOWNERS, Dependabot.
- CI: Python 3.10-3.14, wheel and sdist smoke tests, a Neo4j round-trip check, docs build on PRs
  with a demo-shadowing guard, a post-deploy Playwright check of `/demo/`, and a weekly
  `realdata` workflow.

### Changed
- The API requires a bearer token by default (generated and printed if `VANTAGE_API_TOKEN` is
  unset), rejects foreign `Host` headers (DNS rebinding), caps bodies at 64 KiB and ids at 200
  characters, sends CSP and related headers, and turns OpenAPI docs off unless `VANTAGE_API_DOCS=1`.
- The posture files ship inside the wheel (`vantage/postures/`). The downloader is
  `python -m vantage.download`; the default data dir outside a checkout is `~/.vantage/data`.
- Dataset URLs are pinned to upstream commits; a mismatching fresh download is quarantined.
- Hugging Face embedding models are pinned to a revision; `VANTAGE_EMBED_MODEL` selects a local model.
- The ablation table labels its brackets as a one-sided rule-dropout sensitivity range, not a CI.
- Cypher export uses typed literals, uniqueness constraints and labelled edge matches.
- Release workflow: gated on tests, tag/version check, fixed CHANGELOG extraction, `latest`
  pushed once. Actions are pinned by SHA (Node 24 majors); the Docker base image is pinned by digest.

### Fixed
- The docs page `demo.md` overwrote the static demo at `/demo/` (renamed to `live-demo.md`).
- In the static demo, the what-if checkboxes and auto-map controls are now disabled.
- `export_demo.py` refuses to delete a folder that is not a previous export.
- README: DeTT&CT credited to Rabobank CDC; random-baseline row is the 10-seed mean; the CIS
  ceiling is split into new-since-v8.2 and never-mapped techniques; runtimes match the records.

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
