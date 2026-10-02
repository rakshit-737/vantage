# Reproduce

Every number on this site comes from a script in `benchmarks/` and is written to `results/*.json`
and `results/*.md`. This page lists the exact commands, what they should print, and how long they
took.

**Environment of the published run:** Windows 11 laptop (16 GB RAM, CPU only), Python 3.14. The
laptop was shared with other jobs, so wall times are upper bounds. The `realdata` GitHub Actions
workflow (ubuntu-24.04, Python 3.12) re-runs the same pipeline weekly and uploads its logs and
results as an artefact.

## 1. Install

```bash
git clone https://github.com/rakshit-737/vantage && cd vantage
pip install -e ".[dev,data,bench]"      # add ".[ml]" for the embedding encoders
export VANTAGE_DATA_DIR=$PWD/data       # any folder; datasets are never committed
```

## 2. Download (about 190 MB, resumable)

```bash
python -m vantage.download
```

Each line shows the status, size, sha256 and file. Any `MISMATCH` makes the command exit 1, and a
fresh download that mismatches is renamed `*.mismatch`. Expected output:

```
ok          53.8 MB  dc1639ca...c3d8f4  enterprise-attack-19.2.json
ok          22.3 MB  8af8ba82...9ea69b  enterprise-attack-8.2.json
ok           3.2 MB  5725c91b...385085  sigma_all_rules-r2026-07-01.zip
ok           2.0 MB  355ae97d...a929c8  nist_800_53-rev5_attack-16.1-enterprise.json
ok           1.2 MB  f1d3343d...74af91  cis_v8_attack_v82_master_mapping.xlsx
ok          46.5 MB  8423d8da...982813  enterprise-attack-16.1.json
ok          44.9 MB  0d1c347a...74323b  enterprise-attack-17.1.json
ok           0.6 MB  21d88ec6...068004  ctid/aws-12.12.2024_attack-16.1-enterprise.json
...                                        (6 CTID mappings, OSCAL catalog, 4 baseline profiles)
```

The full digests are in `vantage/download.py`. URLs are pinned to upstream git commits.

## 3. Build the catalogs (about 1-2 min)

```bash
python -m vantage.ingest.build
```

Expected summary (abridged):

```
"safeguards": 153, "mapped_safeguards": 105, "pairs_current": 2919,
"carried_forward_revoked": 134, "dropped_deprecated_or_unknown": 14,
"sigma": {"rules_read": 3302, "kept": 2877, "log_sources": 116}, "techniques": 697
wrote .../processed/catalog.json (2.2 MB)
"controls": 109, "pairs_current": 5236, "carried_forward_revoked": 173, ...
wrote .../processed/catalog-nist.json
```

## 4. Benchmarks

Run from `benchmarks/`. Measured wall times are from the published run.

| command | regenerates | wall time |
|---|---|---|
| `python bench_coverage.py` | `results/coverage.*`, `figures/coverage_gap.png` | about 3-5 min, dominated by the brute-force SPOF check (63-283 s depending on load) |
| `python bench_automap.py` | `results/automap.*`, `figures/automap.png` | about 14 min with embeddings (sum of the `seconds` column: 815 s); `--no-embed` takes a few minutes |
| `python bench_recommend.py` | `results/recommend.*`, `figures/recommend.png` | under 1 min (needs scipy) |
| `python bench_crossframework.py --no-embed` | `results/crossframework.*`, `figures/crossframework.png` | 453 s (recorded in the JSON as `seconds`) |
| `python bench_crossframework.py` | adds the MiniLM encoder (published tables come from this run) | 356 s for both encoders on the GitHub ubuntu runner |
| `python bench_ablation.py` | `results/ablation.*`, `figures/ablation.png` | 439 s |
| `python bench_published.py` | `results/published.md` (reads crossframework.json) | under 1 s |

Expected headline lines:

- `results/ablation.md`: "the paper-vs-defended overstatement is 24.1-55.7 pp ... (T0) and
  still 10.9-26.5 pp ... (T5)".
- `results/coverage.md` A: `T0 classic Windows event logs | IG2 | 3 | 53.9 | 13.2 | 11.2`.
- `results/crossframework.md`: `NIST SP 800-53B ... LOW | 149 | 51 | 460 | 66.0`.

## 5. Tests and determinism

```bash
python -m pytest -q                       # realdata tests run when the catalog exists
python -m pytest -q -m realdata
git diff --exit-code -- results/*.md      # only wall-time / seconds fields may differ
```

Everything is seeded: synthetic orgs (seeds 0-24), random baselines (10 seeds), bootstraps
(seed 0) and rule dropout (seed 0). Only timings change between runs.
