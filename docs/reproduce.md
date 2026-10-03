# Reproduce

Every number on this site comes from a script in `benchmarks/` and is written to `results/*.json`
and `results/*.md`. This page lists the exact commands, what they should print, and how long they
took.

**Environment of the published run:** every committed result file comes from the `realdata`
GitHub Actions run [37092934843](https://github.com/rakshit-737/vantage-compliance-attack-mapping/actions/runs/37092934843)
at commit `6ff466d`: ubuntu-24.04 runner (4 vCPU, 16 GB), Python 3.12.14, CPU-only torch 2.11.0.
Each `results/*.json` names that run and commit in its `provenance` block, and each
`results/*.md` ends with a source line. Before v1.1.0 some files came from a Windows 11 laptop;
the regenerated numbers are identical apart from the coverage gaps, which are now rounded once
(42.7 -> 42.8 pp, 26.6 -> 26.5 pp). The workflow re-runs everything weekly and uploads logs,
results and figures as an artefact.

## 1. Install

```bash
git clone https://github.com/rakshit-737/vantage-compliance-attack-mapping && cd vantage-compliance-attack-mapping
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

## 3. Build the catalogs (5 s on the runner, about 1-2 min on a laptop)

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

Run from `benchmarks/` (`pip install -e ".[dev,data,bench,ml]"`). Wall time and peak memory are
from run 37092934843 (`/usr/bin/time`, in the artefact's `bench_*.log`).

| command | regenerates | wall time | peak RSS |
|---|---|---:|---:|
| `python bench_coverage.py` | `results/coverage.*`, `figures/coverage_gap.png` | 11 s (7.7 s of it the brute-force SPOF check) | 0.3 GB |
| `python bench_recommend.py` | `results/recommend.*`, `figures/recommend.png` (needs scipy) | 3 s | 0.1 GB |
| `python bench_ablation.py` | `results/ablation.*`, `figures/ablation.png`, `figures/ablation_shares.png` | 48 s | 0.3 GB |
| `python bench_walkthrough.py` | `results/walkthrough.*` (the How-it-works numbers) | under 1 s | 0.05 GB |
| `python bench_automap.py` | `results/automap.*`, `results/automap_per_control.csv.gz`, `figures/automap.png` | 287 s with MiniLM and bge-small (model download included) | 1.5 GB |
| `python bench_crossframework.py` | `results/crossframework.*`, `results/crossframework_per_control.csv.gz`, `figures/crossframework.png` (TF-IDF), `figures/crossframework-minilm.png` | 234 s for both encoders | 1.1 GB |
| `python bench_published.py` | `results/published.md` (reads crossframework.json) | under 1 s | - |

`--no-embed` (automap, crossframework) skips the sentence-transformers encoders: it rewrites the
files with the TF-IDF rows and sections only, so the MiniLM/bge numbers disappear until the
benchmark is re-run with the `ml` extra installed.

Expected headline lines:

- `results/ablation.md`: "the paper-vs-defended overstatement is 24.1-55.7 pp ... (T0) and
  still 10.9-26.5 pp ... (T5)" and "the telemetry share (L1-L2) is larger than the rule-tag share
  (L0-L1) in 11/12 at T0, 4/12 at T1, 0/12 at T2 ...".
- `results/coverage.md` A: `T0 classic Windows event logs | IG2 | 3 | 53.9 | 13.2 | 11.2 | 9.2 | 42.8`.
- `results/crossframework.md`: `NIST SP 800-53B ... LOW | 149 | 51 | 460 | 66.0`, and
  "pooled - zero-shot: ... Holm p < 0.05 (m = 16): 4 of 8 positive (AWS, GCP, M365, CSA-CCM-4.1)".
- `results/automap.md`: `mitigation-bridge[all-MiniLM-L6-v2] | 0.384 [0.317, 0.457] | ... | 0.417 [0.357, 0.478]`.

## 5. Tests and determinism

```bash
cd ..                                     # back to the repo root
python -m pytest -q                       # realdata tests run when the catalog exists
python -m pytest -q -m realdata
python scripts/check_results.py           # compare regenerated results/ with git HEAD
```

`scripts/check_results.py` compares every `results/*.json` with the committed version, ignoring
only timing keys (`seconds`, `*_ms`, `spof_*_s`, `speedup`) and provenance (`generated`,
`python`, `platform`, `provenance`), and compares the per-control `.csv.gz` files after
decompression. Strings, integers and row sets must match exactly; floats may differ by 0.002
(JSON, reported to 3 decimals) and per-control scores by 0.01. The tolerance exists because the
embedding encoders run on whatever CPU model the runner gets: two runs on ubuntu-24.04 (37092934843
and 37094692311) agreed on every reported number, but 2 of 1,680 per-safeguard and 2 of 934
per-control MiniLM/bge APs differed by at most 0.00013, from near-tied techniques swapping places
deep in a ranking. TF-IDF results are bit-identical. The Markdown tables carry timing columns and the source line, so they are not
diffed directly. The check needs the `ml` extra: without it the embedding rows are missing and
it reports the difference. The `realdata` workflow runs it after every weekly run.

Everything is seeded: synthetic orgs (seeds 0-24), random baselines (10 seeds), bootstraps and
sign-flip tests (seed 0) and rule dropout (seed 0). Only timings change between runs.
