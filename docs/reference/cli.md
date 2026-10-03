# CLI reference

```text
python -m vantage <command> [--catalog seed|real|nist|PATH] [--org POSTURE.yaml] ...
```

`--catalog` defaults to the offline `seed` toy catalog. `real` and `nist` need
`python -m vantage.ingest.build` first. Without `--org`, the real catalogs use
`vantage/postures/acme-real.yaml` (CIS) or `vantage/postures/acme-nist.yaml` (NIST).

| Command | What it does |
|---|---|
| `coverage` | Summary (claimed %, true %, rule-quality weighted %, status counts) plus a per-tactic table |
| `failure [--top N] [--kind log_source\|detection\|control] [--node ID]` | SPOF ranking (control: techniques left with no claimed control), or one what-if failure |
| `recommend [--steps N] [--log-sources-only]` | Greedy set-cover plan |
| `zt` | Zero-Trust score with the component breakdown and exposed techniques |
| `report --out report.md [--pdf report.pdf]` | "Compliant but undetectable" audit report |
| `navigator --out layer.json` | ATT&CK Navigator layer coloured by status |
| `graph --format json\|cypher` | NetworkX JSON or a Cypher script for Neo4j |
| `serve [--host 127.0.0.1] [--port 8000]` | FastAPI + heatmap UI |
| `demo` | The five demo scenarios |
| `automap [--method tfidf\|embed\|bridge\|bridge-embed] TEXT` | Map free-text control prose to techniques |
| `synth` | Write a synthetic org YAML |

## Posture selectors

| Field | Selectors |
|---|---|
| `claimed_controls` | `@ig1`, `@ig2`, `@ig3` (CIS), `@family:AC\|IA` and `@baseline:LOW\|MODERATE\|HIGH\|PRIVACY` (NIST catalog), `@all`, globs such as `CIS-8.*`, `NIST-AC-*` |
| `ingested_log_sources` | `@all`, globs such as `windows/*` |
| `deployed_detections` | `@all`, `@status:stable\|test` (Sigma statuses: stable, test, experimental, deprecated, unsupported), `@min-level:high`, `@logsource:windows/*`, globs; AND terms with `&` |

A selector or glob that matches nothing in the catalog is an error (`vantage: error: ... matches
nothing in this catalog`, exit 2), so a typo cannot silently report 0% coverage. Unknown statuses,
levels and baselines are errors too, and so is a malformed posture file (bad YAML or a field of the
wrong type). `--top`, `--steps`, `-k` and `--budget` must be positive.

## Helper scripts

| Script | Purpose |
|---|---|
| `python -m vantage.download [--dest DIR]` | Download and sha256-verify the datasets |
| `python -m vantage.ingest.build` | Build `catalog.json` and `catalog-nist.json` |
| `scripts/export_demo.py [--catalog real] [--out docs/demo]` | Pre-render the UI as a static site |
| `scripts/check_results.py [--ref HEAD]` | Determinism check: regenerated `results/` vs a git ref (timing and provenance ignored) |
| `scripts/check_citations.py` | Check every DOI in the references against Crossref / DataCite |
| `scripts/min_constraints.py` | Print the declared minimum versions (audited by `pip-audit` in CI) |
