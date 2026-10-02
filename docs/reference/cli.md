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
| `failure [--top N] [--kind log_source\|detection --node ID]` | SPOF ranking, or one what-if failure |
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
| `claimed_controls` | `@ig1`, `@ig2`, `@ig3` (CIS), `@family:AC\|IA` (NIST), `@all`, globs such as `CIS-8.*`, `NIST-AC-*` |
| `ingested_log_sources` | `@all`, globs such as `windows/*` |
| `deployed_detections` | `@all`, `@status:stable\|test`, `@min-level:high`, `@logsource:windows/*`, globs; AND terms with `&` |

## Helper scripts

| Script | Purpose |
|---|---|
| `scripts/download_data.py [--dest DIR]` | Download and sha256-verify the datasets |
| `python -m vantage.ingest.build` | Build `catalog.json` and `catalog-nist.json` |
| `scripts/export_demo.py [--catalog real] [--out docs/demo]` | Pre-render the UI as a static site |
