# Getting started

## Install

```bash
git clone https://github.com/rakshit-737/vantage && cd vantage
pip install -e ".[dev]"          # core + API + report + test deps
python -m vantage demo           # offline toy catalog, no downloads
```

Python 3.10+ is required. Optional extras: `api`, `report`, `data`, `ml`
(sentence-transformers), `bench` (scipy, matplotlib).

## Real data

```bash
export VANTAGE_DATA_DIR=$PWD/data       # any folder outside the repo is fine
python -m vantage.download              # ~190 MB, resumable, sha256-verified
python -m vantage.ingest.build          # -> processed/catalog.json and catalog-nist.json

python -m vantage demo      --catalog real      # CIS v8 claims
python -m vantage demo      --catalog nist      # NIST SP 800-53 rev5 claims
python -m vantage coverage  --catalog real --org vantage/postures/acme-real.yaml
python -m vantage failure   --catalog real --top 10
python -m vantage recommend --catalog real --log-sources-only --steps 5
python -m vantage report    --catalog real --out report.md --pdf report.pdf
python -m vantage navigator --catalog real --out layer.json
python -m vantage automap   --catalog real --method bridge "Require MFA for all remote access"
python -m vantage serve     --catalog real      # http://127.0.0.1:8000
```

## Posture file

```yaml
name: Acme Corp
claimed_controls: ["@ig2"]          # CIS: @ig1/@ig2/@ig3; NIST: "@family:AC|IA", "@baseline:MODERATE"; globs: CIS-8.*, NIST-AC-*
ingested_log_sources: [windows/security, "azure/*", proxy]
deployed_detections: ["@status:stable|test&@min-level:medium"]
zero_trust: {segments: [...], open_flows: [[finance, general]], mfa_coverage: 0.6}
```

## Docker

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/vantage:latest   # seed catalog
VANTAGE_DATA=/path/to/data VANTAGE_CATALOG=real docker compose up --build   # real catalog
```

The container runs as a non-root user (read-only filesystem in compose) and publishes on
127.0.0.1 only.
