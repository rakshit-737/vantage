# ADR 0001: Build the catalog from real public datasets, never commit them

- Status: accepted (v0.2.0)
- Date: 2026-09-26

## Context
The MVP shipped a hand-written 33-technique seed catalog with illustrative control and detection
mappings. Every number it produced was a statement about the author's guesses, not about the
frameworks. The spec asks for CIS -> ATT&CK mappings "seeded from public mappings", Sigma rules
parsed from the community ruleset, and the ATT&CK STIX bundle.

## Decision
Use three authoritative public sources, pinned to exact releases and verified by sha256 in
`scripts/download_data.py`:

| Source | Release | Licence | Role |
| --- | --- | --- | --- |
| MITRE ATT&CK Enterprise STIX 2.1 (`mitre-attack/attack-stix-data`) | v19.2 (current) and v8.2 | ATT&CK Terms of Use (royalty-free, attribution) | techniques, tactics, mitigations, revoked-by chain |
| CIS Controls v8 -> MITRE Enterprise ATT&CK v8.2 master mapping (xlsx) | 2021 | CC BY-NC-ND 4.0 | control -> technique ground truth |
| SigmaHQ `sigma_all_rules.zip` | r2026-07-01 | Detection Rule License 1.1 | detections, log sources, technique tags |

Datasets live outside git (`$VANTAGE_DATA_DIR`, default `./data`, git-ignored). The joined
catalog (`processed/catalog.json`, 2.2 MB) is rebuilt with `python -m vantage.ingest.build`.
Tests use tiny hand-written fixtures in the same formats; real-data tests carry
`@pytest.mark.realdata` and skip when the catalog is absent, so CI stays green without downloads.

The CIS workbook is ND (no derivatives), so we never redistribute it or a transformed copy. The
committed artefacts only contain safeguard ids, aggregate metrics and ATT&CK names.

## Consequences
- Every coverage number is reproducible from public inputs, and upstream drift is caught by hashes.
- The offline seed catalog stays as the zero-download demo and a fast unit-test universe.
- Users must download about 80 MB once. The CIS link is a marketing redirect that may change; the
  script prints the hash, so a changed file is detected and not silently used.
