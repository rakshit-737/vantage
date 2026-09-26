# Threat model

## Assets
- **Posture file** (claimed controls, ingested log sources, deployed rules, segmentation/IAM facts).
- **Derived outputs**: coverage heatmap, SPOF list, audit report, and graph exports. These are an explicit list of techniques that go undetected.

## Trust boundaries
- VANTAGE reads local YAML and writes local files and stdout. It makes no network calls and does not touch production systems.
- Input files are untrusted data. They are parsed with `yaml.safe_load` (no arbitrary object construction), and every id is checked against the catalog (`Catalog.validate_org`).
- Cypher export escapes every value as a JSON string literal, so node ids and names from the catalog cannot inject clauses.

## Threats and mitigations (STRIDE-lite)

| Threat | Example | Mitigation |
| --- | --- | --- |
| Information disclosure | Report leaks and becomes an attacker's target roadmap | Local-only by design, no server component, and a sensitivity banner in reports. Users should store outputs as confidential. |
| Tampering | Posture file edited to inflate coverage | Out of scope for the MVP. TODO: sign posture files or derive them from live telemetry. |
| Malicious input | YAML with Python tags, or unknown ids | `safe_load`, typed validation, and fail-closed on unknown ids |
| Injection | Crafted names in Cypher export | JSON-escaped literals, labels from a fixed allow-list |
| Misleading output | Illustrative seed mappings treated as authoritative | Documented clearly in README and `seed.py`. Curation is a TODO. |

## Abuse case
The coverage map shows an attacker which techniques go undetected. VANTAGE is a self-hosted analysis artifact and must never be exposed as a public endpoint. The planned FastAPI layer must bind to localhost and require authentication.
