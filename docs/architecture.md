# Architecture

```mermaid
flowchart LR
  subgraph DATA["Public data (downloaded, sha256-pinned, never committed)"]
    A["ATT&CK STIX v19.2 + v8.2"]
    C["CIS v8 to ATT&CK v8.2 master mapping (xlsx)"]
    N["CTID NIST 800-53 rev5 to ATT&CK v16.1 (json)"]
    S["SigmaHQ rules r2026-07-01"]
  end
  A --> I["ingest: STIX parser, revoked-by resolver"]
  C --> I2["ingest: CIS parser"]
  N --> I4["ingest: NIST parser"]
  S --> I3["ingest: Sigma parser, tags + logsource"]
  I --> B["build: catalog.json + catalog-nist.json"]
  I2 --> B
  I3 --> B
  I4 --> B
  O["Org posture YAML with selectors"] --> E
  B --> E["Typed catalog + graph"]
  E --> CE["Coverage engine (binary + rule-quality weighted)"]
  CE --> FP["Failure propagation"]
  CE --> RC["Set-cover recommender"]
  E --> ZT["Zero-Trust scorer"]
  E --> AM["Auto-mapper: TF-IDF, embeddings, mitigation bridge"]
  CE --> API["FastAPI"]
  FP --> API
  RC --> API
  ZT --> API
  AM --> API
  API --> UI["ATT&CK heatmap UI"]
  CE --> R["CLI, Markdown/PDF report, Navigator layer, Cypher"]
```

## The rule

A technique is **defended** only if (a claimed control mitigates it) AND (a deployed rule
detects it) AND (every log source that rule needs is actually ingested).

| Status | Meaning |
| --- | --- |
| `defended` | claimed and detectable |
| `paper_only` | claimed by a control but not detectable ("compliant but blind") |
| `detected_only` | detectable, but no control claims it |
| `blind` | neither |

`weighted_true_pct` additionally scores each defended technique by a noisy-OR of its live rules'
quality (Sigma level x status), see [ADR 0007](adr/0007-rule-quality-weighting.md).

## Engines

- **Coverage** (`vantage.coverage`): per-technique status, claimed % vs true %, per-tactic tables,
  deployed-but-dead rules.
- **Failure propagation** (`vantage.failure`): ranks every log source and rule by how many
  techniques go dark if it fails, in one pass (identical output to brute-force recomputation).
- **Recommender** (`vantage.recommend`): greedy weighted set cover over "deploy rule" and
  "onboard log source (plus the rules it unlocks)" actions, checked against an exact ILP.
- **Zero-Trust scorer** (`vantage.zerotrust`): 0-100 from segmentation, MFA, PAM, device posture
  and account hygiene, plus the lateral-movement techniques exposed by open flows.
- **Auto-mapper** (`vantage.automap`): control text to techniques, directly or through ATT&CK
  mitigations ([ADR 0005](adr/0005-mitigation-bridge-automapper.md)).

## Code layout

`vantage/ingest/` (`attack.py`, `cis.py`, `nist.py`, `sigma.py`, `build.py`), `catalog.py`,
`models.py`, `selectors.py`, `coverage.py`, `failure.py`, `recommend.py`, `zerotrust.py`,
`automap.py`, `graph.py`, `navigator.py`, `report.py`, `pdf.py`, `api.py`, `web/`, `cli.py`.
Offline toy data lives in `seed.py` and `synth.py`.
