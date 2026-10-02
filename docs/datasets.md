# Datasets

| Dataset | Version | Size | Licence | Citation |
|---|---|---:|---|---|
| MITRE ATT&CK Enterprise STIX 2.1 | v19.2 and v8.2 | 54 MB + 22 MB | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) | The MITRE Corporation, [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) |
| CIS Controls v8 Master Mapping to MITRE Enterprise ATT&CK v8.2 | 2021 | 1.2 MB | CC BY-NC-ND 4.0 | Center for Internet Security, [white paper](https://www.cisecurity.org/insights/white-papers/cis-controls-v8-master-mapping-to-mitre-enterprise-attck-v82) |
| NIST SP 800-53 rev5 to ATT&CK v16.1 (Mappings Explorer) | updated 2025-04-16 | 2.0 MB | Apache-2.0 | Center for Threat-Informed Defense, [mappings-explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer) |
| ATT&CK Enterprise STIX 2.1 (releases the CTID mappings target) | v16.1, v17.1 | 46 MB + 45 MB | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) | The MITRE Corporation, [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) |
| CTID Mappings Explorer: AWS, Azure, GCP, M365 security stack; CRI Profile v2.1; CSA CCM 4.1 to ATT&CK | 12.12.2024 / 04.26.2025 / 03.06.2025 / 07.18.2025 / v2.1 / 4.1 (ATT&CK 16.1; CSA 17.1) | 0.5-1.5 MB each | Apache-2.0 | Center for Threat-Informed Defense, [mappings-explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer) |
| NIST SP 800-53 rev5 OSCAL catalog + SP 800-53B LOW/MODERATE/HIGH/PRIVACY profiles | oscal-content @78650f0 | 10 MB + 4 small | Public domain (US Government work) | NIST, [oscal-content](https://github.com/usnistgov/oscal-content) |
| SigmaHQ rule release (`sigma_all_rules.zip`) | r2026-07-01 | 3.2 MB | [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) | SigmaHQ, [sigma](https://github.com/SigmaHQ/sigma) |

None of these files are committed. `python -m vantage.download` (also `scripts/download_data.py`) fetches them from URLs pinned to upstream commits and
verifies pinned sha256 digests. The CIS workbook is non-commercial / no-derivatives: it is read
locally, and only ids and aggregate metrics are published (the static demo shows CIS safeguard
ids, not their text). Sigma rules keep their authors' attribution in the upstream files.

## What the build records

`python -m vantage.ingest.build` writes provenance into the catalog's `meta`: ATT&CK version,
tactic order, every drop decision (deprecated techniques, rules without ATT&CK tags, revoked ids
carried forward) and per-framework pair counts.

| | CIS v8 | NIST 800-53 rev5 |
|---|---:|---:|
| Controls with at least one technique | 105 of 153 | 109 of 109 |
| Source ATT&CK version | 8.2 | 16.1 |
| Pairs carried forward via revoked-by | 134 | 173 |
| Pairs dropped (deprecated) | 14 | 1 |
| Pairs as published | 2,962 | 5,264 |
| Unique pairs on ATT&CK v19.2 | 2,919 | 5,236 |

## Synthetic data

All org postures (`examples/`, `vantage/synth.py`) are synthetic. No public dataset of real
enterprise postures exists.
