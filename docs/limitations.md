# Limitations & roadmap

## Limitations

- **"Detectable" means a live rule is tagged with the technique.** A Sigma tag is not proof of
  detection quality. The rule-quality weighted score (ADR 0007) is a sensitivity check built on
  assumed weights, not measured precision or recall. Sub-techniques and parent techniques are
  scored separately.
- **The CIS mapping is from 2021 (ATT&CK v8.2).** 134 ids were carried forward via revoked-by and
  14 deprecated ids were dropped. Techniques added since then cannot be "claimed" through CIS.
- **The NIST mapping targets ATT&CK v16.1.** SP 800-53B baselines now come from the NIST OSCAL
  profiles (`@baseline:LOW|MODERATE|HIGH`). LOW already reaches 460 of the 466 mapped techniques
  (66.0% vs 66.9%), so "claim every mapped control" is barely an upper bound.
- **ISO 27001 and NIST CSF** have no official ATT&CK mapping. Two-hop mappings derived through
  800-53 would over-approximate, so they are not included. CRI Profile v2.1, which is aligned with
  CSF, is included instead.
- **Cross-framework auto-mapping** helps when the labels come from many frameworks (pooled), but
  most single sources hurt on text-rich frameworks. With few labels (Azure), in-framework training
  is worse than zero-shot. See ADR 0009.
- **Costs are assumptions** (ADR 0004), not measurements. The Zero-Trust facts and all org
  profiles are synthetic; no public dataset of enterprise postures exists.
- **Auto-mapping is a suggestion tool.** The mitigation bridge benefits from CIS and CTID having
  built their mappings via ATT&CK mitigations. On the other frameworks it scores lower (MAP@200
  0.09-0.36 with TF-IDF), though still above direct text matching.
- **No live telemetry ingestion:** "ingested" is declared in the posture file, not measured.
- **The static demo** cannot run what-ifs or auto-mapping; those need the local API.
- **Spec deviations:** the UI is vanilla JS rather than React (ADR 0006); there is no LLM
  re-ranker (VANTAGE stays offline with no API key); the asset/identity layer is segment-level.
- **Timings are load-sensitive.** The brute-force SPOF check took 63 s in the v0.2.0 run and
  283 s in the v1.0.0 re-run on the same laptop while other jobs were running. The one-pass
  ranking stays around 10 ms and its output is identical.

## Roadmap

- [x] Real ATT&CK / CIS / Sigma ingest with revoked-id resolution
- [x] Coverage, failure propagation, recommender, Zero-Trust score on the real catalog
- [x] Auto-mapper benchmark against the official CIS mapping, with bootstrap CIs and seeded baselines
- [x] FastAPI + heatmap UI, PDF audit report, Navigator export, Docker
- [x] NIST 800-53 rev5 -> ATT&CK (CTID Mappings Explorer) as a second control framework (v1.0.0)
- [x] Rule-quality weighting (Sigma level/status) in the defended score (v1.0.0)
- [x] Static demo of the UI on GitHub Pages; docs site; container image and releases (v1.0.0)
- [x] NIST SP 800-53B baselines as selectors; CRI, CSA CCM, AWS, Azure, GCP and M365 mappings;
  train-on-one / test-on-another auto-mapping evaluation (round 3)
- [x] Control-failure SPOFs; Neo4j round-trip check in CI; 12-framework ablation
- [ ] Use Sigma `falsepositives` notes in rule quality (free text: needs human labelling)
- [ ] Asset/identity graph beyond segment-level facts; live Neo4j sync (needs real asset data)
- [ ] Posture ingestion from SIEM APIs (log-source health) instead of declarations (needs a live SIEM)
