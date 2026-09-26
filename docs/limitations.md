# Limitations & roadmap

## Limitations

- **"Detectable" means a live rule is tagged with the technique.** A Sigma tag is not proof of
  detection quality. The rule-quality weighted score (ADR 0007) is a sensitivity check built on
  assumed weights, not measured precision or recall. Sub-techniques and parent techniques are
  scored separately.
- **The CIS mapping is from 2021 (ATT&CK v8.2).** 134 ids were carried forward via revoked-by and
  14 deprecated ids were dropped. Techniques added since then cannot be "claimed" through CIS.
- **The NIST mapping targets ATT&CK v16.1** and has no baseline (low/moderate/high) information,
  so the NIST demo claims every mapped control: an upper bound on paper coverage.
- **Costs are assumptions** (ADR 0004), not measurements. The Zero-Trust facts and all org
  profiles are synthetic; no public dataset of enterprise postures exists.
- **Auto-mapping is a suggestion tool.** The mitigation bridge benefits from CIS having built its
  mapping via ATT&CK mitigations, so results on other frameworks may be lower.
- **No live telemetry ingestion:** "ingested" is declared in the posture file, not measured.
- **The static demo** cannot run what-ifs or auto-mapping; those need the local API.
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
- [ ] NIST SP 800-53B baselines as selectors (needs the baseline tables as a pinned dataset)
- [ ] Use Sigma `falsepositives` notes in rule quality (free text: needs human labelling)
- [ ] Asset/identity graph beyond segment-level facts; live Neo4j sync (needs a running Neo4j and real asset data)
- [ ] Posture ingestion from SIEM APIs (log-source health) instead of declarations (needs a live SIEM)
