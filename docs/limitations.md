# Limitations & roadmap

## Limitations

- **"Defended" means detection-backed.** A technique counts as defended only if a claimed control
  maps to it and a live Sigma rule is tagged with it. Control mappings say a safeguard *could
  mitigate or detect* a technique, and most mapped CIS safeguards are Protect-function controls:
  a technique blocked by a preventive control is defended without any rule. "Paper-only" is
  therefore coverage without detection evidence, not proof of exposure. The
  [ablation](evaluation.md#0-ablation-what-each-evidence-requirement-removes) splits paper-only
  techniques by CIS Security Function (at T5, 88 of CIS IG2's 115 have only non-Detect claims).
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
- **Cross-framework auto-mapping** (ADR 0009). Pooling the labels of the 7 other frameworks beats
  the zero-shot bridge after Holm adjustment on 4 of 8 frameworks with either encoder (AWS, GCP
  and M365, which are sparse-text, and the text-rich CSA CCM), not on CIS, NIST, CRI-2.1 or Azure.
  Most single training frameworks hurt on the text-rich frameworks. In-framework nested
  leave-one-out is not a ceiling everywhere: for CRI-2.1 pooled transfer scores higher (TF-IDF
  0.416 vs 0.390), and for Azure (both encoders) and CRI-2.1 (MiniLM) nested LOO sits below
  zero-shot. Those differences are point estimates whose paired intervals include 0 (Azure
  TF-IDF -0.019 [-0.079, +0.036]); the data show no difference rather than a harm, and with
  20-60 controls per framework the tests have little power.
- **Costs are assumptions** (ADR 0004), not measurements. The Zero-Trust facts and all org
  profiles are synthetic; no public dataset of enterprise postures exists.
- **Auto-mapping is a suggestion tool.** The mitigation bridge benefits from CIS and CTID having
  built their mappings via ATT&CK mitigations. With TF-IDF the zero-shot bridge ranges from
  MAP@200 0.09 (GCP, M365) to 0.36 (CRI-2.1, slightly above CIS's 0.35). Its paired advantage over
  direct text matching has an interval above 0 on CIS, NIST, CRI, CSA CCM, AWS and GCP, but not on
  Azure or M365 (with MiniLM, not on GCP or M365).
- **No live telemetry ingestion:** "ingested" is declared in the posture file, not measured.
- **The static demo** cannot run what-ifs or auto-mapping; those need the local API.
- **Spec deviations:** the UI is vanilla JS rather than React (ADR 0006), and there is no LLM
  re-ranker (VANTAGE stays offline with no API key). There are no Asset nodes or `EMITS`
  (asset -> log source) edges, so coverage is org-wide rather than per segment; the Zero-Trust
  scorer uses segment-level facts only (synthetic segments in `synth.py`).
- **Rule-dropout ranges are not CIs.** The brackets in `results/ablation.md` are a one-sided
  sensitivity range (10% of rules removed) and sit at or below the point estimate.
- **Timings depend on the machine.** Published wall times come from the GitHub ubuntu runner
  (run 37092934843); the brute-force SPOF check took 7.7 s there and minutes on a loaded laptop.
  The one-pass ranking's output is identical either way.

## Roadmap

- [x] Real ATT&CK / CIS / Sigma ingest with revoked-id resolution
- [x] Coverage, failure propagation, recommender, Zero-Trust score on the real catalog
- [x] Auto-mapper benchmark against the official CIS mapping, with bootstrap CIs and seeded baselines
- [x] FastAPI + heatmap UI, PDF audit report, Navigator export, Docker
- [x] NIST 800-53 rev5 -> ATT&CK (CTID Mappings Explorer) as a second control framework (v1.0.0)
- [x] Rule-quality weighting (Sigma level/status) in the defended score (v1.0.0)
- [x] Static demo of the UI on GitHub Pages; docs site; container image and releases (v1.0.0)
- [x] NIST SP 800-53B baselines as selectors; CRI, CSA CCM, AWS, Azure, GCP and M365 mappings;
  train-on-one / test-on-another auto-mapping evaluation (v1.1.0)
- [x] Control-failure SPOFs; Neo4j round-trip check in CI; 12-framework ablation (v1.1.0)
- [x] Every result regenerated in CI with its run id; paired tests with Holm adjustment;
  control-layer arm (detection-only view, CIS-function split)
- [ ] Use Sigma `falsepositives` notes in rule quality (free text: needs human labelling)
- [ ] Asset/identity graph (Asset nodes, `EMITS` edges, per-segment defended coverage); live
  Neo4j sync (needs real asset data)
- [ ] Posture ingestion from SIEM APIs (log-source health) instead of declarations (needs a live SIEM)
