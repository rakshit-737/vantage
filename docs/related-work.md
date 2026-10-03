# Related work

VANTAGE combines three things that exist separately: official control-to-ATT&CK mappings,
detection and data-source coverage, and automatic control-to-technique mapping. This page lists
the closest prior work for each and says what VANTAGE adds. The numeric comparison with published
auto-mapping results is in [Evaluation, section 5](evaluation.md#5-comparison-with-published-work).

## Tools

| Existing | What it does | What VANTAGE adds |
| --- | --- | --- |
| [DeTT&CT (Rabobank CDC)](https://github.com/rabobank-cdc/DeTTECT) | Scores data-source and detection coverage against ATT&CK | A control-framework layer, "paper vs detection-backed" status, failure propagation, recommender, Zero-Trust score |
| [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | Manual technique heatmap | Computed status and what-ifs. VANTAGE exports Navigator layers. |
| [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) | Curated control -> ATT&CK mappings | Consumes such mappings and joins them with live detection state |
| Sigma coverage tools (e.g. `sigma-cli` analyze) | Rule -> technique coverage | Log-source dependency, dead-rule detection, control claims |
| Commercial GRC (Vanta, Drata, scorecards) | Evidence collection, external ratings | Technique- and detection-level linkage, open and local |
| [CTID TRAM](https://github.com/center-for-threat-informed-defense/tram) | Classifies CTI report sentences into about 50 techniques | Different task (control text, not CTI); TRAM's published scores come from a private dataset |

DeTT&CT already covers the data-source -> detection -> ATT&CK part. The [ablation](evaluation.md#0-ablation-what-each-evidence-requirement-removes)
puts a DeTT&CT-style detection-only view next to VANTAGE's defended coverage, so the effect of the
control layer is measured rather than asserted.

## Measuring control coverage of ATT&CK

- **Rahman and Williams (2022)** measured how far NIST SP 800-53 controls mitigate the techniques
  used by cybercrime groups and malware in ATT&CK, using an existing control-to-technique mapping:
  only 101 of 298 controls mitigate any technique, and 53 techniques are mitigated by none. That
  is prior art for VANTAGE's "claimed" layer (L0). VANTAGE adds the detection and telemetry
  layers on top of the claim and repeats the measurement over 12 framework profiles.

## Automatic control-to-technique mapping

- **Lee, Yoon, Lee and Kang (2026)** route control text through ATT&CK mitigations with an
  SBERT ensemble on Korean RMF (K-RMF) control text, evaluated against the CTID NIST 800-53
  mapping as a silver standard. VANTAGE's mitigation bridge is an independent re-implementation of
  that idea, evaluated on CIS v8 and 7 other frameworks. No directly comparable benchmark exists:
  their Recall@restricted metric is defined only in the full text, which could not be retrieved
  (see [published.md](evaluation.md#5-comparison-with-published-work) for every setup difference).
- **Lee, Yoon, Lee and Kang (2025)** compare BERT-based models for mapping RMF security controls to
  ATT&CK techniques: the same task, an earlier paper by the same group.
- **Orbinato, Barbaraci, Natella and Cotroneo (2022)** compare traditional and deep-learning
  classifiers for mapping unstructured CTI to ATT&CK techniques and release two datasets. The
  input differs (threat reports, not control text); the output space is the same.

## References

All identifiers below are checked by `scripts/check_citations.py` (titles and authors against
Crossref and DataCite; run by the `citations` workflow).

1. Hanhee Lee, Sukjoon Yoon, Yunkyung Lee, Jiwon Kang. *Enhancing RMF and ATT&CK Mapping Accuracy Through Integration of Sentence-BERT and Mitigation Parameters*. Electronics 15(6):1248, 2026. [doi:10.3390/electronics15061248](https://doi.org/10.3390/electronics15061248)
2. Hanhee Lee, Sukjoon Yoon, Yun-kyung Lee, Jiwon Kang. *Evaluating BERT-Based Models for Mapping RMF Security Controls to MITRE ATT&CK Techniques*. Journal of Information and Security 25(5):11-20, 2025. [doi:10.33778/kcsa.2025.25.5.011](https://doi.org/10.33778/kcsa.2025.25.5.011)
3. Md Rayhanur Rahman, Laurie Williams. *An investigation of security controls and MITRE ATT&CK techniques*. arXiv:2211.06500, 2022. [doi:10.48550/arXiv.2211.06500](https://doi.org/10.48550/arXiv.2211.06500)
4. Vittorio Orbinato, Mariarosaria Barbaraci, Roberto Natella, Domenico Cotroneo. *Automatic Mapping of Unstructured Cyber Threat Intelligence: An Experimental Study*. 2022 IEEE 33rd International Symposium on Software Reliability Engineering (ISSRE), pp. 181-192, 2022. [doi:10.1109/ISSRE55969.2022.00027](https://doi.org/10.1109/ISSRE55969.2022.00027), [arXiv:2208.12144](https://arxiv.org/abs/2208.12144)
