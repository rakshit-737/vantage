### Comparison with published auto-mapping work

**There is no directly comparable published benchmark** for control text -> ATT&CK ranking under our setup. The table puts VANTAGE's numbers next to the closest published work and lists every difference. It is context, not a head-to-head result.

| system | ground truth | metric | value |
|---|---|---|---|
| Lee et al. 2026, SBERT + ATT&CK mitigations ensemble (published) | CTID NIST 800-53 mapping as 'silver standard', K-RMF control text | Recall@restricted (paper's own calibrated metric) | 0.74 (as reported) |
| VANTAGE direct text match (tfidf) | CTID NIST 800-53 rev5, 109 controls | R@10 / R@50 / MAP@200 | 0.057 / 0.173 / 0.091 |
| VANTAGE mitigation bridge, zero-shot (tfidf) | same | R@10 / R@50 / MAP@200 | 0.105 / 0.316 / 0.214 |
| VANTAGE TransferMapper, trained on the 7 other frameworks (tfidf) | same | R@10 / R@50 / MAP@200 | 0.155 / 0.384 / 0.258 |
| TRAM (CTID), CTI sentence classifier (published) | TRAM-labelled CTI report sentences, about 50 techniques | micro-F1 on sentences | different task: not comparable |

Setup differences:

- Lee et al. 2026 (Electronics 15(6):1248, doi:10.3390/electronics15061248) is the closest published setup and the prior art for routing through ATT&CK mitigations. Its headline metric, Recall@restricted, is defined in the full text, which we could not retrieve (HTTP 403 from both MDPI and preprints.org); the abstract says only that it is 'calibrated' for the coverage limits of the CTID silver standard. Without its exact definition (restriction set, cut-off k) no number here should be read as better or worse than 0.74.
- Control text: they use Korean RMF (K-RMF) control text; we use the NIST OSCAL rev5 control statements.
- ATT&CK release: CTID labels target v16.1; we carry them to v19.2 and rank only techniques that existed in v16.1 (653 candidates).
- Model: they use an SBERT ensemble; the numbers above use the encoder named in the row.
- TRAM classifies CTI report sentences into about 50 techniques; its published scores come from a private 2023 dataset with unseeded splits, so there is no matching setup for control text.
