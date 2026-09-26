# ADR 0005: Map controls to techniques through ATT&CK mitigations

- Status: accepted
- Date: 2026-09-26

## Context
The spec's one genuine ML use is auto-mapping free-text controls to ATT&CK with sentence
embeddings. Controls are preventive, organisational prose ("Establish and maintain a secure
configuration process ..."). Technique descriptions are adversary-behaviour prose ("Adversaries
may abuse ..."). Direct similarity between the two is weak.

## Decision
Ship several mappers and evaluate all of them against the official CIS v8 mapping (105 mapped
safeguards, macro-averaged P@k, R@k and MAP@200):

1. `tfidf-direct`: TF-IDF cosine against technique text (dependency-free).
2. `embed-direct`: sentence-transformers cosine against technique text.
3. `mitigation-bridge`: similarity to the ATT&CK mitigations (42 in v8.2, 44 in v19.2), whose
   prose is control-like, then rank each technique by the best-matching mitigation that
   mitigates it (STIX `mitigates` relationships), plus 0.1 x direct similarity as a tie-breaker.
4. Baselines: random, and leave-one-out popularity (the techniques most often mapped by the other
   safeguards).

Result on ATT&CK v8.2 (`results/automap.md`): direct matching is no better than the popularity
prior (MAP 0.12-0.14 vs 0.16). The bridge reaches MAP 0.34 with TF-IDF and 0.42 with MiniLM
embeddings, and R@50 0.62.

## Consequences
- A 2.6x MAP improvement over the prior with no training and no CIS labels.
- Caveat: CIS built its mapping via ATT&CK mitigations, so the bridge exploits the same structure
  the annotators used. That is legitimate (only public ATT&CK data is used at inference) but
  results on frameworks mapped differently (for example ISO 27001) may be lower.
- Still far from expert level: precision@10 is 0.39. The tool presents suggestions, not mappings.
