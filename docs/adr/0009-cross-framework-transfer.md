# ADR 0009: Cross-framework comparison and transfer evaluation

Date: 2026-10-02. Status: accepted.

## Context
Round 3 asked for SP 800-53B baselines, the other CTID Mappings Explorer frameworks, and an
auto-mapper trained on one framework and tested on another. Three hazards came up in review:

1. **Label leakage.** CTID mapping objects carry a per-pair `comments` field written about the
   technique. Feeding it to a mapper leaks the label.
2. **Optimistic selection.** The first draft reported the "best of 7 sources" chosen by test MAP, and
   an in-framework diagonal whose weights were tuned on the same leave-one-out folds.
3. **Release mismatch.** CIS is mapped on ATT&CK v8.2, the CTID files on v16.1/v17.1, and all are
   scored on v19.2. That penalises older mappings for techniques that did not exist yet.

## Decision
- `vantage.frameworks` loads every framework as `Control` objects carried forward to v19.2 via
  revoked-by links (counts reported per framework). Only the capability id, name and group are
  used as text; `comments` is dropped (tested).
- NIST control text is the OSCAL rev5 statement, with parameters substituted. SP 800-53B baseline
  membership is attached at build time and exposed as the `@baseline:` selector.
- `TransferMapper` = mitigation bridge + kNN label transfer + technique prior. Its two weights are
  chosen by leave-one-out on the *training* framework only.
- The headline transfer source is fixed in advance: **pooled**, i.e. every framework except the
  test one. Single-source results are reported as mean, min-max and the number of sources that
  fall below zero-shot. All differences are paired bootstraps over the same test controls.
- The in-framework estimate is **nested** leave-one-out: the weights are re-chosen without the
  held-out control.
- Each test framework is scored over the v19.2 techniques that existed in its source release
  (CIS 525, v16.1 653, v17.1 677 candidates). Gold labels are restricted to the same set.

## Consequences
- Nested LOO equals the tuned diagonal for the four text-rich frameworks, where the same weights win
  on every fold. It is lower for the four security-stack mappings (AWS 0.231 -> 0.195, Azure
  0.200 -> 0.167, GCP 0.182 -> 0.167, M365 0.457 -> 0.452, TF-IDF). For Azure the nested value falls
  below the zero-shot bridge (0.186), and for AWS it falls below pooled transfer (0.204).
- Pooled transfer beats zero-shot on 6 of 8 frameworks with a paired interval above 0 (all except
  CIS and Azure). Most single sources hurt on the text-rich frameworks (5-7 of 7 below zero-shot).
- The TF-IDF IDF of the training texts still includes the held-out control on the diagonal: a
  small transductive effect, documented in `vantage/transfer.py`.
