# ADR 0009: Cross-framework comparison and transfer evaluation

Date: 2026-10-02. Status: accepted.

## Context
v1.1.0 adds SP 800-53B baselines, the other CTID Mappings Explorer frameworks, and an
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

- Every contrast is paired over the same test controls: a bootstrap interval plus a two-sided
  sign-flip permutation p-value, Holm-adjusted within its family of 16 (bridge - direct and
  pooled - zero-shot are pre-specified; nested LOO - zero-shot and nested LOO - pooled are
  exploratory). Per-control AP@200 is committed (`results/crossframework_per_control.csv.gz`).

## Consequences
Numbers from `results/crossframework.md` (realdata run 37092934843); each statement names its
encoder.

- **Nested LOO vs the tuned diagonal.** With TF-IDF, nested LOO equals the tuned diagonal for the
  four text-rich frameworks (CIS, NIST, CRI-2.1, CSA CCM), where the same weights win on every
  fold, and is lower for the four security-stack mappings (AWS 0.231 -> 0.195, Azure 0.200 ->
  0.167, GCP 0.182 -> 0.167, M365 0.457 -> 0.452). With MiniLM it is lower for all eight,
  including CIS (0.550 -> 0.545), CRI-2.1 (0.363 -> 0.333) and CSA CCM (0.393 -> 0.378).
- **Nested LOO vs pooled transfer.** Nested LOO is below pooled for AWS, Azure, GCP and CRI-2.1
  with TF-IDF (0.195/0.167/0.167/0.390 vs 0.204/0.229/0.194/0.416) and for AWS, Azure, GCP and
  CRI-2.1 with MiniLM. None of these survives Holm adjustment; nested LOO is significantly above
  pooled for CIS, NIST and M365 with both encoders.
- **Nested LOO vs zero-shot.** Nested LOO is below the zero-shot bridge for Azure with both
  encoders (TF-IDF 0.167 vs 0.186, paired -0.019 [-0.079, +0.036], Holm p = 1) and for CRI-2.1 with
  MiniLM (0.333 vs 0.354, -0.022 [-0.054, +0.009]): no detectable difference, not a demonstrated
  harm. AWS has even fewer controls (20) than Azure (38), and its nested LOO beats zero-shot.
- **Pooled vs zero-shot.** With TF-IDF the paired interval is above 0 on 6 of 8 frameworks, but
  after Holm adjustment pooled transfer is significant on 4 (AWS, GCP, M365, CSA CCM); NIST and
  CRI-2.1 drop out. With MiniLM the same 4 are significant and Azure (+0.041 [-0.019, +0.107]) is
  not. The pre-specified source therefore helps on the three sparse-text frameworks other than
  Azure and on the text-rich CSA CCM. Most single sources hurt on the text-rich frameworks (5-7 of
  7 below zero-shot, both encoders).
- The TF-IDF IDF of the training texts still includes the held-out control on the diagonal: a
  small transductive effect, documented in `vantage/transfer.py`.
