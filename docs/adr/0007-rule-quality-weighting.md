# ADR 0007: Rule-quality weighting of the defended score

- Status: accepted (v1.0.0)
- Date: 2026-09-26

## Context
"Defended" is binary: a technique counts once a claimed control mitigates it and at least one
live Sigma rule is tagged with it. A single `informational`/`experimental` rule and ten
`critical`/`stable` rules score the same. The roadmap asked for rule quality in the score.

## Decision
Keep the binary `true_pct` as the headline, and add `weighted_true_pct` next to it:

- Rule quality `q = level_weight x status_weight`, with level weights critical 1.0, high 0.9,
  medium 0.7, low 0.5, informational 0.3 (unknown 0.7) and status weights stable 1.0, test 0.8,
  experimental 0.6 (unknown 0.8).
- Technique confidence is a noisy-OR over its live rules: `1 - prod(1 - q)`.
- `weighted_true_pct` = sum of confidence over *claimed* techniques / all techniques.

It is computed lazily, so plain coverage passes (and the SPOF ranking) cost nothing extra.

## Consequences
- `weighted_true_pct <= true_pct` always. On the real catalog it sits 2.5-4 pp below the binary
  score (for example CIS IG2 with every log source: 37.4% binary, 33.5% weighted).
- The weights are assumptions, not measured precision/recall. Sigma `falsepositives` notes are
  free text and are not used. Treat the number as a sensitivity check, not a detection-quality
  measurement.
