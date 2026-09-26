# ADR 0002: Carry the CIS v8.2-era mapping forward to ATT&CK v19.2

- Status: accepted
- Date: 2026-09-26

## Context
The only official CIS v8 -> ATT&CK mapping targets ATT&CK v8.2 (2021). Sigma rules are tagged
with current technique ids. Joining them naively would silently drop every technique that MITRE
has since revoked (merged into another id) and would count deprecated techniques as "blind".

## Decision
`AttackData.resolve()` follows STIX `revoked-by` relationships in the v19.2 bundle (transitively)
and drops ids that are deprecated or unknown. The same resolver normalises Sigma tags. The build
records what happened in `catalog.meta.cis`:

- 2,962 (safeguard, technique) pairs in the workbook
- 2,814 unchanged, 134 carried forward through revoked-by, 14 dropped (deprecated)
- 2,919 unique pairs after forwarding (merges collapse duplicates)

The auto-mapper benchmark is reported twice: on the exact v8.2 universe (labels as published)
and on v19.2 with forwarded labels.

## Consequences
- No silent loss of mappings; the drop count is visible in every build.
- Techniques added to ATT&CK after v8.2 (for example the v19 `stealth` / `defense-impairment`
  split and new cloud techniques) have no CIS mapping, so claimed coverage is capped at about 54%
  of the current matrix even for an org claiming every IG3 safeguard. We report this as a finding
  rather than inventing mappings.
