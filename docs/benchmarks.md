# Evaluation

All numbers come from `benchmarks/*.py` on ATT&CK v19.2 (697 techniques), CIS v8 (153
safeguards), NIST SP 800-53 rev5 (109 mapped controls) and SigmaHQ r2026-07-01 (2,877 rules over
116 log sources). The tables below are included verbatim from `results/*.md`, which the scripts
regenerate.

Exact commands, expected outputs and measured runtimes are on the [Reproduce](reproduce.md) page.

Randomness is seeded everywhere (synthetic orgs: seeds 0-24 per maturity level; random mapping
baseline: 10 seeds; bootstrap: 1,000 resamples, seed 0). Only timings vary between runs, and
they depend on machine load.

## Methodology

**Statuses.** A technique is *claimed* if a claimed control maps to it, *detectable* if a deployed
Sigma rule tagged with it has all of its log sources ingested, and *defended* if both hold.
Percentages are over the 697 ATT&CK v19.2 (sub-)techniques. Parents and sub-techniques are scored
separately.

**Telemetry tiers** (cumulative; patterns are matched against the Sigma log-source ids):

| tier | adds |
|---|---|
| T0 | `windows/security`, `windows/system`, `windows/application` |
| T1 | PowerShell: `windows/ps_script`, `windows/ps_module`, `windows/powershell-classic`, `windows/ps_classic_*` |
| T2 | Sysmon/EDR-class Windows categories (`process_creation`, `registry_*`, `file_*`, `image_load`, `network_connection`, `dns_query`, `process_access`, ...) |
| T3 | cloud and identity audit: `aws/*`, `azure/*`, `gcp/*`, `m365/*`, `okta/*`, `github/*`, `google_workspace/*`, `onelogin/*` |
| T4 | `proxy`, `dns`, `firewall`, `webserver`, `zeek/*`, `linux*`, `macos/*`, `antivirus` |
| T5 | every Sigma log source (116) |

**Profiles.** Deterministic profiles claim every control up to a CIS Implementation Group, an SP
800-53B baseline, or every mapped control of a CTID framework. They deploy every *stable* and
*test* Sigma rule (2,614 of 2,877). **Synthetic orgs** (`vantage.synth.random_org`, seeds 0-24 per
level) draw each item independently at maturity m (0.2, 0.4, 0.6, 0.8): claim a control with
probability 0.4 + 0.6m, ingest a log source with 0.2 + 0.7m, and deploy a rule with 0.3 + 0.6m.
Claims are deliberately inflated relative to telemetry, to model the paper-vs-real gap.

**Auto-mapping metrics.** For each control with at least one gold technique, the mapper ranks
techniques. P@k is the share of the top k that are gold, R@k is the share of gold found in the top
k, and AP@200 is average precision to depth 200, normalised by min(|gold|, 200). Values are
macro-averaged over controls (MAP@200). Label-using mappers are scored leave-one-control-out;
in-framework transfer is *nested* leave-one-out.

**Intervals.** Auto-mapping uses 95% percentile bootstraps over controls (1,000 resamples, seed 0),
and differences between mappers use paired bootstraps over the same controls (2,000 resamples).
Synthetic orgs use t-intervals of the mean gap over 25 orgs. The ablation range shows the
sensitivity to the rule set: a random 10% of the rules is removed, 500 draws. A with-replacement
bootstrap is not used there, because coverage depends on *distinct* rules.

**Threats to validity.** A Sigma tag is not proof of detection quality. Mappings were authored
against older ATT&CK releases and are carried forward through revoked-by links. CIS and CTID built
their mappings through ATT&CK mitigations, which favours the mitigation bridge. All postures are
synthetic.

## 0. Ablation: what each evidence requirement removes

![ablation](figures/ablation.png)

--8<-- "results/ablation.md"

## 1. Paper vs real coverage

![paper vs real coverage](figures/coverage_gap.png)

--8<-- "results/coverage.md"

## 2. Auto-mapping controls to ATT&CK

Each mapper sees only the safeguard's title and description. Ground truth is the official CIS v8
-> ATT&CK v8.2 mapping (105 mapped safeguards).

![auto-mapping](figures/automap.png)

--8<-- "results/automap.md"

## 3. Recommender vs exact optimum

![recommender](figures/recommend.png)

--8<-- "results/recommend.md"

## 4. Cross-framework comparison and transfer (round 3)

Frameworks side by side in ATT&CK v19.2, SP 800-53B baselines, and auto-mapping trained on one
framework and tested on another ([ADR 0009](adr/0009-cross-framework-transfer.md)).

![cross-framework transfer](figures/crossframework.png)

--8<-- "results/crossframework.md"

## 5. Comparison with published work

--8<-- "results/published.md"
