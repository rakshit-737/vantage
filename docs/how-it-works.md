# How it works

VANTAGE answers one question per ATT&CK technique: **is it defended, or only claimed?** This page
follows two real techniques through the pipeline, using the synthetic Acme posture
(`vantage/postures/acme-real.yaml`) on the real catalog: ATT&CK v19.2, the official CIS v8 mapping
and SigmaHQ r2026-07-01. Acme claims CIS IG2, deploys every stable and test Sigma rule, and ingests
only Windows event, cloud, proxy and web logs.

```mermaid
flowchart TB
  C["Claimed control<br/>(CIS / NIST / CTID mapping)"] -- "mitigates" --> T["ATT&CK technique"]
  D["Deployed Sigma rule"] -- "tagged with" --> T
  L["Log source<br/>(ingested?)"] -- "feeds" --> D
```

A technique is **defended** only when all three hold: a claimed control maps to it, a deployed rule
is tagged with it, and every log source that rule reads is ingested. Otherwise it is
`paper_only` (claimed, not detectable), `detected_only` or `blind`. "Defended" is detection-backed
coverage: a technique claimed only by a preventive control may still be blocked, so `paper_only`
means *no detection evidence*, not *exposed*.

Every number on this page is computed by `benchmarks/bench_walkthrough.py`
([results](evaluation.md#6-numbers-on-the-how-it-works-page)).

## Step 1: the claim

The posture says `claimed_controls: ["@ig2"]`. The official CIS workbook maps 7 IG2 safeguards to
**T1055 Process Injection** and 14 to **T1003.001 LSASS Memory**. On paper both are covered, and a
compliance dashboard would colour both green.

## Step 2: the rules

SigmaHQ has rules tagged with both techniques, and Acme deploys all stable and test ones. A
"coverage by ATT&CK tag" view (DeTT&CT-style, ignoring telemetry) would also call both covered.

## Step 3: the telemetry

Each Sigma rule declares a `logsource` (product/category/service), which VANTAGE turns into a
dependency such as `windows/process_creation`. Acme does not ingest Sysmon-class endpoint
telemetry, so:

| Technique | claimed by | live rules | dead rules (deployed, log source missing) | most common missing source | status |
|---|---:|---:|---:|---|---|
| T1003.001 LSASS Memory | 14 safeguards | 7 | 61 | `windows/process_creation` (28) | **defended** |
| T1055 Process Injection | 7 safeguards | 0 | 29 | `windows/process_creation` (12) | **paper_only** |

T1055 is "compliant but blind": every rule that could see it is deployed and dead. Across the
matrix Acme claims 53.9% of techniques but defends 17.6%, with 2,132 dead rules.

![VANTAGE web UI](figures/ui.png)

In the UI each cell is a technique, coloured by status. The side panel lists the claiming
controls and the live and dead rules with the log sources they need.

## Step 4: what breaks, and what to fix first

* **Failure propagation** removes one node and recomputes. In one pass it ranks every log source
  and rule by how many techniques go dark (`vantage failure`), and every claimed control by how
  many techniques lose their only claim (`vantage failure --kind control`). For Acme, losing
  `windows/security` blinds 39 techniques.
* **The recommender** runs greedy budgeted set cover over "onboard a log source (and deploy the
  rules it unlocks)". Onboarding `windows/ps_script` (cost 1.15) unlocks 134 rules and makes 51
  techniques newly detectable; defended coverage rises from 17.6% to 22.0% (123 -> 153
  techniques, +30), because only claimed techniques count as defended. The recommender maximises
  newly *detectable* techniques, not defended ones. On this instance greedy matched an exact ILP
  at every budget tested ([Evaluation](evaluation.md#3-recommender-vs-exact-optimum)).

## Step 5: is the gap real or an artefact of one framework?

The [ablation](evaluation.md#0-ablation-what-each-evidence-requirement-removes) repeats steps 1-3
for 12 framework profiles: CIS IG1-3, NIST SP 800-53B LOW/MODERATE/HIGH, CRI Profile, CSA CCM, and
the AWS, Azure, GCP and M365 security-stack mappings. It does this at every telemetry tier. The
overstatement appears for every framework. With classic Windows logs (T0), most of the gap is
missing telemetry (step 3: tagged rules whose log sources are not ingested), in 11 of 12
profiles. Once Sysmon-class endpoint logs are ingested (T2 and up), most of what remains is
claimed techniques with no tagged SigmaHQ rule at all (step 2).

![where the gap comes from](figures/ablation_shares.png)

The same page reports a detection-only (DeTT&CT-style) view next to defended coverage, and splits
the paper-only techniques by the CIS Security Function of the safeguards that claim them.

## Where the mappings come from

Control-to-technique edges come from official public mappings (see [Datasets](datasets.md)). For a
new framework with no mapping, VANTAGE can suggest one: the mitigation-bridge auto-mapper matches
control text to ATT&CK mitigations, and the TransferMapper adds labels learned from other
frameworks. Both are evaluated in [Evaluation](evaluation.md) and are suggestion tools, not ground
truth.
