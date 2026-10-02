# VANTAGE

**VANTAGE joins your controls, your detections and MITRE ATT&CK into one graph, then shows the
gap between *compliant* and *defensible*.**

**Contribution:** an open, reproducible measurement of how far compliance overstates
defensibility. Each ATT&CK technique is scored as the conjunction of an official control mapping
(CIS v8, NIST SP 800-53B baselines and six CTID frameworks), a deployed SigmaHQ rule, and that
rule's log-source dependencies. Across 12 framework profiles, paper coverage overstates defended
coverage by **24-56 pp** with classic Windows logs and still by **11-27 pp** with every Sigma log
source ([ablation](benchmarks.md#0-ablation-what-each-evidence-requirement-removes)).

[Try the live demo](live-demo.md){ .md-button .md-button--primary }
[How it works](how-it-works.md){ .md-button }
[Evaluation](benchmarks.md){ .md-button }
[Reproduce](reproduce.md){ .md-button }

![VANTAGE web UI](figures/ui.png)

Organisations pass CIS or NIST audits and still get breached, because "we have a control" does
not mean "we can detect the technique it is meant to stop". VANTAGE models the enterprise as a
graph (Control -> Technique <- Detection <- LogSource) with a segmentation/IAM trust layer and
works out which ATT&CK techniques are actually defended and which are covered only on paper.

It runs on real public data: the ATT&CK Enterprise STIX bundle (v19.2), the official CIS
Controls v8 -> ATT&CK mapping, the CTID Mappings Explorer mappings (NIST SP 800-53 rev5, CRI
Profile, CSA CCM, AWS, Azure, GCP, M365), NIST's OSCAL SP 800-53B baselines and the SigmaHQ
ruleset (2,877 ATT&CK-tagged rules).

!!! warning "Lab-only / defensive"
    VANTAGE is a read-only analysis tool that works on a *declared* posture file. It never
    scans, connects to, or changes any system, and it contains no exploit code. The org
    profiles are synthetic. A real posture file and its reports are a map of your blind spots:
    keep them local.

## Headline results

| Finding | Number |
|---|---|
| Paper minus defended coverage, 12 framework profiles (T0 / T5 telemetry) | 24.1-55.7 pp / 10.9-26.5 pp |
| CIS IG2 claimed vs defended, classic Windows logs only | 53.9% vs 11.2% (42.7 pp gap) |
| Same claims, every Sigma log source ingested | 53.9% vs 37.4% (rule-quality weighted 33.5%) |
| All NIST 800-53 rev5 mapped controls claimed, every log source | 66.9% vs 40.3% (26.6 pp gap) |
| Mitigation-bridge auto-mapper (MiniLM) vs official CIS mapping | MAP@200 0.417 [0.357, 0.478] (bge-small 0.412, indistinguishable; prior 0.161) |
| Labels from the 7 other frameworks minus zero-shot (paired) | TF-IDF +0.028 to +0.102 MAP, interval above 0 on 6 of 8 frameworks; MiniLM 4 of 8 |
| NIST SP 800-53B LOW / MODERATE paper coverage | 66.0% / 66.9% of ATT&CK v19.2 |
| Greedy log-source recommender vs exact ILP | equal at all 7 budgets tested |

Details, confidence intervals and figures: [Benchmarks & results](benchmarks.md).
Try the UI: [static demo](live-demo.md).

## Where to go next

- [Getting started](getting-started.md): install, download the data, run the demo.
- [Architecture](architecture.md): the graph model and engines.
- [Datasets](datasets.md): versions, licences and citations.
- [Limitations & roadmap](limitations.md): what the numbers do *not* mean.
