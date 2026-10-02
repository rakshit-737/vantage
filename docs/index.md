# VANTAGE

**VANTAGE joins your controls, your detections and MITRE ATT&CK into one graph, then shows the
gap between *compliant* and *defensible*.**

Organisations pass CIS or NIST audits and still get breached, because "we have a control" does
not mean "we can detect the technique it is meant to stop". VANTAGE models the enterprise as a
graph (Control -> Technique <- Detection <- LogSource) with a segmentation/IAM trust layer and
works out which ATT&CK techniques are actually defended and which are covered only on paper.

It runs on real public data: the ATT&CK Enterprise STIX bundle (v19.2), the official CIS
Controls v8 -> ATT&CK mapping, the CTID NIST SP 800-53 rev5 -> ATT&CK mapping and the SigmaHQ
ruleset (2,877 ATT&CK-tagged rules).

!!! warning "Lab-only / defensive"
    VANTAGE is a read-only analysis tool that works on a *declared* posture file. It never
    scans, connects to, or changes any system, and it contains no exploit code. The org
    profiles are synthetic. A real posture file and its reports are a map of your blind spots:
    keep them local.

## Headline results

| Finding | Number |
|---|---|
| CIS IG2 claimed vs defended, classic Windows logs only | 53.9% vs 11.2% (42.7 pp gap) |
| Same claims, every Sigma log source ingested | 53.9% vs 37.4% (rule-quality weighted 33.5%) |
| All NIST 800-53 rev5 mapped controls claimed, every log source | 66.9% vs 40.3% (26.6 pp gap) |
| Best auto-mapper (mitigation bridge, MiniLM) vs official CIS mapping | MAP@200 0.417 (popularity prior 0.161) |
| Greedy log-source recommender vs exact ILP | equal at all 7 budgets tested |

Details, confidence intervals and figures: [Benchmarks & results](benchmarks.md).
Try the UI: [static demo](live-demo.md).

## Where to go next

- [Getting started](getting-started.md): install, download the data, run the demo.
- [Architecture](architecture.md): the graph model and engines.
- [Datasets](datasets.md): versions, licences and citations.
- [Limitations & roadmap](limitations.md): what the numbers do *not* mean.
