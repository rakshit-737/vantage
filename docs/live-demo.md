# Live demo (static)

[Open the static heatmap demo](demo/index.html){ .md-button .md-button--primary }

The demo is the real VANTAGE web UI, pre-rendered by `scripts/export_demo.py` from the API's own
responses for the **synthetic** Acme posture on the real catalog (ATT&CK v19.2, official CIS v8
mapping, SigmaHQ r2026-07-01). It holds only ids, names, counts and Sigma rule titles (about
0.7 MB of JSON and the pre-rendered report).

What works: the ATT&CK matrix with status colours and sub-technique bars, status filters, the
technique panel (claiming controls by id, live and dead rules), single points of failure, the
cheapest log-source wins, and downloads of the audit report and the ATT&CK Navigator layer
(pre-rendered files next to the page).

What needs the local API: what-if log-source toggles and auto-mapping. Run
`python -m vantage serve --catalog real` for those.

![VANTAGE web UI](figures/ui.png)
