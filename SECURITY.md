# Security policy

## Scope and intended use
VANTAGE is a **defensive, read-only** posture-analysis tool for labs and coursework. It analyses a declared posture file against public data (MITRE ATT&CK, the CIS v8 mapping, SigmaHQ rules). It does not scan networks, run detections, or contain exploit or offensive code. Org profiles (`examples/`, `vantage/synth.py`) are synthetic.

## Handling outputs
Reports and graph exports produced from a real organisation's posture describe exactly where that organisation is blind. Treat them as confidential. Do not commit them to public repositories, and do not serve them over a network. `vantage serve` binds to 127.0.0.1 by default; set `VANTAGE_API_TOKEN` if you bind it anywhere else.

## Reporting a vulnerability
Please open a private security advisory on the repository, or email the maintainer, instead of filing a public issue. Include reproduction steps. Expect an acknowledgement within 7 days.

## Supply chain
Core runtime dependencies are `networkx` and `PyYAML`. API, report, data and ML features are optional extras. Datasets are fetched from fixed URLs and verified against pinned sha256 digests. CI runs tests, `ruff`, `bandit` (SAST), and `pip-audit` (dependency CVEs).
