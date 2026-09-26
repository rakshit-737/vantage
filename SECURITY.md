# Security policy

## Scope and intended use
VANTAGE is a **defensive, read-only** posture-analysis tool for labs and coursework. It analyses a declared posture file. It does not scan networks, run detections, or contain exploit or offensive code. Bundled data (`examples/`, `vantage/synth.py`) is synthetic.

## Handling outputs
Reports and graph exports produced from a real organisation's posture describe exactly where that organisation is blind. Treat them as confidential. Do not commit them to public repositories, and do not serve them over a network.

## Reporting a vulnerability
Please open a private security advisory on the repository, or email the maintainer, instead of filing a public issue. Include reproduction steps. Expect an acknowledgement within 7 days.

## Supply chain
Runtime dependencies are limited to `networkx` and `PyYAML`. CI runs tests, `ruff`, `bandit` (SAST), and `pip-audit` (dependency CVEs).
