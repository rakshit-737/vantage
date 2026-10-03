# Security policy

## Scope and intended use
VANTAGE is a **defensive, read-only** posture-analysis tool for labs and coursework. It analyses a declared posture file against public data (MITRE ATT&CK, the CIS v8 mapping, SigmaHQ rules). It does not scan networks, run detections, or contain exploit or offensive code. Org profiles (`examples/`, `vantage/synth.py`) are synthetic.

## Handling outputs
Reports and graph exports produced from a real organisation's posture describe exactly where that organisation is blind. Treat them as confidential. Do not commit them to public repositories, and do not serve them over a network. `vantage serve` binds to 127.0.0.1 by default, always requires a bearer token (`VANTAGE_API_TOKEN`, or a random one it prints), and rejects non-localhost `Host` headers unless they are listed in `VANTAGE_ALLOWED_HOSTS`.

## Reporting a vulnerability
Use GitHub private vulnerability reporting: <https://github.com/rakshit-737/vantage/security/advisories/new> (the "Report a vulnerability" button on the Security tab). Please do not file a public issue. Include reproduction steps. Expect an acknowledgement within 7 days.

## Supply chain
Core runtime dependencies are `networkx` and `PyYAML`. API, report, data and ML features are optional extras. Datasets are fetched from HTTPS URLs pinned to upstream git commits and verified against pinned sha256 digests. The embedding mappers (optional `ml` extra) download Hugging Face model weights on first use; set `HF_HUB_OFFLINE=1` with a pre-populated cache to forbid that. CI runs tests, `ruff`, `bandit` (SAST) and `pip-audit` three ways: over every extra as resolved today, over the declared minimum version of every dependency in every extra pinned exactly (`scripts/min_constraints.py`, so a floor that still admits a vulnerable release fails the build), and over `docker/requirements.lock`. The Docker image installs only that hash-locked file (`pip install --require-hashes`), generated with `uv pip compile --generate-hashes`. GitHub Actions are pinned by commit SHA, the Docker base image by digest, and Dependabot keeps them current. Secret scanning with push protection is enabled.
