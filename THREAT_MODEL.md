# Threat model

## Assets
- **Posture file**: claimed controls, ingested log sources, deployed rules, and segmentation/IAM facts.
- **Derived outputs**: coverage heatmap, SPOF list, audit report (Markdown/PDF), Navigator layer, graph exports and API responses. Together these are an explicit list of techniques that go undetected.
- **Downloaded datasets**: ATT&CK STIX, the CIS mapping and SigmaHQ rules. They are public, but their integrity matters because they drive every number.

## Trust boundaries
- The CLI reads local YAML/JSON and writes local files and stdout. Network access: `python -m vantage.download` fetches HTTPS URLs pinned to upstream commits and verifies pinned sha256 digests. The optional embedding mappers (`ml` extra, also reachable via `/api/automap?method=embed|bridge-embed`) download Hugging Face model weights on first use, which `HF_HUB_OFFLINE=1` forbids.
- The optional API (`vantage serve`) is read-only and binds to 127.0.0.1 by default. It always requires a bearer token (`VANTAGE_API_TOKEN`, or a random one printed at start-up; only `VANTAGE_ALLOW_NO_AUTH=1` turns this off) and warns when bound elsewhere.
- Input files and third-party data are untrusted. YAML (posture files and Sigma rules) is parsed with `yaml.safe_load` and never executed. Every id is checked against the catalog (`Catalog.validate_org`). The CIS workbook is read with `openpyxl` in read-only, data-only mode.

## Threats and mitigations (STRIDE-lite)

| Threat | Example | Mitigation |
| --- | --- | --- |
| Information disclosure | Report or API leaks and becomes an attacker's target roadmap | Localhost-only bind, token required by default (constant-time compare), compose publishes on 127.0.0.1, sensitivity banners in the UI and reports. Store outputs as confidential. |
| Tampering (data) | A modified dataset silently changes coverage | sha256 pinning in the downloader; the build records provenance and drop counts in `catalog.meta` |
| Tampering (posture) | Posture file edited to inflate coverage | Out of scope: posture is declared. Roadmap: derive log-source health from SIEM APIs. |
| Malicious input | YAML with Python tags, huge what-if bodies, unknown ids | `safe_load`; request bodies capped at 64 KiB (413); what-if lists capped at 500 items of at most 200 characters (422); unknown what-if log sources ignored; fail-closed on unknown ids in posture files; `defusedxml` for the CIS workbook |
| DNS rebinding | A web page re-points its hostname to 127.0.0.1 and reads the coverage map from the user's browser | `TrustedHostMiddleware`: any `Host` other than localhost or `VANTAGE_ALLOWED_HOSTS` gets 400; the bearer token is also required |
| Clickjacking / content sniffing | The UI is framed or JSON is sniffed as HTML | CSP `default-src 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`; OpenAPI docs off by default |
| XSS | Crafted Sigma rule title rendered in the UI | The UI writes all data with `textContent`, never `innerHTML` |
| Injection | Crafted names in the Cypher export | JSON-escaped literals, labels from a fixed allow-list |
| Denial of service | Expensive auto-map calls | Local single-user tool; query length capped at 4,000 chars and k at 50 |
| Misleading output | Tag-based "detectable" treated as proven detection; auto-map suggestions treated as mappings | Documented in README Limitations and ADR 0005; the seed catalog is labelled illustrative |

## Abuse case
The coverage map shows an attacker which techniques go undetected. VANTAGE is a self-hosted analysis artefact and must never be exposed as a public endpoint.
