# ADR 0006: FastAPI with a dependency-free vanilla JS UI, localhost-only by default

- Status: accepted
- Date: 2026-09-26

## Context
The spec lists FastAPI and a React ATT&CK heatmap and gap explorer. The output is sensitive: the
coverage map is a list of what an attacker can do unseen.

## Decision
- A FastAPI app (`vantage/api.py`) exposes read-only endpoints: meta, coverage (GET, and POST for
  what-if), technique detail, SPOF ranking, recommendations, Zero-Trust score, auto-map, audit
  report and ATT&CK Navigator layer. What-if bodies are validated by pydantic and never persisted;
  unknown log-source ids are ignored rather than injected.
- The UI is a single static page (HTML, CSS and about 250 lines of vanilla JS) served by the same
  app. There is no build step and no npm supply chain, and it renders the full 15-tactic matrix.
  All data is written with `textContent`, because Sigma rule titles are third-party strings.
- `vantage serve` binds 127.0.0.1 and warns otherwise. If `VANTAGE_API_TOKEN` is set, every /api
  route requires `Authorization: Bearer <token>` (constant-time compare). Docker compose publishes
  on 127.0.0.1 only, with a read-only root filesystem and a non-root user.

## Consequences
- One `pip install` and one command give the heatmap; CI tests the API with TestClient and
  smoke-tests the Docker image.
- React was not used. Nothing in the current UI needs a component framework; this can be
  revisited if the gap explorer grows.
- No multi-user auth or TLS: this is deliberately a local analysis tool.
