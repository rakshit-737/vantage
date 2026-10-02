# HTTP API

`python -m vantage serve` binds to 127.0.0.1 and requires `Authorization: Bearer <token>` on every
`/api` route. The token is `VANTAGE_API_TOKEN`, or a random one printed at start-up as a
`http://127.0.0.1:8000/#token=...` link; the UI reads it from the URL fragment. `Host` headers
other than localhost (or `VANTAGE_ALLOWED_HOSTS`) get 400. Bodies over 64 KiB get 413, and ids
over 200 characters get 422. OpenAPI docs are served at `/api/docs` only when `VANTAGE_API_DOCS=1`.

| Method | Path | Body / query | Returns |
|---|---|---|---|
| GET | `/api/meta` | | Catalog counts, log sources (ingested flag, rule count), controls |
| GET | `/api/coverage` | | Summary, ATT&CK matrix, per-tactic table, Zero-Trust score |
| POST | `/api/coverage` | `WhatIf` | Same, after hypothetical changes |
| GET | `/api/technique/{id}` | | Status, claiming controls, live and dead rules, sub-techniques |
| POST | `/api/failure` | `WhatIf`, `?top=&kind=detection\|control` | SPOF ranking (detection side, or claimed controls) |
| POST | `/api/recommend` | `WhatIf`, `?steps=&log_sources_only=` | Greedy plan |
| GET | `/api/zt` | | Zero-Trust breakdown |
| GET | `/api/automap` | `?text=&k=&method=` | Ranked techniques for control prose |
| GET | `/api/report` | | Markdown audit report |
| GET | `/api/navigator` | | ATT&CK Navigator layer |
| GET | `/healthz` | | `{"ok": true}` |

`WhatIf` (never persisted):

```json
{"disable_log_sources": [], "enable_log_sources": [], "disable_controls": [], "deploy_all_rules": false}
```

Each list is capped at 500 entries. Unknown log sources in `enable_log_sources` are ignored.
