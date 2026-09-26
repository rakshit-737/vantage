# HTTP API

`python -m vantage serve` binds to 127.0.0.1. Set `VANTAGE_API_TOKEN` to require
`Authorization: Bearer <token>`; the UI reads the token from `#token=...` in the URL. OpenAPI docs
are served at `/api/docs`.

| Method | Path | Body / query | Returns |
|---|---|---|---|
| GET | `/api/meta` | | Catalog counts, log sources (ingested flag, rule count), controls |
| GET | `/api/coverage` | | Summary, ATT&CK matrix, per-tactic table, Zero-Trust score |
| POST | `/api/coverage` | `WhatIf` | Same, after hypothetical changes |
| GET | `/api/technique/{id}` | | Status, claiming controls, live and dead rules, sub-techniques |
| POST | `/api/failure` | `WhatIf`, `?top=` | SPOF ranking |
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
