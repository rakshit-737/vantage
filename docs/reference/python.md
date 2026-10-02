# Python API

The engines are plain functions over a typed `Catalog` and an `OrgPosture`.

```python
from vantage.catalog import load_catalog
from vantage.coverage import compute_coverage
from vantage.io import load_org
from vantage.selectors import expand_org

cat = load_catalog("real")          # or "seed", "nist", or a catalog JSON path
org = expand_org(cat, load_org("vantage/postures/acme-real.yaml"))
cov = compute_coverage(cat, org)
print(cov.summary())
```

::: vantage.models

::: vantage.coverage

::: vantage.failure

::: vantage.recommend

::: vantage.zerotrust

::: vantage.selectors

::: vantage.automap
    options:
      members: [TfidfMapper, EmbeddingMapper, MitigationBridgeMapper, RandomBaseline, PopularityBaseline, evaluate_mapper, per_control_scores, bootstrap_ci]

::: vantage.ingest.nist
