"""Load the Cypher export of the seed catalog + demo org into a throwaway Neo4j and check that a
Cypher query for *defended* techniques returns exactly what ``compute_coverage`` says.

Runs in CI against a Neo4j service container bound to localhost inside the runner:

    python scripts/neo4j_check.py --uri bolt://127.0.0.1:7687 --password <pw> --out neo4j-check.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vantage.catalog import load_catalog  # noqa: E402
from vantage.coverage import compute_coverage  # noqa: E402
from vantage.graph import build_graph, to_cypher  # noqa: E402
from vantage.models import CoverageStatus  # noqa: E402
from vantage.synth import demo_org  # noqa: E402

# A technique is defended when a claimed control mitigates it AND a deployed rule detects it
# whose every required log source is ingested.
DEFENDED = """
MATCH (t:Technique)
WHERE EXISTS { MATCH (c:Control {claimed: true})-[:MITIGATES]->(t) }
  AND EXISTS {
    MATCH (d:Detection {deployed: true})-[:DETECTS]->(t)
    WHERE NOT EXISTS { MATCH (ls:LogSource {ingested: false})-[:FEEDS]->(d) }
  }
RETURN t.id AS id ORDER BY id
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--uri", default="bolt://127.0.0.1:7687")
    ap.add_argument("--user", default="neo4j")
    ap.add_argument("--password", required=True)
    ap.add_argument("--out", default="neo4j-check.json")
    a = ap.parse_args()
    from neo4j import GraphDatabase

    cat, org = load_catalog("seed"), demo_org()
    script = to_cypher(build_graph(cat, org))
    drv = GraphDatabase.driver(a.uri, auth=(a.user, a.password))
    for _ in range(60):
        try:
            drv.verify_connectivity()
            break
        except Exception:  # noqa: BLE001 - service still starting
            time.sleep(2)
    t0 = time.perf_counter()
    with drv.session() as s:
        s.run("MATCH (n) DETACH DELETE n").consume()
        for stmt in filter(None, (x.strip().rstrip(";") for x in script.splitlines())):
            s.run(stmt).consume()
        got = [r["id"] for r in s.run(DEFENDED)]
        nodes = s.run("MATCH (n) RETURN count(n) AS n").single()["n"]
        rels = s.run("MATCH ()-[r]->() RETURN count(r) AS n").single()["n"]
    drv.close()
    want = sorted(compute_coverage(cat, org).by_status(CoverageStatus.DEFENDED))
    res = {"nodes": nodes, "relationships": rels, "defended_cypher": got, "defended_python": want,
           "match": got == want, "load_and_query_s": round(time.perf_counter() - t0, 2)}
    Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if not k.startswith("defended")} | {"defended": len(got)}))
    return 0 if res["match"] else 1


if __name__ == "__main__":
    sys.exit(main())
