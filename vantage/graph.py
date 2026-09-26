"""Tri-partite graph (Control -> Technique <- Detection <- LogSource) in NetworkX.

Neo4j is optional: `to_cypher` emits an idempotent MERGE script you can pipe into
cypher-shell against the docker-compose Neo4j. Runtime never requires Neo4j.
"""
from __future__ import annotations

import json

import networkx as nx

from .coverage import compute_coverage
from .models import Catalog, OrgPosture


def build_graph(cat: Catalog, org: OrgPosture | None = None) -> nx.DiGraph:
    g = nx.DiGraph()
    cov = compute_coverage(cat, org) if org else None
    for t in cat.techniques.values():
        g.add_node(t.id, kind="technique", name=t.name, tactic=t.tactic,
                   status=cov.status[t.id].value if cov else None)
    for c in cat.controls.values():
        g.add_node(c.id, kind="control", name=c.title,
                   claimed=bool(org and c.id in org.claimed_controls))
        for t in c.mitigates:
            g.add_edge(c.id, t, rel="MITIGATES")
    for ls in cat.log_sources.values():
        g.add_node(ls.id, kind="log_source", name=ls.name,
                   ingested=bool(org and ls.id in org.ingested_log_sources))
    for d in cat.detections.values():
        g.add_node(d.id, kind="detection", name=d.title,
                   deployed=bool(org and d.id in org.deployed_detections))
        for t in d.techniques:
            g.add_edge(d.id, t, rel="DETECTS")
        for ls in d.requires:
            g.add_edge(ls, d.id, rel="FEEDS")
    return g


def techniques_reachable_from(g: nx.DiGraph, node: str) -> set[str]:
    return {n for n in nx.descendants(g, node) if g.nodes[n]["kind"] == "technique"}


def to_json(g: nx.DiGraph) -> str:
    return json.dumps(nx.node_link_data(g, edges="links"), indent=2, default=str)


def _q(s: object) -> str:
    return json.dumps(str(s))  # safe string literal for Cypher


_LABEL = {"technique": "Technique", "control": "Control", "log_source": "LogSource",
          "detection": "Detection"}


def to_cypher(g: nx.DiGraph) -> str:
    lines = []
    for n, a in g.nodes(data=True):
        props = ", ".join(f"n.{k} = {_q(v)}" for k, v in a.items() if k != "kind" and v is not None)
        lines.append(f"MERGE (n:{_LABEL[a['kind']]} {{id: {_q(n)}}})" + (f" SET {props};" if props else ";"))
    for u, v, a in g.edges(data=True):
        lines.append(f"MATCH (a {{id: {_q(u)}}}), (b {{id: {_q(v)}}}) MERGE (a)-[:{a['rel']}]->(b);")
    return "\n".join(lines) + "\n"
