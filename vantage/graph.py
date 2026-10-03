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
    """Control -> Technique <- Detection <- LogSource graph, with org state as node attributes."""
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
    """Technique nodes downstream of ``node``."""
    return {n for n in nx.descendants(g, node) if g.nodes[n]["kind"] == "technique"}


def to_json(g: nx.DiGraph) -> str:
    """Node-link JSON of the graph."""
    return json.dumps(nx.node_link_data(g, edges="links"), indent=2, default=str)


def _q(s: object) -> str:
    """Cypher literal: booleans and numbers stay typed, everything else is a JSON-escaped string."""
    if isinstance(s, bool):
        return "true" if s else "false"
    if isinstance(s, (int, float)):
        return json.dumps(s)
    return json.dumps(str(s))


_LABEL = {"technique": "Technique", "control": "Control", "log_source": "LogSource",
          "detection": "Detection"}


def to_cypher(g: nx.DiGraph) -> str:
    """Idempotent Cypher script: uniqueness constraints, MERGE per node, labelled MATCH per edge."""
    lines = [f"CREATE CONSTRAINT {lab.lower()}_id IF NOT EXISTS FOR (n:{lab}) REQUIRE n.id IS UNIQUE;"
             for lab in _LABEL.values()]
    for n, a in g.nodes(data=True):
        props = ", ".join(f"n.{k} = {_q(v)}" for k, v in a.items() if k != "kind" and v is not None)
        lines.append(f"MERGE (n:{_LABEL[a['kind']]} {{id: {_q(n)}}})" + (f" SET {props};" if props else ";"))
    for u, v, a in g.edges(data=True):
        lu, lv = _LABEL[g.nodes[u]["kind"]], _LABEL[g.nodes[v]["kind"]]
        lines.append(f"MATCH (a:{lu} {{id: {_q(u)}}}), (b:{lv} {{id: {_q(v)}}}) MERGE (a)-[:{a['rel']}]->(b);")
    return "\n".join(lines) + "\n"
