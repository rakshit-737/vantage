# ADR 0003: In-process graph engines, Neo4j optional via Cypher export

- Status: accepted (unchanged from v0.1, re-validated on real data)
- Date: 2026-09-26

## Context
The spec sketches Neo4j as the graph store. The real catalog is small: 697 techniques, 153
controls, 2,877 rules, 116 log sources: 3,843 nodes and 9,744 edges for the Acme posture.

## Decision
Keep all engines in-process on Python sets and NetworkX. Neo4j stays an optional exploration
target: `python -m vantage graph --format cypher` emits an idempotent, injection-safe MERGE
script, and `docker compose --profile neo4j up` starts a localhost-only Neo4j.

Measured on the real catalog (`results/coverage.md`, part C, realdata run 37092934843 on the
GitHub ubuntu runner): a full coverage computation takes 2.9 ms; ranking every single point of
failure takes 2 ms with the one-pass algorithm, versus 7.7 s by brute-force recomputation, with
identical results (checked in the benchmark and by a property test). On a loaded laptop the
brute-force check took minutes; the one-pass ranking stays in milliseconds.

## Consequences
- Zero infrastructure for users and CI; what-if queries are interactive in the web UI.
- Ad-hoc graph queries need the Cypher export; there is no live Neo4j sync.
