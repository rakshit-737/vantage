"""Failure propagation: knock out one node, recompute, rank single points of failure."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .coverage import compute_coverage, live_detections
from .models import Catalog, OrgPosture


@dataclass(frozen=True)
class FailureImpact:
    kind: str                  # "log_source" | "detection"
    node: str
    techniques_gone_dark: tuple[str, ...]
    pct_of_matrix: float


def simulate_failure(cat: Catalog, org: OrgPosture, kind: str, node: str) -> FailureImpact:
    base = compute_coverage(cat, org).detected_set()
    if kind == "log_source":
        after = compute_coverage(cat, org, ingested=org.ingested_log_sources - {node})
    elif kind == "detection":
        after = compute_coverage(cat, org, deployed=org.deployed_detections - {node})
    else:
        raise ValueError(f"unknown failure kind {kind!r}")
    dark = tuple(sorted(base - after.detected_set()))
    return FailureImpact(kind, node, dark, round(100.0 * len(dark) / len(cat.techniques), 1))


def rank_spofs(cat: Catalog, org: OrgPosture, top: int | None = None) -> list[FailureImpact]:
    """All single-node failures in one pass (O(live rules x techniques/rule)).

    A technique goes dark when node X fails iff every live detection covering it depends on X.
    Equivalent to calling simulate_failure for each node (tested), but fast on the full
    SigmaHQ catalog where there are thousands of deployed rules.
    """
    live = live_detections(cat, org.deployed_detections, org.ingested_log_sources)
    by_tech: dict[str, list[str]] = defaultdict(list)
    for d in live:
        for t in cat.detections[d].techniques:
            by_tech[t].append(d)
    dark: dict[tuple[str, str], set[str]] = defaultdict(set)
    for t, dets in by_tech.items():
        if len(dets) == 1:
            dark[("detection", dets[0])].add(t)
        common = set.intersection(*(set(cat.detections[d].requires) for d in dets))
        for ls in common:
            dark[("log_source", ls)].add(t)
    n = len(cat.techniques)
    impacts = [FailureImpact(k, node, tuple(sorted(ts)), round(100.0 * len(ts) / n, 1))
               for (k, node), ts in dark.items()]
    impacts.sort(key=lambda i: (-len(i.techniques_gone_dark), i.kind, i.node))
    return impacts[:top] if top else impacts
