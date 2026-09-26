"""Failure propagation: knock out one node, recompute, rank single points of failure."""
from __future__ import annotations

from dataclasses import dataclass

from .coverage import compute_coverage
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
    impacts = [simulate_failure(cat, org, "log_source", ls) for ls in org.ingested_log_sources]
    impacts += [simulate_failure(cat, org, "detection", d) for d in org.deployed_detections]
    impacts = [i for i in impacts if i.techniques_gone_dark]
    impacts.sort(key=lambda i: (-len(i.techniques_gone_dark), i.kind, i.node))
    return impacts[:top] if top else impacts
