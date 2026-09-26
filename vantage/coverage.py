"""Coverage engine: defended / paper_only / detected_only / blind per technique."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Catalog, CoverageStatus, OrgPosture


def live_detections(cat: Catalog, deployed: set[str], ingested: set[str]) -> set[str]:
    """A detection fires only if deployed AND every required log source is ingested."""
    return {d for d in deployed if cat.detections[d].requires <= ingested}


@dataclass
class CoverageResult:
    status: dict[str, CoverageStatus]
    claimed: dict[str, set[str]]          # technique -> controls claiming it
    detected_by: dict[str, set[str]]      # technique -> live detections
    dead_detections: set[str] = field(default_factory=set)  # deployed but log source missing

    def by_status(self, s: CoverageStatus) -> list[str]:
        return sorted(t for t, v in self.status.items() if v == s)

    @property
    def total(self) -> int:
        return len(self.status)

    def pct(self, s: CoverageStatus) -> float:
        return 100.0 * len(self.by_status(s)) / self.total if self.total else 0.0

    @property
    def claimed_pct(self) -> float:
        """Coverage the org would report on paper (any control claims the technique)."""
        n = sum(1 for t in self.status if self.claimed[t])
        return 100.0 * n / self.total if self.total else 0.0

    @property
    def true_pct(self) -> float:
        return self.pct(CoverageStatus.DEFENDED)

    def detected_set(self) -> set[str]:
        return {t for t, d in self.detected_by.items() if d}

    def summary(self) -> dict:
        return {
            "techniques": self.total,
            "claimed_pct": round(self.claimed_pct, 1),
            "true_pct": round(self.true_pct, 1),
            **{s.value: len(self.by_status(s)) for s in CoverageStatus},
            "dead_detections": sorted(self.dead_detections),
        }


def compute_coverage(
    cat: Catalog,
    org: OrgPosture,
    *,
    ingested: set[str] | None = None,
    deployed: set[str] | None = None,
    controls: set[str] | None = None,
) -> CoverageResult:
    ingested = org.ingested_log_sources if ingested is None else ingested
    deployed = org.deployed_detections if deployed is None else deployed
    controls = org.claimed_controls if controls is None else controls

    live = live_detections(cat, deployed, ingested)
    claimed: dict[str, set[str]] = {t: set() for t in cat.techniques}
    detected: dict[str, set[str]] = {t: set() for t in cat.techniques}
    for cid in controls:
        for t in cat.controls[cid].mitigates:
            claimed[t].add(cid)
    for did in live:
        for t in cat.detections[did].techniques:
            detected[t].add(did)

    status = {}
    for t in cat.techniques:
        c, d = bool(claimed[t]), bool(detected[t])
        status[t] = (
            CoverageStatus.DEFENDED if c and d
            else CoverageStatus.PAPER_ONLY if c
            else CoverageStatus.DETECTED_ONLY if d
            else CoverageStatus.BLIND
        )
    return CoverageResult(status, claimed, detected, set(deployed) - live)
