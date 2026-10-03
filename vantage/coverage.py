"""Coverage engine: defended / paper_only / detected_only / blind per technique."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Catalog, CoverageStatus, Detection, OrgPosture

# Rule-quality weights (ADR 0007). A tag is not a detection guarantee: a "critical"/"stable"
# rule is treated as more trustworthy than an "informational"/"experimental" one. These are
# assumptions, not measured precision/recall.
LEVEL_WEIGHT = {"critical": 1.0, "high": 0.9, "medium": 0.7, "low": 0.5, "informational": 0.3}
STATUS_WEIGHT = {"stable": 1.0, "test": 0.8, "experimental": 0.6}
DEFAULT_LEVEL_WEIGHT = 0.7
DEFAULT_STATUS_WEIGHT = 0.8


def rule_quality(d: Detection) -> float:
    """Confidence in (0, 1] that a live rule really detects its tagged techniques."""
    return (LEVEL_WEIGHT.get(d.level, DEFAULT_LEVEL_WEIGHT)
            * STATUS_WEIGHT.get(d.status, DEFAULT_STATUS_WEIGHT))


def live_detections(cat: Catalog, deployed: set[str], ingested: set[str]) -> set[str]:
    """A detection fires only if deployed AND every required log source is ingested."""
    return {d for d in deployed if cat.detections[d].requires <= ingested}


@dataclass
class CoverageResult:
    """Per-technique status plus the claims and live rules behind it."""
    status: dict[str, CoverageStatus]
    claimed: dict[str, set[str]]          # technique -> controls claiming it
    detected_by: dict[str, set[str]]      # technique -> live detections
    dead_detections: set[str] = field(default_factory=set)  # deployed but log source missing
    catalog: Catalog | None = field(default=None, repr=False, compare=False)
    _confidence: dict[str, float] | None = field(default=None, repr=False, compare=False)

    @property
    def confidence(self) -> dict[str, float]:
        """technique -> 1 - prod(1 - quality(rule)) over its live rules (computed lazily)."""
        if self._confidence is None:
            conf = {}
            for t, ds in self.detected_by.items():
                miss = 1.0
                for did in ds:
                    miss *= 1.0 - (rule_quality(self.catalog.detections[did]) if self.catalog else 1.0)
                conf[t] = 1.0 - miss
            self._confidence = conf
        return self._confidence

    def by_status(self, s: CoverageStatus) -> list[str]:
        """Technique ids with status ``s``, sorted."""
        return sorted(t for t, v in self.status.items() if v == s)

    @property
    def total(self) -> int:
        """Number of techniques scored."""
        return len(self.status)

    def pct(self, s: CoverageStatus) -> float:
        """Share of techniques with status ``s``, in percent."""
        return 100.0 * len(self.by_status(s)) / self.total if self.total else 0.0

    @property
    def claimed_pct(self) -> float:
        """Coverage the org would report on paper (any control claims the technique)."""
        n = sum(1 for t in self.status if self.claimed[t])
        return 100.0 * n / self.total if self.total else 0.0

    @property
    def true_pct(self) -> float:
        """Defended (claimed AND detectable) share, in percent."""
        return self.pct(CoverageStatus.DEFENDED)

    @property
    def weighted_true_pct(self) -> float:
        """Defended coverage where each claimed technique counts by its detection confidence
        (noisy-OR of live rule qualities) instead of 0/1."""
        if not self.total:
            return 0.0
        return 100.0 * sum(self.confidence.get(t, 0.0) for t in self.status if self.claimed[t]) / self.total

    def detected_set(self) -> set[str]:
        """Techniques with at least one live rule, whatever is claimed."""
        return {t for t, d in self.detected_by.items() if d}

    def summary(self) -> dict:
        """Rounded headline numbers, status counts and dead rules (CLI and API output)."""
        return {
            "techniques": self.total,
            "claimed_pct": round(self.claimed_pct, 1),
            "true_pct": round(self.true_pct, 1),
            "weighted_true_pct": round(self.weighted_true_pct, 1),
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
    """Score every technique; keyword overrides replace the org's ingested, deployed or claimed sets."""
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
    return CoverageResult(status, claimed, detected, set(deployed) - live, cat)
