"""Greedy weighted set-cover: cheapest actions for maximum new technique coverage.

Actions:
  * deploy_detection  - an undeployed rule whose log sources are already ingested (or will be)
  * onboard_log_source - ingest a new source AND deploy every catalog rule it unlocks

Greedy ratio (new techniques / cost) gives the classic ln(n)-approximation for set cover.
"""
from __future__ import annotations

from dataclasses import dataclass

from .coverage import live_detections
from .models import Catalog, OrgPosture


@dataclass(frozen=True)
class Recommendation:
    action: str
    target: str
    cost: float
    new_techniques: tuple[str, ...]
    enables: tuple[str, ...]

    @property
    def ratio(self) -> float:
        return len(self.new_techniques) / self.cost


def _covered(cat: Catalog, deployed: set[str], ingested: set[str]) -> set[str]:
    out: set[str] = set()
    for d in live_detections(cat, deployed, ingested):
        out |= cat.detections[d].techniques
    return out


def recommend(
    cat: Catalog, org: OrgPosture, *, budget: float | None = None, max_steps: int = 10
) -> list[Recommendation]:
    deployed = set(org.deployed_detections)
    ingested = set(org.ingested_log_sources)
    plan: list[Recommendation] = []
    spent = 0.0
    for _ in range(max_steps):
        covered = _covered(cat, deployed, ingested)
        candidates: list[Recommendation] = []
        for did, det in cat.detections.items():
            if did in deployed or not det.requires <= ingested:
                continue
            new = det.techniques - covered
            if new:
                candidates.append(Recommendation("deploy_detection", did, det.cost,
                                                 tuple(sorted(new)), (did,)))
        for lid, ls in cat.log_sources.items():
            if lid in ingested:
                continue
            ing2 = ingested | {lid}
            unlock = {d for d, det in cat.detections.items() if det.requires <= ing2 and lid in det.requires}
            new = _covered(cat, deployed | unlock, ing2) - covered
            if new:
                cost = ls.cost + sum(cat.detections[d].cost for d in unlock if d not in deployed)
                candidates.append(Recommendation("onboard_log_source", lid, cost,
                                                 tuple(sorted(new)), tuple(sorted(unlock))))
        if not candidates:
            break
        best = max(candidates, key=lambda r: (r.ratio, len(r.new_techniques), r.target))
        if budget is not None and spent + best.cost > budget:
            affordable = [c for c in candidates if spent + c.cost <= budget]
            if not affordable:
                break
            best = max(affordable, key=lambda r: (r.ratio, len(r.new_techniques), r.target))
        plan.append(best)
        spent += best.cost
        deployed |= set(best.enables)
        if best.action == "onboard_log_source":
            ingested.add(best.target)
    return plan
