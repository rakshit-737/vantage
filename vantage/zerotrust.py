"""Rule-based Zero-Trust posture score (0-100) from segmentation + IAM facts."""
from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from .models import Catalog, ZeroTrustFacts

WEIGHTS = {"segmentation": 0.35, "mfa": 0.25, "privileged_access": 0.2,
           "device_posture": 0.1, "account_hygiene": 0.1}
LATERAL_TACTICS = {"lateral-movement", "discovery"}


@dataclass(frozen=True)
class ZTScore:
    score: float
    components: dict[str, float]
    exposed_lateral_techniques: tuple[str, ...]


def segmentation_score(zt: ZeroTrustFacts) -> float:
    crit = {s.name: s.criticality for s in zt.segments}
    pairs = [frozenset(p) for p in combinations(sorted(crit), 2)]
    if not pairs:
        return 1.0
    weight = lambda p: max(crit[n] for n in p)  # noqa: E731
    total = sum(weight(p) for p in pairs)
    exposed = sum(weight(p) for p in pairs if p in zt.open_flows)
    return 1.0 - exposed / total


def score_zero_trust(zt: ZeroTrustFacts, cat: Catalog | None = None) -> ZTScore:
    zt.validate()
    comps = {
        "segmentation": segmentation_score(zt),
        "mfa": zt.mfa_coverage,
        "privileged_access": (zt.pam_vaulted / zt.privileged_accounts) if zt.privileged_accounts else 1.0,
        "device_posture": 1.0 if zt.device_posture_checks else 0.0,
        "account_hygiene": 1.0 - zt.stale_accounts / zt.total_accounts,
    }
    score = 100.0 * sum(WEIGHTS[k] * v for k, v in comps.items())
    exposed: tuple[str, ...] = ()
    if cat is not None:
        crit = {s.name: s.criticality for s in zt.segments}
        if any(max(crit[n] for n in f) >= 3 for f in zt.open_flows):
            exposed = tuple(sorted(t.id for t in cat.techniques.values() if LATERAL_TACTICS & set(t.all_tactics)))
    return ZTScore(round(score, 1), {k: round(v, 3) for k, v in comps.items()}, exposed)
