"""Typed contracts. Everything the engines consume is validated here."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class ValidationError(ValueError):
    pass


class CoverageStatus(str, Enum):
    DEFENDED = "defended"            # control claims it AND live detection covers it
    PAPER_ONLY = "paper_only"        # control claims it, no live detection ("compliant but blind")
    DETECTED_ONLY = "detected_only"  # live detection, but no control claims it
    BLIND = "blind"                  # nothing


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    description: str = ""

    def __post_init__(self) -> None:
        if not TECHNIQUE_RE.match(self.id):
            raise ValidationError(f"bad ATT&CK technique id: {self.id!r}")


@dataclass(frozen=True)
class Control:
    id: str
    framework: str
    title: str
    mitigates: frozenset[str] = frozenset()
    text: str = ""


@dataclass(frozen=True)
class LogSource:
    id: str
    name: str
    cost: float = 1.0  # relative onboarding cost for the recommender

    def __post_init__(self) -> None:
        if self.cost <= 0:
            raise ValidationError(f"log source {self.id} cost must be > 0")


@dataclass(frozen=True)
class Detection:
    id: str
    title: str
    techniques: frozenset[str]
    requires: frozenset[str]  # log source ids (all must be ingested)
    cost: float = 1.0

    def __post_init__(self) -> None:
        for t in self.techniques:
            if not TECHNIQUE_RE.match(t):
                raise ValidationError(f"detection {self.id}: bad technique {t!r}")
        if not self.requires:
            raise ValidationError(f"detection {self.id}: requires at least one log source")


@dataclass(frozen=True)
class Segment:
    name: str
    criticality: int = 1  # 1..3


@dataclass
class ZeroTrustFacts:
    segments: list[Segment] = field(default_factory=list)
    # pairs of segment names allowed to talk freely (flat network = many pairs)
    open_flows: set[frozenset[str]] = field(default_factory=set)
    mfa_coverage: float = 0.0          # fraction of users with MFA, 0..1
    privileged_accounts: int = 0
    pam_vaulted: int = 0               # privileged accounts under PAM
    device_posture_checks: bool = False
    stale_accounts: int = 0
    total_accounts: int = 1

    def validate(self) -> None:
        names = {s.name for s in self.segments}
        for flow in self.open_flows:
            if len(flow) != 2 or not flow <= names:
                raise ValidationError(f"open flow {set(flow)} references unknown segment")
        if not 0.0 <= self.mfa_coverage <= 1.0:
            raise ValidationError("mfa_coverage must be in [0,1]")
        if self.pam_vaulted > self.privileged_accounts:
            raise ValidationError("pam_vaulted cannot exceed privileged_accounts")
        if self.total_accounts < 1 or self.stale_accounts > self.total_accounts:
            raise ValidationError("invalid account counts")


@dataclass
class OrgPosture:
    """What the org *claims* and what is actually live."""
    name: str
    claimed_controls: set[str]
    ingested_log_sources: set[str]
    deployed_detections: set[str]
    zero_trust: ZeroTrustFacts = field(default_factory=ZeroTrustFacts)


@dataclass
class Catalog:
    techniques: dict[str, Technique]
    controls: dict[str, Control]
    log_sources: dict[str, LogSource]
    detections: dict[str, Detection]

    def validate(self) -> None:
        for c in self.controls.values():
            missing = c.mitigates - self.techniques.keys()
            if missing:
                raise ValidationError(f"control {c.id} maps unknown techniques {sorted(missing)}")
        for d in self.detections.values():
            if d.techniques - self.techniques.keys():
                raise ValidationError(f"detection {d.id} maps unknown techniques")
            if d.requires - self.log_sources.keys():
                raise ValidationError(f"detection {d.id} requires unknown log source")

    def validate_org(self, org: OrgPosture) -> None:
        for kind, ids, known in (
            ("control", org.claimed_controls, self.controls),
            ("log source", org.ingested_log_sources, self.log_sources),
            ("detection", org.deployed_detections, self.detections),
        ):
            unknown = ids - known.keys()
            if unknown:
                raise ValidationError(f"org {org.name}: unknown {kind}(s) {sorted(unknown)}")
        org.zero_trust.validate()
