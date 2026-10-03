"""Typed contracts. Everything the engines consume is validated here."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class ValidationError(ValueError):
    """Invalid catalog, posture file or selector (the CLI prints it and exits 2)."""


class CoverageStatus(str, Enum):
    """Status of one technique for one org."""
    DEFENDED = "defended"            # control claims it AND live detection covers it
    PAPER_ONLY = "paper_only"        # control claims it, no live detection ("compliant but blind")
    DETECTED_ONLY = "detected_only"  # live detection, but no control claims it
    BLIND = "blind"                  # nothing


@dataclass(frozen=True)
class Technique:
    """An ATT&CK (sub-)technique."""
    id: str
    name: str
    tactic: str
    description: str = ""
    tactics: tuple[str, ...] = ()   # all kill-chain phases (real ATT&CK); tactic is the primary one

    @property
    def all_tactics(self) -> tuple[str, ...]:
        """Every tactic the technique belongs to."""
        return self.tactics or (self.tactic,)

    def __post_init__(self) -> None:
        if not TECHNIQUE_RE.match(self.id):
            raise ValidationError(f"bad ATT&CK technique id: {self.id!r}")


@dataclass(frozen=True)
class Control:
    """A framework control and the techniques its official mapping assigns to it."""
    id: str
    framework: str
    title: str
    mitigates: frozenset[str] = frozenset()
    text: str = ""
    ig: int | None = None             # CIS Implementation Group that first includes the safeguard
    function: str = ""                # CIS security function (Identify/Protect/Detect/Respond/Recover)
    baselines: frozenset[str] = frozenset()  # NIST SP 800-53B baselines (LOW/MODERATE/HIGH/PRIVACY)


@dataclass(frozen=True)
class LogSource:
    """A telemetry source that Sigma rules depend on."""
    id: str
    name: str
    cost: float = 1.0  # relative onboarding cost for the recommender

    def __post_init__(self) -> None:
        if self.cost <= 0:
            raise ValidationError(f"log source {self.id} cost must be > 0")


@dataclass(frozen=True)
class Detection:
    """A detection rule, its techniques and the log sources it needs."""
    id: str
    title: str
    techniques: frozenset[str]
    requires: frozenset[str]  # log source ids (all must be ingested)
    cost: float = 1.0
    level: str = ""           # Sigma level (informational..critical)
    status: str = ""          # Sigma status (stable/test/experimental)

    def __post_init__(self) -> None:
        for t in self.techniques:
            if not TECHNIQUE_RE.match(t):
                raise ValidationError(f"detection {self.id}: bad technique {t!r}")
        if not self.requires:
            raise ValidationError(f"detection {self.id}: requires at least one log source")


@dataclass(frozen=True)
class Segment:
    """A network segment and its criticality (1-3)."""
    name: str
    criticality: int = 1  # 1..3


@dataclass
class ZeroTrustFacts:
    """Declared segmentation and identity facts for the Zero-Trust score."""
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
        """Raise ValidationError for unknown segments or out-of-range values."""
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


@dataclass(frozen=True)
class Mitigation:
    """ATT&CK course-of-action (Mxxxx) and the techniques it mitigates (from STIX relationships)."""
    id: str
    name: str
    description: str
    techniques: frozenset[str]


@dataclass
class Catalog:
    """Techniques, controls, log sources, detections and mitigations, with provenance."""
    techniques: dict[str, Technique]
    controls: dict[str, Control]
    log_sources: dict[str, LogSource]
    detections: dict[str, Detection]
    mitigations: dict[str, Mitigation] = field(default_factory=dict)
    meta: dict = field(default_factory=dict)  # provenance: versions, counts, sources

    def validate(self) -> None:
        """Raise ValidationError if any edge points at an unknown id."""
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
        """Raise ValidationError if the posture names ids the catalog does not have."""
        for kind, ids, known in (
            ("control", org.claimed_controls, self.controls),
            ("log source", org.ingested_log_sources, self.log_sources),
            ("detection", org.deployed_detections, self.detections),
        ):
            unknown = ids - known.keys()
            if unknown:
                raise ValidationError(f"org {org.name}: unknown {kind}(s) {sorted(unknown)}")
        org.zero_trust.validate()
