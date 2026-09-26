"""YAML (de)serialisation of org posture files."""
from __future__ import annotations

from pathlib import Path

import yaml

from .models import OrgPosture, Segment, ValidationError, ZeroTrustFacts

_ZT_SCALARS = ("mfa_coverage", "privileged_accounts", "pam_vaulted",
               "device_posture_checks", "stale_accounts", "total_accounts")


def org_from_dict(d: dict) -> OrgPosture:
    if not isinstance(d, dict) or "name" not in d:
        raise ValidationError("org file must be a mapping with a 'name'")
    zt_raw = d.get("zero_trust") or {}
    zt = ZeroTrustFacts(
        segments=[Segment(s["name"], int(s.get("criticality", 1))) for s in zt_raw.get("segments", [])],
        open_flows={frozenset(f) for f in zt_raw.get("open_flows", [])},
        **{k: zt_raw[k] for k in _ZT_SCALARS if k in zt_raw},
    )
    return OrgPosture(
        name=str(d["name"]),
        claimed_controls=set(d.get("claimed_controls", [])),
        ingested_log_sources=set(d.get("ingested_log_sources", [])),
        deployed_detections=set(d.get("deployed_detections", [])),
        zero_trust=zt,
    )


def org_to_dict(org: OrgPosture) -> dict:
    zt = org.zero_trust
    return {
        "name": org.name,
        "claimed_controls": sorted(org.claimed_controls),
        "ingested_log_sources": sorted(org.ingested_log_sources),
        "deployed_detections": sorted(org.deployed_detections),
        "zero_trust": {
            "segments": [{"name": s.name, "criticality": s.criticality} for s in zt.segments],
            "open_flows": sorted(sorted(f) for f in zt.open_flows),
            **{k: getattr(zt, k) for k in _ZT_SCALARS},
        },
    }


def load_org(path: str | Path) -> OrgPosture:
    with open(path, encoding="utf-8") as fh:
        return org_from_dict(yaml.safe_load(fh))


def save_org(org: OrgPosture, path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(org_to_dict(org), fh, sort_keys=False)
