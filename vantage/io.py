"""YAML (de)serialisation of org posture files.

Field types are checked here, so a malformed posture file gives one ``ValidationError`` naming the
file and the field instead of a ``TypeError`` deep inside an engine.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .models import OrgPosture, Segment, ValidationError, ZeroTrustFacts

_LISTS = ("claimed_controls", "ingested_log_sources", "deployed_detections")
_ZT_SCALARS = ("mfa_coverage", "privileged_accounts", "pam_vaulted",
               "device_posture_checks", "stale_accounts", "total_accounts")
_ZT_TYPES = {"mfa_coverage": (int, float), "privileged_accounts": (int,), "pam_vaulted": (int,),
             "device_posture_checks": (bool,), "stale_accounts": (int,), "total_accounts": (int,)}


def _str_list(raw: object, field: str) -> set[str]:
    if raw is None:
        return set()
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ValidationError(f"{field!r} must be a list of strings, e.g. [\"@ig2\", CIS-8.2]")
    return set(raw)


def _segments(raw: object) -> list[Segment]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValidationError("'zero_trust.segments' must be a list of mappings, "
                              "e.g. [{name: finance, criticality: 3}]")
    out = []
    for s in raw:
        if not isinstance(s, dict) or not isinstance(s.get("name"), str):
            raise ValidationError("each 'zero_trust.segments' entry must be a mapping with a string 'name', "
                                  "e.g. {name: finance, criticality: 3}")
        crit = s.get("criticality", 1)
        if isinstance(crit, bool) or not isinstance(crit, int):
            raise ValidationError(f"segment {s['name']!r}: 'criticality' must be an integer (1-3)")
        out.append(Segment(s["name"], crit))
    return out


def _flows(raw: object) -> set[frozenset[str]]:
    if raw is None:
        return set()
    if not isinstance(raw, list) or not all(
            isinstance(f, list) and len(f) == 2 and all(isinstance(x, str) for x in f) for f in raw):
        raise ValidationError("'zero_trust.open_flows' must be a list of [segment, segment] pairs")
    return {frozenset(f) for f in raw}


def org_from_dict(d: object) -> OrgPosture:
    """Build an ``OrgPosture`` from parsed YAML, checking every field's type."""
    if not isinstance(d, dict) or "name" not in d:
        raise ValidationError("org file must be a mapping with a 'name'")
    zt_raw = d.get("zero_trust") or {}
    if not isinstance(zt_raw, dict):
        raise ValidationError("'zero_trust' must be a mapping (segments, open_flows, mfa_coverage, ...)")
    scalars = {}
    for k in _ZT_SCALARS:
        if k in zt_raw:
            v = zt_raw[k]
            ok = _ZT_TYPES[k]
            if (isinstance(v, bool) and bool not in ok) or not isinstance(v, ok):
                kind = "true/false" if bool in ok else "a number" if float in ok else "an integer"
                raise ValidationError(f"'zero_trust.{k}' must be {kind}, got {v!r}")
            scalars[k] = v
    zt = ZeroTrustFacts(segments=_segments(zt_raw.get("segments")), open_flows=_flows(zt_raw.get("open_flows")),
                        **scalars)
    return OrgPosture(
        name=str(d["name"]),
        claimed_controls=_str_list(d.get("claimed_controls"), "claimed_controls"),
        ingested_log_sources=_str_list(d.get("ingested_log_sources"), "ingested_log_sources"),
        deployed_detections=_str_list(d.get("deployed_detections"), "deployed_detections"),
        zero_trust=zt,
    )


def org_to_dict(org: OrgPosture) -> dict:
    """Inverse of ``org_from_dict`` (sorted, so the YAML is stable)."""
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
    """Read a posture YAML file. Syntax and type errors raise ``ValidationError`` naming the file."""
    with open(path, encoding="utf-8") as fh:
        try:
            raw = yaml.safe_load(fh)
        except yaml.YAMLError as e:
            raise ValidationError(f"{path}: invalid YAML: {' '.join(str(e).split())}") from e
    try:
        return org_from_dict(raw)
    except ValidationError as e:
        raise ValidationError(f"{path}: {e}") from e


def save_org(org: OrgPosture, path: str | Path) -> None:
    """Write a posture YAML file."""
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(org_to_dict(org), fh, sort_keys=False)
