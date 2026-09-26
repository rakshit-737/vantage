"""Posture-file selectors so real-catalog org files stay short.

claimed_controls:      "@ig1" / "@ig2" / "@ig3" (all CIS safeguards up to that Implementation
                       Group), "@all", or glob patterns such as "CIS-8.*".
ingested_log_sources:  "@all" or globs such as "windows/*", "aws/cloudtrail".
deployed_detections:   "@all", "@status:stable", "@min-level:high", or globs over rule ids.
Several "@..." terms in one entry are AND-ed with "&": "@status:stable&@min-level:medium".
Plain ids pass through unchanged (and are validated by Catalog.validate_org).
"""
from __future__ import annotations

from fnmatch import fnmatchcase

from .models import Catalog, OrgPosture, ValidationError

LEVELS = ["informational", "low", "medium", "high", "critical"]


def _match_detection(cat: Catalog, did: str, term: str) -> bool:
    d = cat.detections[did]
    if term == "@all":
        return True
    if term.startswith("@status:"):
        return d.status in term.split(":", 1)[1].split("|")
    if term.startswith("@min-level:"):
        want = term.split(":", 1)[1]
        if want not in LEVELS:
            raise ValidationError(f"unknown Sigma level {want!r}")
        return d.level in LEVELS and LEVELS.index(d.level) >= LEVELS.index(want)
    if term.startswith("@logsource:"):
        return any(fnmatchcase(ls, term.split(":", 1)[1]) for ls in d.requires)
    raise ValidationError(f"unknown detection selector {term!r}")


def _match_control(cat: Catalog, cid: str, term: str) -> bool:
    if term == "@all":
        return True
    if term.lower() in ("@ig1", "@ig2", "@ig3"):
        ig = cat.controls[cid].ig
        return ig is not None and ig <= int(term[-1])
    raise ValidationError(f"unknown control selector {term!r}")


def _expand(ids: set[str], universe, matcher) -> set[str]:
    out: set[str] = set()
    for entry in ids:
        if entry.startswith("@"):
            terms = entry.split("&")
            out |= {u for u in universe if all(matcher(u, t) for t in terms)}
        elif any(ch in entry for ch in "*?["):
            out |= {u for u in universe if fnmatchcase(u, entry)}
        else:
            out.add(entry)
    return out


def expand_org(cat: Catalog, org: OrgPosture) -> OrgPosture:
    """Resolve selectors in-place against the catalog and return the org."""
    org.claimed_controls = _expand(org.claimed_controls, cat.controls,
                                   lambda c, t: _match_control(cat, c, t))
    org.ingested_log_sources = _expand(org.ingested_log_sources, cat.log_sources,
                                       lambda _ls, t: t == "@all" or _bad(t))
    org.deployed_detections = _expand(org.deployed_detections, cat.detections,
                                      lambda d, t: _match_detection(cat, d, t))
    return org


def _bad(term: str) -> bool:
    raise ValidationError(f"unknown log-source selector {term!r}")
