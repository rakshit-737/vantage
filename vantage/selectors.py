"""Posture-file selectors so real-catalog org files stay short.

claimed_controls:      "@ig1" / "@ig2" / "@ig3" (all CIS safeguards up to that Implementation
                       Group), "@family:AC|IA" (NIST 800-53 families), "@baseline:LOW|MODERATE|HIGH"
                       (NIST SP 800-53B baselines), "@all", or globs
                       such as "CIS-8.*" / "NIST-AC-*".
ingested_log_sources:  "@all" or globs such as "windows/*", "aws/cloudtrail".
deployed_detections:   "@all", "@status:stable", "@min-level:high", or globs over rule ids.
Several "@..." terms in one entry are AND-ed with "&": "@status:stable&@min-level:medium".
Plain ids pass through unchanged (and are validated by Catalog.validate_org).

A selector or glob that matches nothing in the catalog is an error (a typo such as
"@status:stabel" would otherwise silently give 0% coverage), and so is an unknown Sigma level,
Sigma status or SP 800-53B baseline name.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from fnmatch import fnmatchcase

from .models import Catalog, OrgPosture, ValidationError

LEVELS = ["informational", "low", "medium", "high", "critical"]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}  # SigmaHQ rule statuses
BASELINES = {"LOW", "MODERATE", "HIGH", "PRIVACY"}                         # NIST SP 800-53B


def _match_detection(cat: Catalog, did: str, term: str) -> bool:
    d = cat.detections[did]
    if term == "@all":
        return True
    if term.startswith("@status:"):
        want = term.split(":", 1)[1].split("|")
        bad = [w for w in want if w not in STATUSES]
        if bad:
            raise ValidationError(f"unknown Sigma status {bad[0]!r} (use {'|'.join(sorted(STATUSES))})")
        return d.status in want
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
    if term.lower().startswith("@family:"):   # NIST 800-53 family, e.g. @family:AC|IA
        fams = term.split(":", 1)[1].upper().split("|")
        return cid.startswith("NIST-") and cid[5:].split("-", 1)[0] in fams
    if term.lower().startswith("@baseline:"):  # NIST SP 800-53B, e.g. @baseline:MODERATE
        want = set(term.split(":", 1)[1].upper().split("|"))
        if want - BASELINES:
            raise ValidationError(f"unknown SP 800-53B baseline {sorted(want - BASELINES)[0]!r} "
                                  f"(use {'|'.join(sorted(BASELINES))})")
        return bool(cat.controls[cid].baselines & want)
    if term.lower() in ("@ig1", "@ig2", "@ig3"):
        ig = cat.controls[cid].ig
        return ig is not None and ig <= int(term[-1])
    raise ValidationError(f"unknown control selector {term!r}")


def _expand(ids: set[str], universe: Iterable[str], matcher: Callable[[str, str], bool],
            kind: str) -> set[str]:
    out: set[str] = set()
    for entry in sorted(ids):
        if entry.startswith("@"):
            terms = entry.split("&")
            hit = {u for u in universe if all(matcher(u, t) for t in terms)}
        elif any(ch in entry for ch in "*?["):
            hit = {u for u in universe if fnmatchcase(u, entry)}
        else:
            out.add(entry)
            continue
        if not hit:
            raise ValidationError(f"{kind} {entry!r} matches nothing in this catalog")
        out |= hit
    return out


def expand_org(cat: Catalog, org: OrgPosture) -> OrgPosture:
    """Resolve selectors in-place against the catalog and return the org."""
    if any("@baseline:" in e.lower() for e in org.claimed_controls) and not any(
            c.baselines for c in cat.controls.values()):
        raise ValidationError("@baseline: needs a catalog with SP 800-53B baselines (--catalog nist)")
    org.claimed_controls = _expand(org.claimed_controls, cat.controls,
                                   lambda c, t: _match_control(cat, c, t), "claimed_controls entry")
    org.ingested_log_sources = _expand(org.ingested_log_sources, cat.log_sources,
                                       lambda _ls, t: t == "@all" or _bad(t), "ingested_log_sources entry")
    org.deployed_detections = _expand(org.deployed_detections, cat.detections,
                                      lambda d, t: _match_detection(cat, d, t), "deployed_detections entry")
    return org


def _bad(term: str) -> bool:
    raise ValidationError(f"unknown log-source selector {term!r}")
