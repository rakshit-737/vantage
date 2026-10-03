"""All control frameworks with a public ATT&CK mapping, as ``Control`` objects in one ATT&CK release.

* CIS Controls v8 (official CIS mapping, ATT&CK v8.2) - from the real catalog
* NIST SP 800-53 rev5 (CTID, ATT&CK v16.1) - control statement prose from the NIST OSCAL catalog,
  and SP 800-53B LOW / MODERATE / HIGH / PRIVACY baseline membership
* CRI Profile v2.1, CSA CCM 4.1, AWS, Azure, GCP, M365 (CTID Mappings Explorer)

Every technique id is carried forward to the catalog's ATT&CK release through revoked-by links
(``AttackData.resolve``); deprecated/unknown ids are dropped and counted.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from . import paths
from .ingest.attack import AttackData
from .ingest.ctid import load_ctid
from .ingest.oscal import OscalControl, load_catalog_with_baselines
from .models import Control

TEXT_RICH = ("CIS v8", "NIST 800-53", "CSA-CCM-4.1", "CRI-2.1")   # have more than a product name


@dataclass
class Framework:
    """One control framework's controls, carried forward to the current ATT&CK release."""
    name: str
    controls: dict[str, Control]
    stats: dict = field(default_factory=dict)
    source_attack: str = ""

    @property
    def mapped(self) -> list[Control]:
        """Controls with at least one mapped technique."""
        return [c for c in self.controls.values() if c.mitigates]

    @property
    def techniques(self) -> set[str]:
        """Every technique some control of the framework maps to."""
        return {t for c in self.controls.values() for t in c.mitigates}


def _carry(ids: Iterable[str], attack: AttackData, stats: Counter) -> frozenset[str]:
    out = set()
    for t in ids:
        new = attack.resolve(t)
        if new is None:
            stats["dropped_deprecated_or_unknown"] += 1
        else:
            stats["carried_forward_revoked" if new != t else "unchanged"] += 1
            out.add(new)
    return frozenset(out)


def load_oscal() -> dict[str, OscalControl]:
    """NIST SP 800-53 rev5 OSCAL catalog with SP 800-53B baseline membership attached."""
    d = paths.data_dir() / paths.CTID_DIR
    return load_catalog_with_baselines(d / paths.OSCAL_CATALOG,
                                       {b: d / f for b, f in paths.OSCAL_BASELINES.items()})


def nist_framework(attack: AttackData, oscal: dict[str, OscalControl] | None = None,
                   text: str = "statement") -> Framework:
    """text: 'statement' (OSCAL control statement), 'title' (name only, as in the CTID file)."""
    doc_ctrls, _ = load_ctid(paths.data_dir() / paths.NIST_FILE)
    oscal = oscal if oscal is not None else load_oscal()
    stats: Counter = Counter()
    out = {}
    for cid, c in sorted(doc_ctrls.items()):
        cid = cid.upper()
        o = oscal.get(cid)
        stats["with_oscal_text" if o else "without_oscal_text"] += 1
        body = (o.statement if o and text == "statement" else "") or ""
        fam = o.family_name if o else c.group_name
        out[f"NIST:{cid}"] = Control(f"NIST:{cid}", "NIST 800-53", f"{cid} {c.name}",
                                     _carry(c.techniques, attack, stats),
                                     f"{fam}: {c.name}. {body}".strip(), None, cid.split("-")[0])
    name = "NIST 800-53" if text == "statement" else "NIST 800-53 (title only)"
    return Framework(name, out, dict(stats), paths.NIST_ATTACK_VERSION)


def ctid_framework(short: str, attack: AttackData) -> Framework:
    """One CTID Mappings Explorer framework (``short`` is a key of ``paths.CTID_FRAMEWORKS``)."""
    fname, ver = paths.CTID_FRAMEWORKS[short]
    caps, _ = load_ctid(paths.data_dir() / paths.CTID_DIR / fname)
    stats: Counter = Counter()
    out = {}
    for cid, c in sorted(caps.items()):
        grp = c.group_name if c.group_name and c.group_name != c.group else ""
        txt = f"{grp}: {c.name}" if grp and grp.lower() != c.name.lower() else c.name
        key = f"{short}:{cid}"
        out[key] = Control(key, short, c.name, _carry(c.techniques, attack, stats), txt, None,
                           "/".join(sorted(c.categories)))
    return Framework(short, out, dict(stats), ver)


def cis_framework(catalog_controls: dict[str, Control], stats: dict | None = None) -> Framework:
    """CIS v8 safeguards from the built catalog (already carried forward at build time; pass the
    catalog's ``meta['cis']`` as ``stats`` to report those build-time counts)."""
    out = {f"CIS:{k}": Control(f"CIS:{k}", "CIS v8", c.title, c.mitigates, c.text, c.ig, c.function)
           for k, c in catalog_controls.items() if c.framework.startswith("CIS")}
    return Framework("CIS v8", out, dict(stats or {}), paths.ATTACK_CIS_VERSION)


def all_frameworks(attack: AttackData, catalog_controls: dict[str, Control],
                   include_title_only_nist: bool = False, cis_stats: dict | None = None) -> dict[str, Framework]:
    """Every framework keyed by display name (CIS first, then NIST, then the CTID files)."""
    fws = [cis_framework(catalog_controls, cis_stats), nist_framework(attack)]
    if include_title_only_nist:
        fws.append(nist_framework(attack, text="title"))
    fws += [ctid_framework(s, attack) for s in paths.CTID_FRAMEWORKS]
    return {f.name: f for f in fws}


def baseline_techniques(nist: Framework, oscal: dict[str, OscalControl]) -> dict[str, set[str]]:
    """Techniques mitigated by the CTID-mapped controls in each SP 800-53B baseline."""
    out: dict[str, set[str]] = {}
    for b in paths.OSCAL_BASELINES:
        ids = {cid for cid, o in oscal.items() if b in o.baselines}
        out[b] = {t for k, c in nist.controls.items() if k.split(":", 1)[1] in ids for t in c.mitigates}
    return out


def source_universe(release_file: str | None, attack: AttackData) -> frozenset[str]:
    """Current-release technique ids that existed (directly or via revoked-by) in an older ATT&CK
    release: the fair candidate set for scoring a mapping authored against that release."""
    from .ingest.attack import load_attack
    if release_file is None:
        return frozenset(attack.techniques)
    old = load_attack(paths.data_dir() / release_file)
    return frozenset(r for t in old.techniques if (r := attack.resolve(t)) is not None)
