"""Synthetic org generators. No real enterprise data is used anywhere."""
from __future__ import annotations

import random

from .models import Catalog, OrgPosture, Segment, ZeroTrustFacts

SEGMENTS = [Segment("finance", 3), Segment("hr", 2), Segment("general", 1),
            Segment("servers", 3), Segment("guest", 1)]


def demo_org() -> OrgPosture:
    """'Acme Corp': audit-ready on paper, blind in practice (drives the README scenarios)."""
    return OrgPosture(
        name="Acme Corp (synthetic)",
        claimed_controls={"CIS-8.2", "CIS-8.8", "CIS-10.1", "CIS-11.1", "CIS-6.3", "CIS-5.4",
                          "CIS-12.2", "CIS-9.2", "CIS-13.3", "CIS-9.7", "CIS-4.1"},
        # Windows Security + Sysmon are NOT ingested -> their rules are deployed but dead.
        ingested_log_sources={"edr", "proxy", "dns", "email_gw", "vpn"},
        deployed_detections={
            "sig_svc_new", "sig_schtask", "sig_localacct", "sig_group_add", "sig_logclear",
            "sig_bruteforce", "sig_kerberoast", "sig_pth",
            "sig_edr_inject", "sig_edr_tamper", "sig_edr_ransom", "sig_edr_shadow",
            "sig_edr_cred", "sig_edr_ps", "sig_edr_lateral",
            "sig_proxy_c2", "sig_dns_tunnel", "sig_phish_attach", "sig_vpn_anomaly",
        },
        zero_trust=ZeroTrustFacts(
            segments=list(SEGMENTS),
            open_flows={frozenset({"finance", "general"}), frozenset({"hr", "general"}),
                        frozenset({"servers", "general"})},
            mfa_coverage=0.6, privileged_accounts=20, pam_vaulted=5,
            device_posture_checks=False, stale_accounts=40, total_accounts=400,
        ),
    )


def random_org(cat: Catalog, seed: int = 0, maturity: float = 0.5, name: str | None = None) -> OrgPosture:
    """Random org. `maturity` in [0,1] drives how much is claimed / ingested / deployed.
    Claims are deliberately inflated relative to reality to model the paper-vs-real gap."""
    if not 0.0 <= maturity <= 1.0:
        raise ValueError("maturity must be in [0,1]")
    # reproducible synthetic data, not a security use
    rng = random.Random(seed)  # nosec B311
    pick = lambda xs, p: {x for x in sorted(xs) if rng.random() < p}  # noqa: E731
    claim_p = min(1.0, 0.4 + 0.6 * maturity)
    ingested = pick(cat.log_sources, 0.2 + 0.7 * maturity)
    deployed = pick(cat.detections, 0.3 + 0.6 * maturity)
    segs = list(SEGMENTS)
    flows = {frozenset({a.name, b.name}) for i, a in enumerate(segs) for b in segs[i + 1:]
             if rng.random() < 1.0 - maturity}
    priv = rng.randint(5, 50)
    total = rng.randint(100, 2000)
    return OrgPosture(
        name=name or f"synthetic-org-{seed}",
        claimed_controls=pick(cat.controls, claim_p),
        ingested_log_sources=ingested,
        deployed_detections=deployed,
        zero_trust=ZeroTrustFacts(
            segments=segs, open_flows=flows,
            mfa_coverage=round(min(1.0, maturity + rng.uniform(-0.2, 0.2)) if maturity > 0.2 else 0.1, 2),
            privileged_accounts=priv, pam_vaulted=int(priv * maturity),
            device_posture_checks=rng.random() < maturity,
            stale_accounts=int(total * (1 - maturity) * 0.2), total_accounts=total,
        ),
    )
