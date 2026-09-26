"""SigmaHQ rule parser.

Each rule becomes a Detection: ATT&CK techniques from `tags: attack.tNNNN[.NNN]`, and the
required log source from `logsource: {product, category, service}`. Rules are read straight
from the release zip (or a directory) with `yaml.safe_load`; nothing is executed.
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

import yaml

TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
USABLE_STATUS = {"stable", "test", "experimental"}


@dataclass(frozen=True)
class SigmaRule:
    id: str
    title: str
    status: str
    level: str
    logsource: str
    techniques: tuple[str, ...]
    path: str


def logsource_id(ls: dict | None) -> str:
    ls = ls or {}
    parts = [str(ls[k]).strip().lower() for k in ("product", "category", "service") if ls.get(k)]
    return "/".join(parts) or "unknown"


def parse_rule(doc: dict, path: str = "") -> SigmaRule | None:
    if not isinstance(doc, dict) or "logsource" not in doc or "title" not in doc:
        return None
    techs = sorted({m.group(1).upper() for t in doc.get("tags") or []
                    if isinstance(t, str) and (m := TAG_RE.match(t.strip()))})
    return SigmaRule(
        id=str(doc.get("id") or path), title=str(doc["title"]).strip(),
        status=str(doc.get("status") or "").lower(), level=str(doc.get("level") or "").lower(),
        logsource=logsource_id(doc.get("logsource")), techniques=tuple(techs), path=path,
    )


def _docs(text: str) -> Iterator[dict]:
    # Some rules are multi-document (action: global); the first doc carries metadata.
    try:
        for d in yaml.safe_load_all(text):
            if isinstance(d, dict):
                yield d
                return
    except yaml.YAMLError:
        return


def iter_rule_texts(source: str | Path) -> Iterator[tuple[str, str]]:
    source = Path(source)
    if source.is_dir():
        for p in sorted(source.rglob("*.yml")):
            yield str(p.relative_to(source)).replace("\\", "/"), p.read_text(encoding="utf-8")
        return
    with zipfile.ZipFile(source) as zf:
        for name in sorted(zf.namelist()):
            if name.endswith((".yml", ".yaml")):
                yield name, zf.read(name).decode("utf-8", errors="replace")


def load_rules(source: str | Path, statuses: Iterable[str] = USABLE_STATUS) -> list[SigmaRule]:
    statuses = set(statuses)
    out = []
    for name, text in iter_rule_texts(source):
        if "/deprecated/" in f"/{name}" or "/unsupported/" in f"/{name}":
            continue
        for doc in _docs(text):
            r = parse_rule(doc, name)
            if r and r.status in statuses:
                out.append(r)
    return out


# Relative onboarding cost per log source (assumption, documented in docs/adr/0004).
# 1.0 = already-standard OS/cloud audit log; 1.5 = needs an agent/config such as Sysmon or a
# proxy tap; 2.0 = heavier telemetry (auditd rules, full EDR, packet capture/Zeek).
def logsource_cost(ls_id: str) -> float:
    p = ls_id.split("/")
    prod = p[0]
    if prod == "windows":
        if len(p) > 1 and p[1] in {"security", "system", "application", "powershell",
                                     "powershell-classic", "ps_script", "ps_module", "ps_classic_start",
                                     "taskscheduler", "windefend", "bits-client", "wmi"}:
            return 1.0
        return 1.5  # Sysmon / EDR-class categories (process_creation, registry_*, file_* ...)
    if prod == "linux":
        return 2.0 if "auditd" in ls_id else 1.5
    if prod == "macos":
        return 2.0
    if prod in {"zeek", "network"}:
        return 2.0
    if prod in {"aws", "azure", "gcp", "m365", "okta", "github", "google_workspace", "onelogin",
                "bitbucket", "kubernetes", "jumpcloud", "cisco", "fortios", "paloalto", "huawei",
                "juniper", "opencanary", "qualys", "django", "python", "ruby_on_rails", "spring",
                "velocity", "nodejs", "sql", "apache", "nginx", "rpc_firewall", "modsecurity"}:
            return 1.0
    return 1.5 if prod in {"proxy", "dns", "firewall", "webserver", "antivirus"} else 1.0
