#!/usr/bin/env python
"""Check the bibliography: every DOI in the references resolves and matches its registry record.

    python scripts/check_citations.py                    # docs/related-work.md + README.md

For each reference line (a line with an *italic title* and a doi.org link) the DOI is looked up in
Crossref (api.crossref.org) or, for arXiv DOIs (10.48550), DataCite (api.datacite.org). The title
in the docs must match the registry title (case and punctuation ignored; a registry subtitle may
follow), and every family name in the docs must appear among the registry authors. doi.org must
redirect. Publisher landing pages often answer bots with 403, so they are not fetched.
Network access: doi.org, api.crossref.org, api.datacite.org only.
"""
from __future__ import annotations

import html
import json
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [ROOT / "docs" / "related-work.md", ROOT / "README.md"]
UA = {"User-Agent": "vantage-citation-check/1.0 (https://github.com/rakshit-737/vantage-compliance-attack-mapping)"}
REF = re.compile(r"\*(?P<title>[^*]+)\*.*?doi\.org/(?P<doi>10\.[^)\s\]]+)")


def norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", html.unescape(s).replace("\\&", "&"))
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def get_json(url: str, tries: int = 3) -> dict:
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:  # nosec B310
                return json.load(r)
        except (urllib.error.URLError, TimeoutError):
            if i == tries - 1:
                raise
            time.sleep(5 * (i + 1))
    raise RuntimeError("unreachable")


def registry(doi: str) -> tuple[str, list[str]]:
    """(title, author family names) from Crossref, or DataCite for arXiv DOIs."""
    if doi.lower().startswith("10.48550/"):
        a = get_json(f"https://api.datacite.org/dois/{doi}")["data"]["attributes"]
        return a["titles"][0]["title"], [c.get("familyName") or c["name"].split(",")[0] for c in a["creators"]]
    m = get_json(f"https://api.crossref.org/works/{doi}")["message"]
    return m["title"][0], [a["family"] for a in m.get("author", []) if "family" in a]


def resolves(doi: str) -> bool:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: ANN002, ANN003
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(urllib.request.Request(f"https://doi.org/{doi}", headers=UA, method="HEAD"), timeout=30)  # nosec B310
    except urllib.error.HTTPError as e:
        return e.code in (301, 302, 303, 307, 308)
    return True


def main() -> int:
    bad, seen = 0, set()
    for f in FILES:
        for line in f.read_text(encoding="utf-8").splitlines():
            m = REF.search(line)
            if not m or m["doi"] in seen:
                continue
            doi, title = m["doi"].rstrip(".,"), m["title"]
            seen.add(doi)
            reg_title, families = registry(doi)
            authors_part = line[: m.start()]
            missing = [fam for fam in families if norm(fam) and norm(fam) not in norm(authors_part)]
            title_ok = norm(reg_title).startswith(norm(title)) or norm(title).startswith(norm(reg_title))
            ok = title_ok and not missing and resolves(doi)
            print(f"{'ok' if ok else 'MISMATCH':<9} {doi}  {reg_title[:70]}")
            if not title_ok:
                print(f"          title in docs: {title}")
            if missing:
                print(f"          authors missing from docs: {', '.join(missing)}")
            bad += not ok
    print(f"{len(seen)} DOIs checked, {bad} problem(s)")
    return 1 if bad or not seen else 0


if __name__ == "__main__":
    sys.exit(main())
