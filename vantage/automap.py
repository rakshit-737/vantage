"""Auto-map free-text controls to ATT&CK techniques.

Mappers (all expose ``rank(text, k) -> [(technique_id, score), ...]``):

* ``TfidfMapper``        - dependency-free TF-IDF + cosine against technique name/description.
* ``EmbeddingMapper``    - sentence-transformers embeddings + cosine (optional dependency).
* ``MitigationBridgeMapper`` - match the control text to ATT&CK *mitigations* (Mxxxx), then
  rank the techniques those mitigations address (STIX ``mitigates`` relationships). Uses only
  public ATT&CK data - never the CIS labels - but exploits the fact that controls are
  preventive/organisational text, which is much closer to mitigation prose than to
  adversary-behaviour prose.
* ``PopularityBaseline`` / ``RandomBaseline`` - sanity baselines for the benchmark.

``evaluate`` (micro P/R@k, used by the offline seed demo) and ``evaluate_mapper`` (P@k, R@k,
MAP, per-control macro averages, used by ``benchmarks/bench_automap.py`` against the official
CIS v8 -> ATT&CK mapping).
"""
from __future__ import annotations

import math
import random
import re
from collections import Counter
from collections.abc import Iterable
from typing import Protocol

from .models import Catalog, Control

_STOP = set("a an and the to of for in on or by as is are be with from such so that this "
            "can after into over all any its it via may use used using".split())


def tokenize(text: str) -> list[str]:
    toks = [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOP and len(t) > 1]
    return [t[:-1] if t.endswith("s") and len(t) > 4 else t for t in toks]  # crude stemming


class Mapper(Protocol):
    name: str

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]: ...


def technique_doc(t) -> str:
    return f"{t.name}. {t.name}. {t.description}"


def mitigation_doc(m) -> str:
    return f"{m.name}. {m.name}. {m.description}"


class _Tfidf:
    def __init__(self, docs: list[str]):
        toks = [tokenize(d) for d in docs]
        df = Counter(tok for d in toks for tok in set(d))
        n = len(toks)
        self.idf = {tok: math.log((1 + n) / (1 + c)) + 1 for tok, c in df.items()}
        self.vecs = [self.vec(d) for d in toks]

    def vec(self, toks: list[str]) -> dict[str, float]:
        tf = Counter(toks)
        v = {t: (1 + math.log(c)) * self.idf[t] for t, c in tf.items() if t in self.idf}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def sims(self, text: str) -> list[float]:
        q = self.vec(tokenize(text))
        return [sum(q.get(t, 0.0) * w for t, w in v.items()) if len(v) > len(q)
                else sum(v.get(t, 0.0) * w for t, w in q.items()) for v in self.vecs]


def _top(ids: list[str], scores: Iterable[float], k: int) -> list[tuple[str, float]]:
    pairs = sorted(zip(ids, scores, strict=False), key=lambda x: (-x[1], x[0]))
    return [(t, round(float(s), 4)) for t, s in pairs[:k] if s > 0]


class TfidfMapper:
    name = "tfidf-direct"

    def __init__(self, cat: Catalog):
        self.ids = list(cat.techniques)
        self.model = _Tfidf([technique_doc(t) for t in cat.techniques.values()])

    def scores(self, text: str) -> list[float]:
        return self.model.sims(text)

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        return _top(self.ids, self.scores(text), k)


class _Encoder:
    """Thin wrapper over sentence-transformers with an in-process model cache."""
    _cache: dict = {}

    def __init__(self, model: str):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:  # pragma: no cover - optional
            raise RuntimeError("pip install 'vantage[ml]' for the embedding mapper") from e
        if model not in self._cache:
            self._cache[model] = SentenceTransformer(model)
        self.m = self._cache[model]

    def encode(self, texts: list[str]):
        return self.m.encode(texts, normalize_embeddings=True, batch_size=64, show_progress_bar=False)


DEFAULT_EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class EmbeddingMapper:
    def __init__(self, cat: Catalog, model: str = DEFAULT_EMBED_MODEL):
        self.name = f"embed-direct[{model.split('/')[-1]}]"
        self.enc = _Encoder(model)
        self.ids = list(cat.techniques)
        self.mat = self.enc.encode([technique_doc(t) for t in cat.techniques.values()])

    def scores(self, text: str):
        return self.mat @ self.enc.encode([text])[0]

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        return _top(self.ids, self.scores(text), k)


class MitigationBridgeMapper:
    """text -> ATT&CK mitigations -> techniques they mitigate.

    score(t) = max_{m mitigates t} sim(text, m) + alpha * sim(text, t)
    The direct term only breaks ties inside a mitigation's technique group.
    """

    def __init__(self, cat: Catalog, encoder: str = "tfidf", alpha: float = 0.1,
                 model: str = DEFAULT_EMBED_MODEL):
        if not cat.mitigations:
            raise ValueError("catalog has no ATT&CK mitigations (use the real catalog)")
        self.name = f"mitigation-bridge[{encoder if encoder == 'tfidf' else model.split('/')[-1]}]"
        self.ids = list(cat.techniques)
        self.idx = {t: i for i, t in enumerate(self.ids)}
        self.mits = list(cat.mitigations.values())
        self.alpha = alpha
        mdocs = [mitigation_doc(m) for m in self.mits]
        if encoder == "tfidf":
            self.direct = TfidfMapper(cat)
            self._msims = _Tfidf(mdocs).sims
        else:
            self.direct = EmbeddingMapper(cat, model)
            enc, mmat = self.direct.enc, self.direct.enc.encode(mdocs)
            self._msims = lambda text: list(mmat @ enc.encode([text])[0])

    def scores(self, text: str) -> list[float]:
        best = [0.0] * len(self.ids)
        for m, s in zip(self.mits, self._msims(text), strict=False):
            for t in m.techniques:
                i = self.idx.get(t)
                if i is not None and s > best[i]:
                    best[i] = float(s)
        direct = self.direct.scores(text)
        return [b + self.alpha * float(d) for b, d in zip(best, direct, strict=False)]

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        return _top(self.ids, self.scores(text), k)


class PopularityBaseline:
    """Always predicts the techniques most often mapped by *other* controls (leave-one-out)."""
    name = "baseline-popularity"

    def __init__(self, cat: Catalog):
        self.cat = cat
        self.counts = Counter(t for c in cat.controls.values() for t in c.mitigates)

    def rank_for(self, control: Control, k: int) -> list[tuple[str, float]]:
        c = self.counts.copy()
        c.subtract(control.mitigates)
        return [(t, float(n)) for t, n in sorted(c.items(), key=lambda x: (-x[1], x[0]))[:k] if n > 0]

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        return [(t, float(n)) for t, n in self.counts.most_common(k)]


class RandomBaseline:
    name = "baseline-random"

    def __init__(self, cat: Catalog, seed: int = 0):
        self.ids = sorted(cat.techniques)
        self.seed = seed

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        rng = random.Random(f"{self.seed}:{text}")  # benchmark baseline, not crypto; nosec B311
        return [(t, 1.0) for t in rng.sample(self.ids, min(k, len(self.ids)))]


def control_text(c: Control) -> str:
    return f"{c.title}. {c.text}" if c.text else c.title


def _ranked(mapper, c: Control, depth: int) -> list[str]:
    if isinstance(mapper, PopularityBaseline):
        return [t for t, _ in mapper.rank_for(c, depth)]
    return [t for t, _ in mapper.rank(control_text(c), depth)]


def evaluate_mapper(mapper, cat: Catalog, ks: tuple[int, ...] = (5, 10, 20, 50),
                    depth: int = 200) -> dict:
    """Evaluate against each control's `mitigates` set (ground truth). Controls with no
    mapped techniques are skipped. Returns macro-averaged P@k, R@k and MAP@depth."""
    ctrls = [c for c in cat.controls.values() if c.mitigates]
    p = {k: 0.0 for k in ks}
    r = {k: 0.0 for k in ks}
    ap_sum = 0.0
    for c in ctrls:
        ranked = _ranked(mapper, c, max(depth, *ks))
        gold = c.mitigates
        for k in ks:
            hit = len(set(ranked[:k]) & gold)
            p[k] += hit / k
            r[k] += hit / len(gold)
        hits, ap = 0, 0.0
        for i, t in enumerate(ranked[:depth], 1):
            if t in gold:
                hits += 1
                ap += hits / i
        ap_sum += ap / min(len(gold), depth)
    n = len(ctrls) or 1
    out = {"mapper": getattr(mapper, "name", type(mapper).__name__), "controls": len(ctrls)}
    out |= {f"P@{k}": round(p[k] / n, 3) for k in ks}
    out |= {f"R@{k}": round(r[k] / n, 3) for k in ks}
    out[f"MAP@{depth}"] = round(ap_sum / n, 3)
    return out


def evaluate(cat: Catalog, k: int = 5) -> dict:
    """Micro-averaged P/R@k of the TF-IDF mapper (kept for the offline seed demo)."""
    m = TfidfMapper(cat)
    tp = fp = fn = 0
    for c in cat.controls.values():
        pred = {t for t, _ in m.rank(c.text, k)}
        tp += len(pred & c.mitigates)
        fp += len(pred - c.mitigates)
        fn += len(c.mitigates - pred)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"k": k, "precision": round(p, 3), "recall": round(r, 3),
            "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0, "controls": len(cat.controls)}
