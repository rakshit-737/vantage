"""Auto-map free-text controls to ATT&CK techniques.

Default backend is a dependency-free TF-IDF + cosine model. A sentence-transformers backend
is a documented TODO (Grade B/C: needs model download). Evaluation reports precision/recall@k
against the seed catalog's hand-written mapping (which is itself illustrative).
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .models import Catalog

_STOP = set("a an and the to of for in on or by as is are be with from such so that this "
            "can after into over all any its it via".split())


def tokenize(text: str) -> list[str]:
    toks = [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOP and len(t) > 1]
    return [t[:-1] if t.endswith("s") and len(t) > 4 else t for t in toks]  # crude stemming


class TfidfMapper:
    def __init__(self, cat: Catalog):
        self.ids = list(cat.techniques)
        docs = [tokenize(f"{t.name} {t.name} {t.description}") for t in cat.techniques.values()]
        df = Counter(tok for d in docs for tok in set(d))
        n = len(docs)
        self.idf = {tok: math.log((1 + n) / (1 + c)) + 1 for tok, c in df.items()}
        self.vecs = [self._vec(d) for d in docs]

    def _vec(self, toks: list[str]) -> dict[str, float]:
        tf = Counter(toks)
        v = {t: c * self.idf.get(t, 0.0) for t, c in tf.items() if t in self.idf}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        q = self._vec(tokenize(text))
        scores = [(tid, sum(q.get(t, 0.0) * w for t, w in vec.items()))
                  for tid, vec in zip(self.ids, self.vecs)]
        scores.sort(key=lambda x: (-x[1], x[0]))
        return [(t, round(s, 4)) for t, s in scores[:k] if s > 0]


def evaluate(cat: Catalog, k: int = 5) -> dict:
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
