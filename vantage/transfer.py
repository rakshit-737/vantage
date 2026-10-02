"""Supervised control -> ATT&CK mapping that is *trained on one framework and applied to another*.

``TransferMapper`` combines three signals, all computed over the ATT&CK technique universe:

* ``bridge``  - the zero-shot mitigation-bridge score (control text -> ATT&CK mitigations ->
  techniques; see ``vantage.automap.MitigationBridgeMapper``). Uses no framework labels.
* ``knn``     - label transfer: the query control's k most similar *training* controls vote for
  their mapped techniques, weighted by text similarity (normalised to max 1).
* ``prior``   - how often each technique is mapped in the training framework (normalised to max 1).

    score(t) = bridge(t) + beta * knn(t) + gamma * prior(t)

``beta`` and ``gamma`` are chosen on the *training* framework only, by leave-one-control-out
MAP@200 over a small grid; the test framework's labels are never seen. When the test control is
itself part of the training set (the in-framework diagonal), ``rank_for`` excludes it from the
neighbours and from the prior. Because (beta, gamma) were tuned on those same leave-one-out folds,
that diagonal is optimistic; ``nested_loo_aps`` gives the honest in-framework estimate, choosing
(beta, gamma) without the held-out control. (The TF-IDF vocabulary/IDF of the training texts still
includes the held-out control: a small transductive effect on the diagonal only.)
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from .automap import DEFAULT_EMBED_MODEL, MitigationBridgeMapper, _Tfidf, _top, control_text
from .models import Catalog, Control

BETAS = (0.0, 0.25, 0.5, 1.0, 2.0, 4.0)
GAMMAS = (0.0, 0.1, 0.25, 0.5, 1.0)


def average_precision(ranked: Sequence[str], gold: set[str] | frozenset[str], depth: int = 200) -> float:
    """AP@depth of one ranking against a gold set (normalised by min(|gold|, depth))."""
    hits, ap = 0, 0.0
    for i, t in enumerate(ranked[:depth], 1):
        if t in gold:
            hits += 1
            ap += hits / i
    return ap / min(len(gold), depth) if gold else 0.0


def _norm(v: list[float]) -> list[float]:
    m = max(v) if v else 0.0
    return [x / m for x in v] if m > 0 else v


class TransferMapper:
    """Mitigation bridge + kNN label transfer + technique prior, trained on one framework's labels."""

    def __init__(self, cat: Catalog, train: Sequence[Control], encoder: str = "tfidf",
                 model: str = DEFAULT_EMBED_MODEL, k_nn: int = 10, beta: float | None = None,
                 gamma: float | None = None, train_name: str = "train",
                 bridge: MitigationBridgeMapper | None = None, universe: frozenset[str] | None = None):
        """``universe`` restricts the candidate techniques (e.g. those that existed in the ATT&CK
        release a framework was mapped against); ``bridge`` lets callers share one encoder."""
        self.bridge = bridge or MitigationBridgeMapper(cat, encoder, model=model)
        self._keep = [i for i, t in enumerate(self.bridge.ids) if universe is None or t in universe]
        self.ids = [self.bridge.ids[i] for i in self._keep]
        self.idx = {t: i for i, t in enumerate(self.ids)}
        self.train = [c for c in train if c.mitigates & set(self.idx)]
        if not self.train:
            raise ValueError("no training control has a technique in this catalog")
        self.k_nn = k_nn
        texts = [control_text(c) for c in self.train]
        if encoder == "tfidf":
            self._csims = _Tfidf(texts).sims
        else:
            enc = self.bridge.direct.enc
            mat = enc.encode(texts)
            self._csims = lambda text: [float(x) for x in mat @ enc.encode([text])[0]]
        self.counts = Counter(t for c in self.train for t in c.mitigates if t in self.idx)
        self.name = f"transfer[{self.bridge.name.split('[')[1].rstrip(']')}, train={train_name}]"
        if beta is None or gamma is None:
            beta, gamma = self.fit()
        self.beta, self.gamma = beta, gamma

    # -- signals -------------------------------------------------------------------------------
    def _prior(self, exclude: Control | None = None) -> list[float]:
        c = self.counts
        if exclude is not None:
            c = c.copy()
            c.subtract(t for t in exclude.mitigates if t in self.idx)
        return _norm([float(max(c.get(t, 0), 0)) for t in self.ids])

    def _knn(self, text: str, exclude_id: str | None = None) -> list[float]:
        sims = self._csims(text)
        order = sorted((i for i in range(len(self.train)) if self.train[i].id != exclude_id),
                       key=lambda i: -sims[i])[: self.k_nn]
        out = [0.0] * len(self.ids)
        for i in order:
            s = max(float(sims[i]), 0.0)
            for t in self.train[i].mitigates:
                j = self.idx.get(t)
                if j is not None:
                    out[j] += s
        return _norm(out)

    def _bridge(self, text: str) -> list[float]:
        b = self.bridge.scores(text)
        return [b[i] for i in self._keep]

    @staticmethod
    def _combine(b, kn, pr, beta, gamma) -> list[float]:
        return [x + beta * y + gamma * z for x, y, z in zip(b, kn, pr, strict=True)]

    # -- fitting ---------------------------------------------------------------------------------
    def fit(self) -> tuple[float, float]:
        """Grid-search (beta, gamma) by leave-one-out MAP@200 on the training framework."""
        feats = []
        for c in self.train:
            text = control_text(c)
            feats.append((self._bridge(text), self._knn(text, c.id), self._prior(c),
                          c.mitigates & set(self.idx)))
        best, best_map = (0.0, 0.0), -1.0
        self._grid: dict[tuple[float, float], list[float]] = {}
        for beta in BETAS:
            for gamma in GAMMAS:
                aps = []
                for b, kn, pr, gold in feats:
                    s = self._combine(b, kn, pr, beta, gamma)
                    ranked = [t for t, _ in sorted(zip(self.ids, s, strict=True), key=lambda x: (-x[1], x[0]))]
                    aps.append(average_precision(ranked, gold))
                self._grid[(beta, gamma)] = aps
                m = sum(aps) / len(aps)
                if m > best_map + 1e-9:
                    best, best_map = (beta, gamma), m
        self.fit_map = round(best_map, 4)
        return best

    def nested_loo_aps(self) -> dict[str, float]:
        """Honest in-framework estimate: for each training control, (beta, gamma) are re-chosen on
        the other n-1 controls' leave-one-out APs, then that control's AP is reported.

        Returns {control id: AP@200}. Requires that ``fit`` ran (beta/gamma not passed in)."""
        if not hasattr(self, "_grid"):
            self.fit()
        n = len(self.train)
        out = {}
        for i, c in enumerate(self.train):
            best, best_m = None, -1.0
            for key, aps in self._grid.items():
                m = (sum(aps) - aps[i]) / max(n - 1, 1)
                if m > best_m + 1e-9:
                    best, best_m = key, m
            out[c.id] = self._grid[best][i]
        return out

    # -- ranking ---------------------------------------------------------------------------------
    def scores(self, text: str, exclude: Control | None = None) -> list[float]:
        """Combined score per technique (aligned with ``self.ids``); ``exclude`` = leave-one-out."""
        in_train = exclude is not None and any(c.id == exclude.id for c in self.train)
        ex = exclude if in_train else None
        return self._combine(self._bridge(text), self._knn(text, ex.id if ex else None),
                             self._prior(ex), self.beta, self.gamma)

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        """Top-k techniques for free text."""
        return _top(self.ids, self.scores(text), k)

    def rank_for(self, control: Control, k: int) -> list[tuple[str, float]]:
        return _top(self.ids, self.scores(control_text(control), exclude=control), k)


class PriorTransferBaseline:
    """Labels-only transfer: rank techniques by how often the *training* framework maps them."""

    def __init__(self, train: Sequence[Control], train_name: str = "train"):
        self.train = list(train)
        self.name = f"prior-only[train={train_name}]"

    def rank_for(self, control: Control, k: int) -> list[tuple[str, float]]:
        c = Counter(t for x in self.train if x.id != control.id for t in x.mitigates)
        return [(t, float(n)) for t, n in sorted(c.items(), key=lambda x: (-x[1], x[0]))[:k] if n > 0]

    def rank(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        c = Counter(t for x in self.train for t in x.mitigates)
        return [(t, float(n)) for t, n in c.most_common(k)]
