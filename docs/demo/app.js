// VANTAGE UI: vanilla JS, no build step. All data rendered via textContent (no innerHTML of data).
"use strict";

const state = { meta: null, base: null, cur: null, disabled: new Set(), enabled: new Set(),
  allRules: false, filter: "all", selected: null };
const token = new URLSearchParams(location.hash.slice(1)).get("token");
// Static demo (GitHub Pages): responses were pre-rendered by scripts/export_demo.py.
const STATIC = window.VANTAGE_STATIC || null;

function staticPath(path) {
  const p = path.split("?")[0];
  if (p.startsWith("/api/technique/")) return STATIC + "technique/" + p.slice(15) + ".json";
  return STATIC + p.slice(5) + ".json";
}

async function api(path, body) {
  if (STATIC) {
    if (path.startsWith("/api/automap")) throw new Error("auto-map needs the local API (vantage serve)");
    const r = await fetch(staticPath(path));
    if (!r.ok) throw new Error(path + " -> " + r.status);
    return r.json();
  }
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  const r = await fetch(path, body === undefined ? { headers } :
    { method: "POST", headers, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}

const whatIf = () => ({ disable_log_sources: [...state.disabled], enable_log_sources: [...state.enabled],
  deploy_all_rules: state.allRules });
const LABEL = { defended: "Defended", paper_only: "Paper-only", detected_only: "Detected, no control", blind: "Blind" };

function renderKpis() {
  const s = state.cur.summary, b = state.base.summary;
  const delta = (a, c, invert) => {
    const d = Math.round((a - c) * 10) / 10;
    if (!d) return null;
    const good = invert ? d < 0 : d > 0;
    return el("span", { class: "delta " + (good ? "up" : "down"), text: (d > 0 ? "+" : "") + d });
  };
  const k = [
    ["Claimed (paper) coverage", s.claimed_pct + "%", delta(s.claimed_pct, b.claimed_pct)],
    ["True (defended) coverage", s.true_pct + "%", delta(s.true_pct, b.true_pct)],
    ["Paper-only techniques", s.paper_only, delta(s.paper_only, b.paper_only, true)],
    ["Blind techniques", s.blind, delta(s.blind, b.blind, true)],
    ["Live / dead rules", s.live_detections + " / " + s.dead_detections, null],
    ["Zero-Trust score", state.cur.zero_trust, null],
  ];
  const box = document.getElementById("kpis");
  box.replaceChildren(...k.map(([l, v, d]) => el("div", { class: "kpi" }, el("b", { text: String(v) }, d), el("span", { text: l }))));
}

function renderMatrix() {
  const m = document.getElementById("matrix");
  m.replaceChildren(...state.cur.matrix.map(col => {
    const counts = col.techniques.filter(t => t.status === "defended").length;
    return el("div", { class: "col" },
      el("h3", { text: col.name }, el("small", { text: counts + "/" + col.techniques.length + " defended" })),
      ...col.techniques.map(t => {
        const dim = state.filter !== "all" && t.status !== state.filter;
        const c = el("button", { class: `cell ${t.status}${dim ? " dim" : ""}${state.selected === t.id ? " sel" : ""}`,
          title: `${t.id} ${t.name}\n${LABEL[t.status]} | live rules: ${t.rules}` +
            (t.subs ? ` | sub-techniques defended ${t.subs_defended}/${t.subs}` : ""),
          type: "button", onclick: () => showTech(t.id) },
          el("span", { class: "id", text: t.id }), el("br"), t.name);
        if (t.subs) c.append(el("span", { class: "bar", style: `width:${Math.round(100 * t.subs_defended / t.subs)}%` }));
        return c;
      }));
  }));
}

function renderSources() {
  const q = document.getElementById("lsfilter").value.trim().toLowerCase();
  const list = document.getElementById("lslist");
  list.replaceChildren(...state.meta.log_sources.filter(l => !q || l.id.includes(q)).slice(0, 200).map(l => {
    const on = (l.ingested && !state.disabled.has(l.id)) || state.enabled.has(l.id);
    const cb = el("input", { type: "checkbox", id: "ls-" + l.id });
    cb.checked = on;
    cb.addEventListener("change", () => {
      if (l.ingested) cb.checked ? state.disabled.delete(l.id) : state.disabled.add(l.id);
      else cb.checked ? state.enabled.add(l.id) : state.enabled.delete(l.id);
      refresh();
    });
    const changed = state.disabled.has(l.id) || state.enabled.has(l.id);
    return el("li", { class: changed ? "changed" : "" }, cb, el("label", { for: "ls-" + l.id, text: l.id }),
      el("span", { class: "n", text: l.rules + " rules" }));
  }));
}

async function showTech(id) {
  state.selected = id;
  renderMatrix();
  const t = await api("/api/technique/" + encodeURIComponent(id));
  const box = document.getElementById("tech");
  const pill = s => el("span", { class: "pill cell " + s, text: LABEL[s] });
  const ul = (items, f) => items.length ? el("ul", { class: "list" }, ...items.map(x => el("li", {}, ...f(x)))) :
    el("p", { class: "muted small", text: "none" });
  box.replaceChildren(
    el("h2", { text: "Technique" }),
    el("div", {}, el("b", { text: `${t.id} ${t.name} ` }), pill(t.status)),
    el("p", { class: "muted small", text: t.tactics.join(", ") }),
    el("p", { class: "tech-desc", text: t.description }),
    el("h2", { text: `Claimed by (${t.claimed_by.length})` }), ul(t.claimed_by, c => [`${c.id} ${c.title}`]),
    el("h2", { text: `Live rules (${t.live_rules.length})` }), ul(t.live_rules.slice(0, 12), r => [`${r.title} [${r.level}]`]),
    el("h2", { text: `Dead rules: log source missing (${t.dead_rules.length})` }),
    ul(t.dead_rules.slice(0, 12), r => [`${r.title}; needs ${r.requires.join(", ")}`]),
    t.subtechniques.length ? el("h2", { text: "Sub-techniques" }) : null,
    t.subtechniques.length ? ul(t.subtechniques, s => [pill(s.status), ` ${s.id} ${s.name}`]) : null);
}

async function renderSide() {
  const [spof, recs] = await Promise.all([api("/api/failure?top=8", whatIf()),
    api("/api/recommend?steps=6&log_sources_only=true", whatIf())]);
  document.getElementById("spof").replaceChildren(...spof.map(s =>
    el("li", { text: `${s.kind === "log_source" ? "log source" : "rule"} ${s.node}: ${s.dark} techniques dark (${s.pct}%)` })));
  document.getElementById("recs").replaceChildren(...recs.map(r =>
    el("li", { text: `onboard ${r.target} (cost ${r.cost.toFixed(2)}, unlocks ${r.enables} rules): +${r.new} techniques` })));
}

async function refresh() {
  state.cur = await api("/api/coverage", whatIf());
  renderKpis(); renderMatrix(); renderSources();
  renderSide();
}

async function automap() {
  const text = document.getElementById("amtext").value.trim();
  const out = document.getElementById("amout");
  if (text.length < 3) return;
  out.replaceChildren(el("li", { class: "muted", text: "mapping..." }));
  try {
    const method = document.getElementById("ammethod").value;
    const res = await api(`/api/automap?k=10&method=${method}&text=` + encodeURIComponent(text));
    out.replaceChildren(...res.map(r => el("li", { text: `${r.id} ${r.name} (${r.score.toFixed(3)})` })));
  } catch (e) { out.replaceChildren(el("li", { text: String(e) })); }
}

async function init() {
  state.meta = await api("/api/meta");
  document.getElementById("org").textContent = state.meta.org;
  const c = state.meta.catalog;
  document.getElementById("catalog").textContent =
    `${c.techniques} techniques · ${c.controls} controls · ${c.detections} rules · ${c.log_sources} log sources` +
    (c.attack_version ? ` · ATT&CK v${c.attack_version}` : " · offline seed catalog");
  state.base = await api("/api/coverage");
  document.getElementById("lsfilter").addEventListener("input", renderSources);
  document.getElementById("reset").addEventListener("click", () => {
    state.disabled.clear(); state.enabled.clear(); state.allRules = false;
    document.getElementById("allrules").checked = false; refresh();
  });
  document.getElementById("allrules").addEventListener("change", e => { state.allRules = e.target.checked; refresh(); });
  document.getElementById("legend").addEventListener("click", e => {
    const b = e.target.closest("button"); if (!b) return;
    state.filter = b.dataset.f;
    document.querySelectorAll("#legend button").forEach(x => x.classList.toggle("on", x === b));
    renderMatrix();
  });
  document.getElementById("amgo").addEventListener("click", automap);
  if (STATIC) {
    document.querySelectorAll(".side input, .side button").forEach(x => { x.disabled = true; });
    document.getElementById("lsfilter").disabled = false;
    document.querySelector(".side p").textContent =
      "Static snapshot: what-if toggles and auto-map need the local API (python -m vantage serve).";
  }
  await refresh();
}

init().catch(e => { document.getElementById("org").textContent = "error: " + e.message; });
