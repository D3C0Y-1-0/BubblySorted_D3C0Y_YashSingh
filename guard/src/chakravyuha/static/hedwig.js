// The Hedwig part of the dashboard: bank architecture, infrastructure, findings with the
// code-reachability tree and filters, incidents, service reports and SOC reports.
// Everything that came from a request or a file goes in through textContent only.
"use strict";

const REFRESH_MS = 4000;
const LIVE_ATTACK_MS = 60000; // a service shows the warning symbol for a minute after an attack
const SEV = { low: 0, medium: 1, high: 2, critical: 3 };
const ATTACK_ACTIONS = new Set(["blocked", "banned", "trapped"]);

let arch = { services: [], infra: [] };
let hedwig = {
  findings: [], runs: [], incidents: [], audit: [], soc_reports: [],
  active_run: null, active_incident: null, note: "",
};
let selected = null;
const recent = new Map(); // service -> { at, cats:Set, last: event }

function node(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function bearer() {
  const t = ($("token").value || "").trim();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function getJson(url) {
  try {
    const r = await fetch(url, { cache: "no-store" });
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  }
}

// ---- live attack tracking (called by app.js for every batch of events) -------------------------
window.trackEvents = (batch) => {
  const now = Date.now();
  for (const e of batch) {
    const svc = e.service;
    if (!svc || !ATTACK_ACTIONS.has(e["event.action"]) || e["hedwig.monitor"]) continue;
    const at = Date.parse(e["@timestamp"]) || now;
    if (now - at > LIVE_ATTACK_MS) continue; // history (loaded with the page) is not a live attack
    const entry = recent.get(svc) || { at: 0, cats: new Set() };
    entry.at = Math.max(entry.at, at);
    entry.last = e;
    if (e["event.category"]) entry.cats.add(e["event.category"]);
    recent.set(svc, entry);
  }
  renderArch();
};

function underAttack(name) {
  const entry = recent.get(name);
  return entry && Date.now() - entry.at < LIVE_ATTACK_MS ? entry : null;
}

// ---- architecture and infrastructure ----------------------------------------------------------
function worstRisk(name) {
  const mine = hedwig.findings.filter((f) => f.service === name);
  return mine.reduce((m, f) => Math.max(m, f.risk || 0), 0);
}

function renderArch() {
  const grid = $("arch");
  grid.replaceChildren();
  for (const svc of arch.services) {
    const attack = underAttack(svc.name);
    const tile = node("button", `svc ${svc.status}${attack ? " under-attack" : ""}`);
    tile.type = "button";
    tile.append(node("span", "stack", svc.stack));
    const title = node("div", "svc-name");
    title.append(node("span", "dot-status"), document.createTextNode(svc.name));
    if (attack) title.append(node("span", "warn", "⚠"));
    tile.append(title);
    const risk = worstRisk(svc.name);
    tile.append(node("small", "", `${svc.status} · ${svc.tier} · :${svc.port}`));
    if (risk) tile.append(node("small", "risk", `top risk ${risk.toFixed(2)}`));
    if (attack) tile.append(node("small", "alert", "LIVE ATTACK: " + [...attack.cats].join(", ")));
    tile.addEventListener("click", () => openReport(svc));
    grid.append(tile);
  }
  const down = arch.services.filter((s) => s.status !== "active").length;
  $("arch-note").textContent = arch.services.length
    ? `${arch.services.length - down} of ${arch.services.length} services active`
    : "";
  const list = $("infra");
  list.replaceChildren();
  for (const item of arch.infra) {
    const li = node("li", item.status);
    li.append(node("span", "dot-status"), node("b", "", item.name),
      node("span", "role", item.role), node("span", "port", `:${item.port}`));
    if (item.version) li.append(node("span", "role", `v${item.version}`));
    li.append(node("span", "state", item.status));
    list.append(li);
  }
}

async function refreshArch() {
  const data = await getJson("/api/architecture");
  if (data) {
    arch = data;
    renderArch();
  }
}

// ---- findings, filters, reachability tree ------------------------------------------------------
function visible(f) {
  const text = $("h-text").value.trim().toLowerCase();
  const hay = `${f.id} ${f.package} ${f.service} ${f.severity} ${f.kind}`.toLowerCase();
  if (text && !hay.includes(text)) return false;
  const floor = $("h-sev").value;
  if (floor && SEV[f.severity] < SEV[floor]) return false;
  if ($("h-svc").value && f.service !== $("h-svc").value) return false;
  if ($("h-reach").checked && f.reachability !== "called") return false;
  return true;
}

function kindTag(f) {
  return { "malicious-package": "MALWARE", typosquat: "typosquat?", "install-script": "dropper?" }[f.kind] || "";
}

function renderFindings() {
  const body = $("h-rows");
  body.replaceChildren();
  const shown = hedwig.findings.filter(visible);
  for (const f of shown) {
    const tr = node("tr", selected === f ? "sel" : "");
    const sev = node("td");
    sev.append(node("span", `badge ${f.severity}`, f.severity));
    const pkg = node("td", "", f.version ? `${f.package}@${f.version}` : f.package);
    const tag = kindTag(f);
    if (tag) pkg.append(node("span", "kind", tag));
    tr.append(sev, node("td", "", (f.risk || 0).toFixed(2)), node("td", "", f.service), pkg,
      node("td", "", f.id), node("td", f.reachability === "called" ? "called" : "", f.reachability),
      node("td", "", f.decision));
    tr.addEventListener("click", () => {
      selected = f;
      renderFindings();
      renderDetail(f);
    });
    body.append(tr);
  }
  $("h-count").textContent = `${shown.length} of ${hedwig.findings.length} shown`;
  if (!hedwig.findings.length) {
    const tr = node("tr");
    const td = node("td", "empty", hedwig.note || "No findings.");
    td.colSpan = 7;
    tr.append(td);
    body.append(tr);
  }
}

function fillServiceFilter() {
  const box = $("h-svc");
  const current = box.value;
  const names = [...new Set(hedwig.findings.map((f) => f.service))].sort();
  box.replaceChildren(new Option("All services", ""), ...names.map((n) => new Option(n, n)));
  box.value = names.includes(current) ? current : "";
}

async function loadSnippet(box, service, site) {
  const data = await getJson(
    `/api/snippet?service=${encodeURIComponent(service)}&file=${encodeURIComponent(site.file)}&line=${site.line}`
  );
  box.replaceChildren();
  for (const l of (data && data.lines) || []) {
    const row = node("div", l.hit ? "code hit" : "code");
    row.textContent = `${l.hit ? "▶" : " "} ${String(l.n).padStart(4)} │ ${l.text}`;
    box.append(row);
  }
  if (!box.children.length) box.append(node("div", "code", "(source not readable)"));
}

function renderDetail(f) {
  const box = $("h-detail");
  box.replaceChildren();
  const head = node("div", "d-head");
  head.append(node("span", `badge ${f.severity}`, f.severity), node("b", "", ` ${f.id}`),
    node("span", "note", ` risk ${(f.risk || 0).toFixed(2)} · ${f.service} · ${f.tier} tier`));
  box.append(head, node("p", "", f.summary || ""), node("p", "why", f.reasoning || ""));
  box.append(node("p", "note", `fix: ${f.package_fix ? "bump to " + f.package_fix : f.kind === "malicious-package" ? "remove the package" : "none"} · decision: ${f.decision}`));
  const tools = node("div", "tree-tools");
  const expand = node("button", "", "Expand all");
  const collapse = node("button", "", "Collapse all");
  tools.append(node("b", "", `Reachability: ${f.reachability}`), expand, collapse);
  box.append(tools);
  const tree = node("div", "tree");
  const byFile = new Map();
  for (const s of f.call_sites || []) byFile.set(s.file, [...(byFile.get(s.file) || []), s]);
  if (!byFile.size) tree.append(node("p", "note", "No call sites: the code does not call the vulnerable package."));
  for (const [file, sites] of byFile) {
    const fileEl = document.createElement("details");
    fileEl.append(node("summary", "", `${file} (${sites.length} call site${sites.length === 1 ? "" : "s"})`));
    for (const site of sites) {
      const siteEl = document.createElement("details");
      siteEl.open = true;
      siteEl.append(node("summary", "", `${site.function}() line ${site.line}: ${site.symbol}`));
      const code = node("div", "snippet");
      siteEl.append(code);
      fileEl.append(siteEl);
      loadSnippet(code, f.service, site);
    }
    tree.append(fileEl);
  }
  expand.addEventListener("click", () => tree.querySelectorAll("details").forEach((d) => (d.open = true)));
  collapse.addEventListener("click", () => tree.querySelectorAll("details").forEach((d) => (d.open = false)));
  box.append(tree);
}

// ---- incidents, runs, activity log ---------------------------------------------------------------
function stamp(iso) {
  return (iso || "").replace("T", " ").slice(0, 19);
}

// ---- the incident banner and the live "agents at work" panel ------------------------------------
function renderIncidentBanner() {
  const box = $("h-incident-banner");
  const inc = hedwig.active_incident;
  if (!inc) {
    box.hidden = true;
    return;
  }
  const pr = inc.pr_number ? ` (PR #${inc.pr_number})` : "";
  box.textContent = inc.state === "running"
    ? `⚠ Incident: ${inc.service} is down${pr} — Hedwig is fixing it`
    : `⚠ Incident: ${inc.service} is still down${pr} — waiting for a fix`;
  box.hidden = false;
}

function stepLabel(s) {
  return { running: "running", ok: "done", failed: "failed", skipped: "skipped" }[s.status] || s.status;
}

function renderAgents() {
  const panel = $("agents-panel");
  const run = hedwig.active_run;
  if (!run || !(run.steps || []).length) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  $("agents-note").textContent =
    `${run.service} · ${run.package} ${run.from_version} → ${run.to_version || "-"} · ` +
    `attempt ${run.attempts || 1}${run.state === "running" ? " · running" : " · " + run.state}`;
  const list = $("agents-steps");
  list.replaceChildren();
  for (const s of run.steps) {
    const li = node("li", s.status);
    li.append(node("span", "step-dot"), node("span", "step-name", s.name),
      node("span", "step-detail", `${stepLabel(s)}${s.detail ? " — " + s.detail : ""}`),
      node("span", "step-at", stamp(s.at).slice(11)));
    li.title = s.detail || "";
    list.append(li);
  }
}

function renderLower() {
  const list = $("h-incidents");
  list.replaceChildren();
  for (const i of hedwig.incidents) {
    const li = node("li", `inc ${i.state}`);
    li.append(node("b", "", `${i.service} · ${i.pr_number ? "PR #" + i.pr_number : "pushed change"}`),
      node("span", `badge ${i.state === "contained" ? "ok" : "critical"}`, i.state),
      node("span", "note", ` downtime ${i.downtime_seconds == null ? "n/a" : Math.round(i.downtime_seconds) + " s"}`));
    const steps = node("ul", "steps");
    for (const e of i.timeline || []) {
      steps.append(node("li", "", `${stamp(e.at).slice(11)}  ${e.event}${e.detail ? " — " + e.detail : ""}`));
    }
    li.append(steps);
    list.append(li);
  }
  for (const r of hedwig.runs) {
    const li = node("li", "run");
    li.append(node("b", "", `${r.service} · ${r.package}`),
      node("span", "note", ` ${r.from_version} → ${r.to_version || "-"} · ${r.state}, ${r.action || "-"}`));
    if (r.pr_url) {
      const a = node("a", "", " PR");
      a.href = /^https:\/\//.test(r.pr_url) ? r.pr_url : "#";
      a.target = "_blank";
      a.rel = "noopener";
      li.append(a);
    }
    list.append(li);
  }
  if (!list.children.length) list.append(node("li", "empty", "No incidents or fix runs yet"));
  const log = $("h-log");
  log.replaceChildren();
  for (const a of hedwig.audit.slice(-25).reverse()) {
    const detail = a.action || a.step || a.agent || a.state || "";
    log.append(node("li", "", `${stamp(a.at).slice(11)}  ${a.kind}  ${detail} ${a.service || a.run || ""}`.trim()));
  }
  if (!log.children.length) log.append(node("li", "empty", "No Hedwig activity yet"));
}

async function refreshHedwig() {
  const data = await getJson("/api/hedwig");
  if (!data) return;
  hedwig = data;
  fillServiceFilter();
  renderFindings();
  renderLower();
  renderArch();
  renderIncidentBanner();
  renderAgents();
  if (selected) selected = hedwig.findings.find((f) => f.id === selected.id && f.service === selected.service) || null;
}

// ---- service report (click a tile) ----------------------------------------------------------------
function section(parent, title) {
  parent.append(node("h2", "", title));
  const box = node("div", "report-section");
  parent.append(box);
  return box;
}

function openReport(svc) {
  $("svc-title").textContent = `${svc.name} · ${svc.stack} · ${svc.status}`;
  const out = $("svc-content");
  out.replaceChildren();
  const attack = underAttack(svc.name);
  if (attack) {
    out.append(node("div", "critical-banner", `⚠ CRITICAL: live attack on ${svc.name} (${[...attack.cats].join(", ")})`));
  }
  const events = logEvents.filter((e) => e.service === svc.name && ATTACK_ACTIONS.has(e["event.action"])).slice(-12).reverse();
  const live = section(out, "Attack events");
  if (!events.length) live.append(node("p", "empty", "No attack events in the recent log."));
  for (const e of events) {
    live.append(node("div", "ev", `${(e["@timestamp"] || "").slice(11, 19)}  ${e["source.ip"]}  ${e["event.action"]}  ${e.rule || e["event.category"] || ""}  ${e["url.path"] || ""}`));
  }
  const files = logEvents.filter((e) => e.service === svc.name && e["file.hash.sha256"]);
  if (files.length) {
    const box = section(out, "Planted files (malware / ransomware)");
    for (const e of files.slice(-6).reverse()) {
      box.append(node("div", "ev", `${e["file.name"] || "(no name)"}  ${e.rule}  from ${e["source.ip"]}`));
      box.append(node("div", "ev hash", `sha256 ${e["file.hash.sha256"]}`));
    }
  }
  const honey = logEvents.filter((e) => e["event.category"] === "honeytoken");
  if (honey.length) {
    const box = section(out, "Honeytoken use (attacker reached the honeypot)");
    for (const e of honey.slice(-3)) {
      box.append(node("div", "ev", `${(e["@timestamp"] || "").slice(11, 19)}  ${e["source.ip"]} used a planted ${e["hedwig.honeytoken.kind"] || "token"}; linked IPs banned`));
    }
  }
  const mine = hedwig.findings.filter((f) => f.service === svc.name).slice(0, 8);
  const found = section(out, `Vulnerabilities (${hedwig.findings.filter((f) => f.service === svc.name).length})`);
  if (!mine.length) found.append(node("p", "empty", "None found, or no scan yet."));
  for (const f of mine) {
    found.append(node("div", "ev", `${f.severity.toUpperCase()}  ${f.package}@${f.version}  ${f.id}  risk ${(f.risk || 0).toFixed(2)}`));
  }
  const inc = hedwig.incidents.filter((i) => i.service === svc.name);
  const incBox = section(out, `Incidents (${inc.length})`);
  for (const i of inc) {
    incBox.append(node("div", "ev", `${i.state}: ${i.pr_title || "change"}; downtime ${i.downtime_seconds == null ? "n/a" : Math.round(i.downtime_seconds) + " s"}`));
  }
  socBlock(section(out, "SOC report"));
  $("svc-report").hidden = false;
}

function socBlock(box) {
  box.replaceChildren();
  const reports = hedwig.soc_reports || [];
  if (!reports.length) box.append(node("p", "empty", "No SOC report yet. Generate one after an attack."));
  for (const r of reports.slice(0, 4)) {
    const a = node("a", "", r.name);
    a.href = `/api/soc/${encodeURIComponent(r.name)}`;
    a.target = "_blank";
    a.rel = "noopener";
    const row = node("div", "ev");
    row.append(a);
    box.append(row);
  }
  const make = node("button", "", "Generate and email SOC report");
  make.addEventListener("click", async () => {
    make.disabled = true;
    make.textContent = "Generating...";
    const r = await fetch("/api/run/soc", { method: "POST", headers: bearer() });
    const j = await r.json().catch(() => ({}));
    make.textContent = j.ok ? "Done. Reload the list" : `Failed: ${j.error || j.message || r.status}`;
    make.disabled = false;
    refreshHedwig();
  });
  box.append(make);
}

// ---- wiring ---------------------------------------------------------------------------------------
for (const id of ["h-text", "h-sev", "h-svc", "h-reach"]) $(id).addEventListener("input", renderFindings);
$("h-clear").addEventListener("click", () => {
  $("h-text").value = "";
  $("h-sev").value = "";
  $("h-svc").value = "";
  $("h-reach").checked = false;
  renderFindings();
});
$("h-scan").addEventListener("click", async (e) => {
  e.target.disabled = true;
  e.target.textContent = "Scanning...";
  const r = await fetch("/api/run/scan", { method: "POST", headers: bearer() });
  e.target.textContent = r.ok ? "Rescan" : `Rescan failed (${r.status})`;
  e.target.disabled = false;
  refreshHedwig();
});
$("agents-clear").addEventListener("click", async (e) => {
  const run = hedwig.active_run;
  if (!run) return;
  e.target.disabled = true;
  e.target.textContent = "Clearing...";
  const r = await fetch(`/api/hedwig/runs/${encodeURIComponent(run.run_id)}`, {
    method: "DELETE",
    headers: bearer(),
  });
  e.target.textContent = "Clear";
  e.target.disabled = false;
  if (r.ok) {
    hedwig.active_run = null;
    renderAgents();
  }
  refreshHedwig();
});
$("svc-close").addEventListener("click", () => ($("svc-report").hidden = true));
$("svc-report").addEventListener("click", (e) => {
  if (e.target.id === "svc-report") $("svc-report").hidden = true;
});
$("soc-open").addEventListener("click", () => {
  $("svc-title").textContent = "SOC reports";
  const out = $("svc-content");
  out.replaceChildren();
  socBlock(section(out, "Reports for the SOC team"));
  $("svc-report").hidden = false;
});

refreshArch();
refreshHedwig();
setInterval(refreshArch, REFRESH_MS);
setInterval(refreshHedwig, REFRESH_MS);
