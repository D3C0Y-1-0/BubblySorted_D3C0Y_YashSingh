// Chakravyuha dashboard. Plain JS, no dependencies. Everything that came from a request
// (paths, IPs, usernames) is attacker-controlled, so it only ever goes into textContent.
"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const RINGS = [
  { id: 1, name: "Gate", r: 455 },
  { id: 2, name: "Flood", r: 395 },
  { id: 3, name: "Challenge", r: 335 },
  { id: 4, name: "Route", r: 275 },
  { id: 5, name: "Login", r: 215 },
  { id: 6, name: "Inspection", r: 158 },
  { id: 7, name: "Maze", r: 105 },
];
const CORE_R = 58;
const OUTSIDE_R = 492;
const STOPPED = new Set(["blocked", "banned", "trapped", "challenged"]);
const LOG_MAX = 200;
const SPARKS_MAX = 120;
const COLORS = [
  [0, [61, 220, 151]],
  [3, [245, 197, 66]],
  [5, [255, 138, 61]],
  [10, [255, 61, 90]],
];

const $ = (id) => document.getElementById(id);
const svg = $("rings");
const dots = new Map(); // ip -> { el, data }
const ringEls = new Map(); // ring id -> { warriors, count }
let layers = {};
let thresholds = { tarpit: 3, hard_challenge: 5, trap: 10 };
let logEvents = [];
let paused = false;
let sparks = 0;

// ---- helpers ------------------------------------------------------------------------------
function el(name, attrs = {}, parent) {
  const node = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (parent) parent.appendChild(node);
  return node;
}

function hash(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967295;
}

function color(score) {
  const scale = 10 / (thresholds.trap || 10);
  const s = Math.max(0, score * scale);
  for (let i = 1; i < COLORS.length; i++) {
    const [hi, c1] = COLORS[i];
    const [lo, c0] = COLORS[i - 1];
    if (s <= hi) {
      const t = (s - lo) / (hi - lo);
      const mix = c0.map((v, j) => Math.round(v + (c1[j] - v) * t));
      return `rgb(${mix.join(",")})`;
    }
  }
  return `rgb(${COLORS[COLORS.length - 1][1].join(",")})`;
}

function radiusFor(ring) {
  const found = RINGS.find((r) => String(r.id) === String(ring));
  return found ? found.r : null;
}

function placement(c) {
  // where a client's dot sits: on the ring that stopped it, in the maze, or in the core
  const a = hash(c.ip) * Math.PI * 2;
  const jitter = (hash(c.ip + "j") - 0.5) * 16;
  if (c.trapped || String(c.ring) === "7") return { layer: "maze", r: 105 + jitter * 0.8, a };
  if (c.banned) return { layer: "dots", r: OUTSIDE_R - 12, a };
  const r = radiusFor(c.ring);
  if (r && STOPPED.has(c.action)) return { layer: "dots", r: r + jitter, a };
  return { layer: "dots", r: 8 + hash(c.ip + "c") * (CORE_R - 18), a };
}

function xy(r, a) {
  return [Math.cos(a) * r, Math.sin(a) * r];
}

function fmtUptime(s) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h ? `${h}h ${m}m` : m ? `${m}m ${s % 60}s` : `${s}s`;
}

// ---- formation ----------------------------------------------------------------------------
function buildFormation() {
  const bg = el("g", {}, svg);
  RINGS.forEach((ring, i) => {
    el("circle", { r: ring.r, class: "ring-band" }, bg);
    const circumference = 2 * Math.PI * ring.r;
    const warriors = el(
      "circle",
      {
        r: ring.r,
        class: "ring-warriors" + (i % 2 ? " rev" : "") + (ring.id === 7 ? " maze" : ""),
        "stroke-dasharray": ring.id === 7 ? "" : `${circumference / 90} ${circumference / 90}`,
      },
      bg
    );
    const label = el("text", { x: 0, y: -ring.r + 24, "text-anchor": "middle" }, bg);
    const name = el("tspan", { class: "ring-label" }, label);
    name.textContent = `${ring.id} ${ring.name.toUpperCase()}  `;
    const count = el("tspan", { class: "ring-count" }, label);
    count.textContent = "0";
    ringEls.set(String(ring.id), { warriors, count });
  });
  el("circle", { r: CORE_R, class: "core" }, bg);
  const core = el("text", { x: 0, y: 6, "text-anchor": "middle", class: "core-label" }, bg);
  core.textContent = "BANK";
  layers.sparks = el("g", {}, svg);
  layers.dots = el("g", {}, svg);
  layers.maze = el("g", { class: "maze-orbit" }, svg);
}

function flashRing(ring) {
  const entry = ringEls.get(String(ring));
  if (!entry) return;
  entry.warriors.classList.add("flash");
  clearTimeout(entry.timer);
  entry.timer = setTimeout(() => entry.warriors.classList.remove("flash"), 260);
}

function spark(event) {
  // a request travelling inward from outside the formation to where it was decided
  if (sparks >= SPARKS_MAX) return;
  const ip = event["source.ip"] || "";
  const a = hash(ip) * Math.PI * 2;
  const stopped = STOPPED.has(event["event.action"]) && !event["hedwig.monitor"];
  const target = stopped ? radiusFor(event.ring) || CORE_R : 10;
  const [x0, y0] = xy(OUTSIDE_R, a);
  const [x1, y1] = xy(target, a);
  const dot = el("circle", { r: 4, class: "spark", fill: color(event["hedwig.suspicion"] || 0) });
  dot.style.transform = `translate(${x0}px, ${y0}px)`;
  dot.style.transition = "transform 0.55s ease-in, opacity 0.4s 0.55s";
  layers.sparks.appendChild(dot);
  sparks++;
  requestAnimationFrame(() =>
    requestAnimationFrame(() => {
      dot.style.transform = `translate(${x1}px, ${y1}px)`;
      dot.style.opacity = "0";
    })
  );
  setTimeout(() => {
    dot.remove();
    sparks--;
    if (stopped) flashRing(event.ring);
  }, 1000);
}

function updateDots(clients) {
  const seen = new Set();
  for (const c of clients) {
    seen.add(c.ip);
    let entry = dots.get(c.ip);
    if (!entry) {
      const node = el("circle", { r: 7, class: "dot" });
      node.addEventListener("mouseenter", () => showTip(c.ip));
      node.addEventListener("mouseleave", hideTip);
      entry = { el: node };
      dots.set(c.ip, entry);
    }
    entry.data = c;
    const p = placement(c);
    const layer = layers[p.layer];
    if (entry.el.parentNode !== layer) layer.appendChild(entry.el);
    const [x, y] = xy(p.r, p.a);
    entry.el.style.transform = `translate(${x}px, ${y}px)`;
    entry.el.setAttribute("fill", color(c.suspicion));
    entry.el.setAttribute("r", c.allowlisted ? 9 : 7);
    entry.el.classList.toggle("tablet", c.allowlisted);
    entry.el.classList.toggle("banned", c.banned);
  }
  for (const [ip, entry] of dots) {
    if (!seen.has(ip)) {
      entry.el.remove();
      dots.delete(ip);
    }
  }
}

function showTip(ip) {
  const entry = dots.get(ip);
  if (!entry) return;
  const c = entry.data;
  const signals = Object.entries(c.signals || {})
    .map(([k, v]) => `${k} +${v}`)
    .join(", ");
  const where = c.trapped ? "in the maze" : c.banned ? "banned" : `ring ${c.ring}`;
  const tip = $("tip");
  tip.textContent =
    `${c.ip}${c.allowlisted ? " (allowlisted)" : ""}\n` +
    `suspicion ${c.suspicion} · ${where}\n` +
    `last: ${c.action} ${c.status ?? ""} ${c.path}\n` +
    `${c.requests} requests, ${c.stops} stopped` +
    (signals ? `\nsignals: ${signals}` : "");
  const box = svg.getBoundingClientRect();
  const dot = entry.el.getBoundingClientRect();
  const host = svg.parentElement.getBoundingClientRect();
  tip.style.left = `${Math.min(dot.right - host.left + 8, box.width - 280)}px`;
  tip.style.top = `${dot.top - host.top}px`;
  tip.hidden = false;
}

function hideTip() {
  $("tip").hidden = true;
}

// ---- panels -------------------------------------------------------------------------------
function renderBars(ringStops) {
  const list = $("ring-bars");
  const max = Math.max(1, ...Object.values(ringStops));
  if (!list.children.length) {
    for (const ring of RINGS) {
      const li = document.createElement("li");
      if (ring.id === 7) li.className = "maze";
      li.innerHTML = '<span class="name"></span><span class="track"><span class="fill"></span></span><span class="n">0</span>';
      li.querySelector(".name").textContent = `${ring.id} ${ring.name}`;
      list.appendChild(li);
    }
  }
  RINGS.forEach((ring, i) => {
    const n = ringStops[String(ring.id)] || 0;
    const li = list.children[i];
    li.querySelector(".fill").style.width = `${(n / max) * 100}%`;
    li.querySelector(".n").textContent = n;
    ringEls.get(String(ring.id)).count.textContent = n;
  });
}

function renderSuspects(suspects) {
  const list = $("suspects");
  list.replaceChildren();
  if (!suspects.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No suspicion yet";
    list.appendChild(li);
    return;
  }
  for (const s of suspects) {
    const li = document.createElement("li");
    const ip = document.createElement("span");
    ip.className = "ip";
    ip.textContent = s.ip + (s.allowlisted ? " (allowlisted)" : "");
    const score = document.createElement("span");
    score.className = "score";
    score.style.color = color(s.suspicion);
    score.textContent = s.suspicion.toFixed(1);
    const why = document.createElement("span");
    why.className = "why";
    why.textContent =
      Object.entries(s.signals)
        .map(([k, v]) => `${k} +${v}`)
        .join(" · ") || "—";
    li.append(ip, score, why);
    list.appendChild(li);
  }
}

function applySnapshot(s) {
  thresholds = s.thresholds || thresholds;
  document.body.dataset.level = s.level;
  $("level").textContent = s.level;
  $("mode").textContent = s.mode;
  $("uptime").textContent = fmtUptime(s.uptime);
  $("t-rps").textContent = s.rates.rps;
  $("t-stopped-rps").textContent = s.rates.stopped_rps;
  $("t-allowed").textContent = s.totals.allowed;
  $("t-stopped").textContent = s.totals.stopped;
  $("t-tarpit").textContent = s.tarpitted_now;
  $("t-bans").textContent = s.bans;
  $("t-traps").textContent = s.traps;
  $("t-passwords").textContent = s.passwords;
  $("t-challenges").textContent = `${s.challenges.solved} / ${s.challenges.issued}`;
  renderBars(s.ring_stops);
  renderSuspects(s.suspects);
  updateDots(s.clients);
  if (s.events) {
    logEvents = s.events.slice(-LOG_MAX);
    renderLog();
  }
}

// ---- event log ----------------------------------------------------------------------------
function matches(e) {
  const ring = $("f-ring").value;
  const cat = $("f-cat").value;
  const text = $("f-ip").value.trim().toLowerCase();
  if (ring && String(e.ring) !== ring) return false;
  if (cat && e["event.category"] !== cat) return false;
  if (text) {
    const hay = `${e["source.ip"] || ""} ${e["url.path"] || ""}`.toLowerCase();
    if (!hay.includes(text)) return false;
  }
  return true;
}

function row(e) {
  const tr = document.createElement("tr");
  tr.className = `a-${e["event.action"]}` + (e["hedwig.monitor"] ? " monitor" : "");
  const time = (e["@timestamp"] || "").slice(11, 23);
  const cells = [
    time,
    e["source.ip"],
    e.ring,
    e["event.action"],
    e["http.response.status_code"],
    e["http.request.method"],
    e["url.path"],
    e.rule || e["user.name"] || "",
    e["hedwig.suspicion"],
  ];
  for (const value of cells) {
    const td = document.createElement("td");
    td.textContent = value ?? "";
    if (value != null) td.title = String(value);
    tr.appendChild(td);
  }
  return tr;
}

function renderLog() {
  const body = $("log");
  const rows = [];
  for (let i = logEvents.length - 1; i >= 0; i--) {
    if (matches(logEvents[i])) rows.push(row(logEvents[i]));
  }
  body.replaceChildren(...rows);
}

function addEvents(batch) {
  logEvents.push(...batch);
  if (logEvents.length > LOG_MAX) logEvents = logEvents.slice(-LOG_MAX);
  batch.slice(-40).forEach(spark);
  if (paused) return;
  if (batch.length > 20) return renderLog();
  const body = $("log");
  for (const e of batch) if (matches(e)) body.prepend(row(e));
  while (body.children.length > LOG_MAX) body.lastChild.remove();
}

// ---- wiring -------------------------------------------------------------------------------
function connect() {
  const conn = $("conn");
  const source = new EventSource("/api/stream");
  source.onopen = () => {
    conn.textContent = "live";
    conn.className = "pill conn live";
  };
  source.onerror = () => {
    conn.textContent = "reconnecting";
    conn.className = "pill conn down";
  };
  source.addEventListener("snapshot", (m) => applySnapshot(JSON.parse(m.data)));
  source.addEventListener("events", (m) => addEvents(JSON.parse(m.data)));
}

for (const id of ["f-ring", "f-cat", "f-ip"]) $(id).addEventListener("input", renderLog);
$("pause").addEventListener("click", (e) => {
  paused = !paused;
  e.target.textContent = paused ? "Resume" : "Pause";
  e.target.setAttribute("aria-pressed", String(paused));
  if (!paused) renderLog();
});

buildFormation();
renderBars({});
connect();
