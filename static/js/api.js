(function(){
"use strict";
/* API 客户端 — 与后端 /api/* 一一对应 (业务零改动, 仅消费现有 JSON) */
let TOKEN = new URLSearchParams(location.search).get("token") || sessionStorage.getItem("hp_token") || "";

function setToken(t) {
  TOKEN = t || "";
  if (TOKEN) sessionStorage.setItem("hp_token", TOKEN);
  else sessionStorage.removeItem("hp_token");
}

function qs(params = {}) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== "" && v != null) p.set(k, v);
  }
  if (TOKEN) p.set("token", TOKEN);
  const s = p.toString();
  return s ? `?${s}` : "";
}

async function get(name, params) {
  const r = await fetch(`/api/${name}${qs(params)}`, { credentials: "same-origin" });
  if (r.status === 401) throw Object.assign(new Error("unauthorized"), { code: 401 });
  if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
  return r.json();
}

async function post(path, body, { json = true } = {}) {
  const r = await fetch(`/api/${path}${qs()}`, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "X-Requested-With": "xmlhttp",
      ...(json ? { "Content-Type": "application/json" } : {}),
    },
    body: json ? JSON.stringify(body || {}) : undefined,
  });
  if (!r.ok && r.status !== 401) {
    let detail = {};
    try { detail = await r.json(); } catch (_) {}
    throw Object.assign(new Error(detail.error || `HTTP ${r.status}`), { code: r.status });
  }
  return r.json();
}

const api = {
  me: () => get("me", { _: Date.now() }),
  login: (username, password) => post("login", { username, password }),
  logout: () => post("logout"),
  runs: () => get("runs"),
  summary: (run) => get("summary", { run }),
  situation: () => get("situation"),
  sensors: () => get("sensors"),
  setSensorNote: (sensor_id, note) => post("sensors/note", { sensor_id, note }),
  config: () => get("config"),
  saveConfig: (cfg) => post("config", cfg),
  testAlert: () => post("config/test_alert"),
  kpi: (run) => get("kpi", { run }),
  bandit: () => get("bandit"),
  attribution: (run) => get("attribution", { run }),
  compare: (run) => get("compare", { run }),
  trials: (params) => get("trials", params),
  events: (params) => get("events", { limit: 100, ...params }),
  intel: (params) => get("intel", { limit: 60, ...params }),
  requests: (params) => get("requests", { limit: 100, ...params }),
  attackers: (days) => get("attackers", { days }),
  beacons: (limit) => get("beacons", { limit }),
  entity: (type, id) => get(`entity/${type}/${encodeURIComponent(id)}`),
  sessionTimeline: (session_id) => get("session_timeline", { session_id }),
  get,
  post,
};

function stixUrl(run) { return `/api/export-stix${qs({ run })}`; }
function sseUrl() { return `/api/events/stream${qs()}`; }

window.HP = window.HP || {};
HP.api = api; HP.stixUrl = stixUrl; HP.sseUrl = sseUrl; HP.setToken = setToken;
})();
