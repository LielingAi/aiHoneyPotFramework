(function(){
"use strict";
/* UI 基础件: 元素构造 / 表格 / 卡片 / 抽屉 / Toast / 格式化 */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "html") el.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const esc = (v) => String(v ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const fmtPct = (v) => (v == null ? "-" : (v * 100).toFixed(1) + "%");
const fmtNum = (v) => (v == null ? "-" : Number(v).toLocaleString());

function relTime(ts) {
  if (!ts) return "-";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return s.toFixed(0) + " 秒前";
  if (s < 3600) return (s / 60).toFixed(0) + " 分钟前";
  if (s < 86400) return (s / 3600).toFixed(1) + " 小时前";
  return (s / 86400).toFixed(1) + " 天前";
}

function pill(text, kind = "dim", title) {
  return h("span", { class: `pill ${kind}`, title: title || "" }, text);
}

const GRADE = {
  consistent: ["ok", "铁证"], canary: ["ok", "金丝雀复用"],
  forged: ["bad", "表演数据"], shared_forgery: ["bad", "跨会话造假"],
  shared_forgery_confirmed: ["bad", "造假·已证实"],
  attribution: ["purple", "操作者指纹"], weak: ["warn", "弱证据"],
};
const gradePill = (g) => {
  const [kind, label] = GRADE[g] || ["warn", g];
  return pill(label, kind);
};

/* ---------- 表格: 列定义 {h, k, num, w, render(row)} ---------- */
function table(cols, rows, { onRow, empty = "暂无数据" } = {}) {
  if (!rows || !rows.length) return h("div", { class: "empty" }, empty);
  const thead = h("tr", {}, ...cols.map((c) =>
    h("th", { class: c.num ? "num" : "" }, c.h)));
  const tbody = h("tbody", {}, ...rows.map((r) =>
    h("tr", { onclick: onRow ? () => onRow(r) : null },
      ...cols.map((c) => {
        const val = c.render ? c.render(r) : (r[c.k] ?? "");
        const cell = h("td", { class: c.num ? "num" : "" });
        if (val instanceof Node) cell.append(val);
        else cell.innerHTML = esc(val);
        return cell;
      }))));
  return h("div", { class: "table-wrap" },
    h("table", {}, h("thead", {}, thead), tbody));
}

function statCard({ title, value, desc, kind = "", node }) {
  const card = h("div", { class: `card pad ${kind}` }, h("div", { class: "t" }, title));
  card.append(node || h("div", { class: "v" }, value));
  if (desc) card.append(h("div", { class: "d" }, desc));
  return card;
}

function pageHead(title, sub) {
  return h("div", { class: "page-head" }, h("h1", {}, title),
    sub ? h("span", { class: "sub" }, sub) : null);
}

function barRows(items, { hot = false, warn = false, unit = "" } = {}) {
  if (!items?.length) return h("div", { class: "empty" }, "暂无数据");
  const max = Math.max(1, ...items.map(([, v]) => v));
  return h("div", {}, ...items.map(([label, v]) =>
    h("div", { class: "barrow" },
      h("span", { class: "lab", title: label }, label),
      h("span", { class: `bar ${hot ? "hot" : warn ? "warn" : ""}`,
        style: `width:${Math.round((v / max) * 200) + 8}px` }),
      h("span", { class: "count" }, `${v}${unit}`))));
}

function histogram(values, { height = 96 } = {}) {
  if (!values?.length) return h("div", { class: "empty" }, "暂无数据");
  const max = Math.max(1, ...values);
  return h("div", { class: "hist", style: `height:${height}px` },
    ...values.map((v, i) =>
      h("div", { class: "bar", style: `height:${Math.round((v / max) * (height - 10)) + 4}px` },
        h("span", { class: "tip" }, `${23 - i} 小时前 · ${v}`))));
}

/* ---------- 抽屉 ---------- */
const drawer = $("#drawer");
function openDrawer(title, bodyNode) {
  $("#drawer-head").innerHTML = "";
  $("#drawer-head").append(
    h("h2", {}, title),
    h("button", { class: "ctl", onclick: closeDrawer }, "关闭"));
  const body = $("#drawer-body");
  body.innerHTML = "";
  body.append(bodyNode);
  drawer.hidden = false;
}
function closeDrawer() { drawer.hidden = true; }
$("#drawer-mask")?.addEventListener("click", closeDrawer);

function kvList(pairs) {
  return h("div", { class: "kv" }, ...pairs.flatMap(([k, v]) => [
    h("div", { class: "k" }, k), h("div", { class: "v" }, String(v ?? "-"))]));
}

/* ---------- Toast ---------- */
function toast(msg, kind = "") {
  const box = $("#toasts");
  const t = h("div", { class: `toast ${kind}` }, msg);
  box.append(t);
  setTimeout(() => t.remove(), 4200);
}

/* ---------- 标签页 ---------- */
function tabs(defs, activeId, onSelect) {
  return h("div", { class: "tabs" }, ...defs.map((d) =>
    h("button", {
      class: "tab" + (d.id === activeId ? " active" : ""),
      onclick: () => onSelect(d.id),
    }, d.label)));
}

/* ---------- 分页器 ---------- */
function pager({ page, pageSize, total, onPage, onSize }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return h("div", { class: "toolbar", style: "margin-top:10px;justify-content:flex-end" },
    h("span", { class: "count" }, `共 ${total} 条 · 第 ${page}/${pages} 页`),
    h("button", { class: "btn", disabled: page <= 1,
      onclick: () => onPage(page - 1) }, "‹ 上一页"),
    h("button", { class: "btn", disabled: page >= pages,
      onclick: () => onPage(page + 1) }, "下一页 ›"),
    h("select", { class: "ctl", onchange: (e) => onSize(Number(e.target.value)) },
      ...[20, 50, 100].map((n) => h("option", { value: n, selected: n === pageSize },
        `${n}/页`))));
}

/* ---------- 骨架 ---------- */
function skeleton(rows = 5) {
  return h("div", { class: "card pad" },
    ...Array.from({ length: rows }, () => h("div", { class: "skel" })));
}

window.HP = window.HP || {};
HP.ui = { $, $$, h, esc, fmtPct, fmtNum, relTime, pill, gradePill, table,
          statCard, pageHead, barRows, histogram, openDrawer, closeDrawer,
          kvList, toast, skeleton, tabs, pager };
})();
